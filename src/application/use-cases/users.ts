/**
 * إدارة المستخدمين — إنشاء الحسابات
 *
 * تشبيه: كشف الأحزمة في النادي.
 *   - المالك يقدر يمنح أي حزام، لأي صالة فرعية يختارها.
 *   - مدرّب حزامه أسود (مدير فرع) يقدر يرقّي تلميذ لحزام أزرق
 *     أو حتى أسود مثله — لكن دايماً **جوّه صالته هو بس**.
 *     ما يقدرش يوزّع أحزمة في صالة تانية حتى لو حاول.
 *
 * القاعدة دي مفروضة هنا في منطق العمل، مش مجرّد فحص صلاحية.
 * فحص الصلاحية بيقول "تقدر تنشئ مستخدم". القاعدة هنا بتقول
 * "تنشئه لمين وفي أي فرع" — وهي الأهم أمنياً.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  PasswordHasher,
  RoleKey,
  TeamMember,
  UserRepository,
} from '../ports';

export interface UserDeps {
  users: UserRepository;
  branches: BranchRepository;
  hasher: PasswordHasher;
  clock: Clock;
  audit: AuditLogger;
}

/** الأدوار القابلة للإنشاء من هنا. لاحظ غياب SUPER_ADMIN عمداً —
 *  حساب المالك يُصنع من /setup فقط، مرة واحدة، ولا يُمنح لاحقاً. */
export type CreatableRole = 'BRANCH_MANAGER' | 'STAFF';

export interface CreateUserRequest {
  username: string;
  fullName: string;
  password: string;
  roleKey: CreatableRole;
  /** مطلوب فقط لما المنشئ هو المالك — مدير الفرع مقفول على فرعه */
  branchId?: string | null;
}

const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;

export async function createUser(
  deps: UserDeps,
  actor: AuthenticatedUser,
  input: CreateUserRequest,
): Promise<{ id: string }> {
  // الحارس الأول: هل المنشئ يملك الصلاحية العامة أصلاً؟
  if (!actor.permissions.includes(PERMISSIONS.USER_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.USER_CREATE);
  }

  // الحارس الثاني، وهو الأهم: تحديد الفرع المستهدف حسب هوية المنشئ.
  // مدير الفرع لا يملك أي طريقة يمرّر بيها فرعاً مختلفاً — القيمة
  // مأخوذة من جلسته هو، لا من الطلب، حتى لو حاول التلاعب بالـ body.
  let targetBranchId: string | null;

  if (actor.roleKey === 'SUPER_ADMIN') {
    if (!input.branchId) throw Errors.validation('اختر الفرع.');
    const exists = await deps.branches.exists(input.branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    targetBranchId = input.branchId;
  } else if (actor.roleKey === 'BRANCH_MANAGER') {
    if (!actor.branchId) throw Errors.internal('branch manager without a branch');
    targetBranchId = actor.branchId; // إجباري — أي قيمة في الطلب تُتجاهل
  } else {
    // الموظّف لا يملك USER_CREATE أصلاً في الأدوار الافتراضية، لكن
    // نتحقق صراحة تحسّباً لأي استثناء فردي يُمنح له لاحقاً بالغلط
    throw Errors.forbidden(PERMISSIONS.USER_CREATE);
  }

  const username = input.username.trim().toLowerCase();
  const fullName = input.fullName.trim();

  if (!USERNAME_RE.test(username)) {
    throw Errors.validation('اسم المستخدم: حروف إنجليزية صغيرة وأرقام فقط، من 3 إلى 32 حرف.');
  }
  if (fullName.length < 3 || fullName.length > 80) {
    throw Errors.validation('الاسم الكامل غير صالح.');
  }
  if (input.password.length < 12) {
    throw Errors.validation('كلمة المرور 12 حرف على الأقل.');
  }
  if (input.password.length > 1024) {
    throw Errors.validation('كلمة المرور أطول من الحد المسموح.');
  }

  const existing = await deps.users.findByUsername(username);
  if (existing) throw Errors.validation('اسم المستخدم ده مُستخدَم بالفعل.');

  const passwordHash = await deps.hasher.hash(input.password);

  const created = await deps.users.create({
    username,
    fullName,
    passwordHash,
    roleKey: input.roleKey,
    branchId: targetBranchId,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'user.create',
    entity: 'User',
    entityId: created.id,
    metadata: {
      username,
      roleKey: input.roleKey,
      branchId: targetBranchId,
      createdByRole: actor.roleKey,
    },
  });

  return created;
}

/** قائمة الفريق — المالك يرى الجميع، مدير الفرع يرى فرعه فقط */
export async function listTeam(deps: UserDeps, actor: AuthenticatedUser): Promise<TeamMember[]> {
  if (!actor.permissions.includes(PERMISSIONS.USER_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.USER_VIEW);
  }

  if (actor.roleKey === 'SUPER_ADMIN') {
    return deps.users.listInScope({ allBranches: true });
  }

  // غير المالك **لازم** يكون له فرع. لو مالوش، نرفض بدل ما نعرض الكل.
  // القاعدة: عند الشك، اقفل. مش افتح.
  if (!actor.branchId) throw Errors.forbidden('branch scope');

  return deps.users.listInScope({ branchId: actor.branchId });
}

/** قائمة الفروع — لملء القائمة المنسدلة عند إنشاء حساب من واجهة المالك */
export async function listBranchesForActor(
  deps: UserDeps,
  actor: AuthenticatedUser,
): Promise<{ id: string; name: string }[]> {
  if (actor.roleKey !== 'SUPER_ADMIN') return [];
  const branches = await deps.branches.listActive();
  return branches.map((b) => ({ id: b.id, name: b.name }));
}
