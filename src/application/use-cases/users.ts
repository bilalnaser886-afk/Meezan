/**
 * إدارة المستخدمين — إنشاء الحسابات
 *
 * تشبيه: كشف الأحزمة في النادي.
 *   - صاحب المحل يقدر يمنح أي حزام، لأي فرع من فروعه.
 *   - مدرّب حزامه أسود (مدير فرع) يقدر يرقّي تلميذ لحزام أزرق
 *     أو حتى أسود مثله — لكن دايماً **جوّه صالته هو بس**.
 *     ما يقدرش يوزّع أحزمة في صالة تانية حتى لو حاول.
 *
 * القاعدة دي مفروضة هنا في منطق العمل، مش مجرّد فحص صلاحية.
 * فحص الصلاحية بيقول "تقدر تنشئ مستخدم". القاعدة هنا بتقول
 * "تنشئه لمين وفي أي فرع" — وهي الأهم أمنياً.
 *
 * ══ وطبقة تالتة اتضافت مع نظام المحلات ══
 * كل الفحوصات تحت بتبدأ بالمحل. الفرع سؤال جوّه المحل، مش قبله.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  PasswordHasher,
  SessionRepository,
  TeamMember,
  UserRepository,
} from '../ports';

export interface UserDeps {
  users: UserRepository;
  branches: BranchRepository;
  /** مطلوب للتعطيل: قطع الجلسات الحيّة فورًا مش في الطلب الجاي */
  sessions: SessionRepository;
  hasher: PasswordHasher;
  clock: Clock;
  audit: AuditLogger;
}

/** الأدوار القابلة للإنشاء من هنا. لاحظ غياب SUPER_ADMIN و
 *  PLATFORM_ADMIN عمداً — حساب صاحب المحل بيتصنع وقت فتح المحل،
 *  وحساب المنصّة مالوش علاقة بشاشة المحل أصلاً. */
export type CreatableRole = 'BRANCH_MANAGER' | 'STAFF';

export interface CreateUserRequest {
  username: string;
  fullName: string;
  password: string;
  roleKey: CreatableRole;
  /** مطلوب فقط لما المنشئ هو صاحب المحل — مدير الفرع مقفول على فرعه */
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

    // ⚠ المحل جزء من فحص الوجود مش سياق حواليه.
    // من غيره، صاحب محل يقدر يربط موظّف بفرع محل تاني لو خمّن
    // معرّفه — والموظّف ده هيشوف بضاعة وفلوس مش بتاعته.
    const exists = await deps.branches.exists(actor.tenantId, input.branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    targetBranchId = input.branchId;
  } else if (actor.roleKey === 'BRANCH_MANAGER') {
    if (!actor.branchId) throw Errors.internal('branch manager without a branch');
    targetBranchId = actor.branchId; // إجباري — أي قيمة في الطلب تُتجاهل
  } else {
    // الموظّف لا يملك USER_CREATE أصلاً في الأدوار الافتراضية، لكن
    // نتحقق صراحةً تحسّباً لأي استثناء فردي يُمنح له لاحقاً بالغلط
    throw Errors.forbidden(PERMISSIONS.USER_CREATE);
  }

  const username = input.username.trim().toLowerCase();
  const fullName = input.fullName.trim();

  if (!USERNAME_RE.test(username)) {
    throw Errors.validation('اسم المستخدم: حروف إنجليزية صغيرة وأرقام فقط، من 3 إلى 32 حرفًا.');
  }
  if (fullName.length < 3 || fullName.length > 80) {
    throw Errors.validation('الاسم الكامل غير صالح.');
  }
  if (input.password.length < 12) {
    throw Errors.validation('كلمة المرور 12 حرفًا على الأقل.');
  }
  if (input.password.length > 1024) {
    throw Errors.validation('كلمة المرور أطول من الحد المسموح.');
  }

  // ⚠ فحص التكرار **جوّه المحل**.
  //
  // نفس اسم المستخدم في محل تاني مسموح تمامًا — دول شخصين
  // مختلفين وما يعرفوش بعض. ولولا كده، أول محل ياخد "ahmed"
  // كان هيمنع كل المحلات التانية منه للأبد.
  //
  // وده بالظبط السبب اللي خلّى كود المحل جزء من شاشة الدخول:
  // الاسم لوحده بقى مش كافي يميّز حد.
  const existing = await deps.users.findByTenantAndUsername(actor.tenantCode, username);
  if (existing) throw Errors.validation('اسم المستخدم ده مُستخدَم بالفعل.');

  const passwordHash = await deps.hasher.hash(input.password);

  const created = await deps.users.create({
    tenantId: actor.tenantId,
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
      tenantId: actor.tenantId,
      createdByRole: actor.roleKey,
    },
  });

  return created;
}

/** قائمة الفريق — صاحب المحل يرى كل فروع محله، مدير الفرع يرى فرعه فقط */
export async function listTeam(deps: UserDeps, actor: AuthenticatedUser): Promise<TeamMember[]> {
  if (!actor.permissions.includes(PERMISSIONS.USER_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.USER_VIEW);
  }

  if (actor.roleKey === 'SUPER_ADMIN') {
    // ⚠ كل فروع **محله**. مش كل النظام.
    // النوع نفسه بقى بيمنع الحالة التانية — مفيش نطاق بلا محل
    // غير حالة واحدة صريحة لمشغّل المنصّة.
    return deps.users.listInScope({ tenantId: actor.tenantId });
  }

  // غير صاحب المحل **لازم** يكون له فرع. لو مالوش، نرفض بدل ما
  // نعرض المحل كله. القاعدة: عند الشك، اقفل. مش افتح.
  if (!actor.branchId) throw Errors.forbidden('branch scope');

  return deps.users.listInScope({ tenantId: actor.tenantId, branchId: actor.branchId });
}

/** قائمة الفروع — لملء القائمة المنسدلة عند إنشاء حساب */
export async function listBranchesForActor(
  deps: UserDeps,
  actor: AuthenticatedUser,
): Promise<{ id: string; name: string }[]> {
  if (actor.roleKey !== 'SUPER_ADMIN') return [];
  const branches = await deps.branches.listActive(actor.tenantId);
  return branches.map((b) => ({ id: b.id, name: b.name }));
}

/**
 * تعطيل أو تفعيل حساب.
 *
 * تشبيه: سحب كارت النادي من عضو. مش بتمسح اسمه من السجل — سجلّه
 * ومبيعاته وكل حركاته بتفضل. بس الكارت ما بيفتحش الباب تاني.
 *
 * ══ خمس قواعد، كل واحدة ليها سبب ══
 */
export async function setUserActive(
  deps: UserDeps,
  actor: AuthenticatedUser,
  targetUserId: string,
  isActive: boolean,
): Promise<void> {
  // 1) الصلاحية العامة
  if (!actor.permissions.includes(PERMISSIONS.USER_EDIT)) {
    throw Errors.forbidden(PERMISSIONS.USER_EDIT);
  }

  // 2) ما تعطّلش نفسك.
  //    السبب عملي مش نظري: مدير فرع يعطّل نفسه بالغلط = يتقفل بره
  //    النظام ومحدش يقدر يرجّعه غير صاحب المحل. نمنعها من الأساس.
  if (targetUserId === actor.id) {
    throw Errors.validation('ما ينفعش تعطّل حسابك بنفسك.');
  }

  const target = await deps.users.findById(targetUserId);

  // ⚠ حاجز المحل الأول.
  //
  // ولاحظ إن الرد "غير موجود" مش "ممنوع": "ممنوع" بتأكّد للسائل
  // إن الحساب موجود في مكان ما — ودي معلومة ما ينفعش يعرفها عن
  // محل تاني أصلاً.
  if (!target || target.deletedAt || target.tenantId !== actor.tenantId) {
    throw Errors.notFound('الحساب');
  }

  // 3) حساب صاحب المحل محصّن.
  //    لو اتعطّل، المحل يبقى بلا صلاحية عليا نهائيًا ومفيش طريق
  //    رجوع. ده باب مسدود، مش مخاطرة.
  if (target.roleKey === 'SUPER_ADMIN' || target.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('cannot disable an owner account');
  }

  // 4) نطاق الفرع — fail-closed
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (target.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  await deps.users.setActive(targetUserId, isActive);

  // 5) التعطيل لازم يقطع الجلسات الحيّة **فورًا**.
  //    من غير السطر ده، الموظف المطرود يفضل شغّال لحد ما بطاقته
  //    تنتهي — لحد 5 دقايق كاملة يقدر يبيع ويصرف فيها.
  if (!isActive) {
    await deps.sessions.revokeAllForUser(targetUserId, 'account_disabled', deps.clock.now());
  }

  await deps.audit.record({
    actorId: actor.id,
    action: isActive ? 'user.reactivate' : 'user.deactivate',
    entity: 'User',
    entityId: targetUserId,
    metadata: {
      username: target.username,
      targetRole: target.roleKey,
      targetBranchId: target.branchId,
      tenantId: actor.tenantId,
    },
  });
}
