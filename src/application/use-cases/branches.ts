/**
 * إدارة الفروع
 *
 * ملف منفصل عن `users.ts` عن قصد — الفروع كيان مستقل، ولو حطّيناهم
 * مع المستخدمين هيبقى عندنا ملف بيعمل حاجتين. الفصل هنا رخيص دلوقتي
 * وبيوفّر تنظيف مؤلم بعدين لما يكبر (فروع لها خزائن ومخزون وتقارير).
 *
 * ══ مين يقدر ينشئ فرع؟ ══
 * المالك بس. صلاحية `BRANCH_MANAGE` غايبة عن مدير الفرع عمدًا —
 * لأن إنشاء فرع قرار مِلكية مش قرار تشغيلي.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  BranchSummary,
  Clock,
} from '../ports';

export interface BranchDeps {
  branches: BranchRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateBranchRequest {
  code: string;
  name: string;
  address?: string | null;
  phone?: string | null;
}

/**
 * كود الفرع: حروف إنجليزية كبيرة وأرقام وشرطة، من 2 لـ 16.
 * بيتكتب في الفواتير والتقارير، فبيفضل قصير وثابت (RYD-01).
 */
const CODE_RE = /^[A-Z0-9-]{2,16}$/;

export async function createBranch(
  deps: BranchDeps,
  actor: AuthenticatedUser,
  input: CreateBranchRequest,
): Promise<{ id: string }> {
  if (!actor.permissions.includes(PERMISSIONS.BRANCH_MANAGE)) {
    throw Errors.forbidden(PERMISSIONS.BRANCH_MANAGE);
  }

  // نوحّد الكود لحروف كبيرة قبل الفحص عشان "ryd-01" و"RYD-01"
  // ما يبقوش فرعين مختلفين
  const code = input.code.trim().toUpperCase();
  const name = input.name.trim();

  if (!CODE_RE.test(code)) {
    throw Errors.validation('كود الفرع: حروف إنجليزية كبيرة وأرقام وشرطة، من 2 إلى 16 حرف.');
  }
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم الفرع غير صالح.');
  }

  const address = input.address?.trim() || null;
  const phone = input.phone?.trim() || null;

  if (address && address.length > 200) throw Errors.validation('العنوان طويل جدًا.');
  if (phone && phone.length > 32) throw Errors.validation('رقم الهاتف غير صالح.');

  // فحص التكرار قبل المحاولة عشان نطلّع رسالة عربية واضحة بدل
  // خطأ قاعدة بيانات خام. قيد UNIQUE في الجدول هو الضمان النهائي.
  const existing = await deps.branches.findByCode(code);
  if (existing) throw Errors.validation('كود الفرع ده مستخدم بالفعل.');

  const created = await deps.branches.create({ code, name, address, phone });

  await deps.audit.record({
    actorId: actor.id,
    action: 'branch.create',
    entity: 'Branch',
    entityId: created.id,
    metadata: { code, name },
  });

  return created;
}

/**
 * قائمة الفروع لشاشة الإدارة.
 * المالك يشوف الكل. غيره ما بيشوفش الشاشة دي أصلًا.
 */
export async function listBranches(
  deps: BranchDeps,
  actor: AuthenticatedUser,
): Promise<BranchSummary[]> {
  if (!actor.permissions.includes(PERMISSIONS.BRANCH_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.BRANCH_VIEW);
  }

  // مدير الفرع عنده BRANCH_VIEW، لكن مفيش سبب يشوف بيه فروع غيره.
  // بنرجّعله فرعه هو بس.
  const all = await deps.branches.listAll();
  if (actor.roleKey === 'SUPER_ADMIN') return all;

  return all.filter((b) => b.id === actor.branchId);
}
