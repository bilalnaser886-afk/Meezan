/**
 * إدارة الفروع
 *
 * ملف منفصل عن `users.ts` عن قصد — الفروع كيان مستقل، ولو حطّيناهم
 * مع المستخدمين هيبقى عندنا ملف بيعمل حاجتين. الفصل هنا رخيص دلوقتي
 * وبيوفّر تنظيف مؤلم بعدين لما يكبر (فروع لها خزائن ومخزون وتقارير).
 *
 * ══ مين يقدر ينشئ فرع؟ ══
 * صاحب المحل بس. صلاحية `BRANCH_MANAGE` غايبة عن مدير الفرع عمدًا —
 * لأن إنشاء فرع قرار مِلكية مش قرار تشغيلي.
 *
 * ══ وحد الاشتراك ══
 * عدد الفروع محكوم بـ `max_branches` في سجل المحل، ومشغّل المنصّة
 * هو اللي بيحرّكه. صاحب المحل بيفتح لحد الحد وبس.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  BranchSummary,
  Clock,
  TenantRepository,
} from '../ports';

export interface BranchDeps {
  branches: BranchRepository;
  /** لقراءة حد الفروع المسموح في اشتراك المحل */
  tenants: TenantRepository;
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
    throw Errors.validation('كود الفرع: حروف إنجليزية كبيرة وأرقام وشرطة، من 2 إلى 16 حرفًا.');
  }
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم الفرع غير صالح.');
  }

  const address = input.address?.trim() || null;
  const phone = input.phone?.trim() || null;

  if (address && address.length > 200) throw Errors.validation('العنوان طويل جدًا.');
  if (phone && phone.length > 32) throw Errors.validation('رقم الهاتف غير صالح.');

  // ⚠ فحص التكرار **جوّه المحل**.
  //
  // محل تاني عنده فرع بنفس الكود مالوش دعوة بينا — دول نظامين
  // منفصلين تمامًا وما يعرفوش بعض. لو فحصنا على مستوى النظام،
  // أول محل ياخد MAIN يمنع كل المحلات التانية منه للأبد.
  const existing = await deps.branches.findByCode(actor.tenantId, code);
  if (existing) throw Errors.validation('كود الفرع ده مستخدم بالفعل.');

  // ══ حد الاشتراك ══
  //
  // ⚠ الفحص هنا مش في الواجهة. إخفاء زرار "إضافة فرع" مش بيمنع
  // حد يبعت الطلب من المتصفح مباشرةً — والفرق بين الاتنين هو
  // الفرق بين لافتة وقفل.
  const tenant = await deps.tenants.findById(actor.tenantId);
  if (!tenant) throw Errors.internal('tenant not found');

  const current = await deps.branches.countActive(actor.tenantId);
  if (current >= tenant.maxBranches) {
    throw Errors.validation(
      `اشتراكك يسمح بـ ${tenant.maxBranches} فرع. راجع الإدارة لرفع الحد.`,
    );
  }

  const created = await deps.branches.create({
    tenantId: actor.tenantId,
    code,
    name,
    address,
    phone,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'branch.create',
    entity: 'Branch',
    entityId: created.id,
    metadata: { code, name, tenantId: actor.tenantId },
  });

  return created;
}

/**
 * قائمة الفروع لشاشة الإدارة.
 * صاحب المحل يشوف كل فروع محله. غيره ما بيشوفش الشاشة دي أصلًا.
 */
export async function listBranches(
  deps: BranchDeps,
  actor: AuthenticatedUser,
): Promise<BranchSummary[]> {
  if (!actor.permissions.includes(PERMISSIONS.BRANCH_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.BRANCH_VIEW);
  }

  // ⚠ الاستعلام محصور بالمحل من المستودع نفسه، مش بفلترة بعدية.
  const all = await deps.branches.listAll(actor.tenantId);
  if (actor.roleKey === 'SUPER_ADMIN') return all;

  // مدير الفرع عنده BRANCH_VIEW، لكن مفيش سبب يشوف بيه فروع غيره.
  // بنرجّعله فرعه هو بس.
  return all.filter((b) => b.id === actor.branchId);
}
