/**
 * تقفيل اليومية
 *
 * ══ اليومية مش يوم تقويمي ══
 * الفترة بتمتد من **لحظة آخر تقفيل** للحظة التقفيل الجديد. ممكن
 * تبقى 6 ساعات وممكن 30 — حسب معادك إنت.
 *
 * عشان كده مفيش أي استخدام لـ`todayInCairo()` في الملف ده. دي
 * مسألة زمنية مختلفة تمامًا عن "تاريخ العملية" اللي في البيع
 * والمرتجع والتقارير.
 *
 * ══ والتقفيل ما بيمنعش حاجة ══
 * مفيش قفل ولا توقّف. أول ما تقفل، الفترة الجديدة بتبدأ من نفس
 * اللحظة، والبيع اللي بعدها بثانية بيتسجّل عادي.
 *
 * تشبيه: الجرس آخر الجولة. مش بينهي النزال — بيرسم خط تحت اللي
 * حصل وبس.
 *
 * ══ ⚠ لقطة مش مرجع ══
 * التفاصيل بتتنسخ نسخة كاملة مستقلة جوّه القاعدة وقت التقفيل.
 * مش رابط للجداول الحيّة. يعني لو عدّلت فاتورة بكرة، اليومية
 * المقفولة ما بتتغيّرش.
 *
 * ══ الفرق بين "تقدر تشوف" و"تقدر تقفل" ══
 * ⚠ دي أهم تفصيلة في الحراسة هنا، وهي نفس تفريقتك في الوثيقة:
 *
 *   الشاشة  ← محكومة بـ**صلاحية** (`sales.view_branch`)
 *   الزرار  ← محكوم بـ**إعداد الفرع** (`closing_roles`)
 *
 * يعني ممكن تشوف السجل وما تقدرش تقفل. ودي الحالة الطبيعية
 * لأغلب الموظفين.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  ListScope,
} from '../ports';
import type {
  CloseDayResult,
  ClosingDetail,
  ClosingPreview,
  ClosingRepository,
  ClosingRole,
  ClosingRolesChange,
  ClosingSummary,
} from '../ports';

export interface ClosingDeps {
  closings: ClosingRepository;
  branches: BranchRepository;
  clock: Clock;
  audit: AuditLogger;
}

/** القيم المسموحة. صاحب المحل بره القايمة — بيقفل دايمًا. */
const VALID_ROLES: ClosingRole[] = ['BRANCH_MANAGER', 'STAFF'];

// ─────────── حراسة ───────────

/**
 * حارس الشاشة.
 *
 * ⚠ `sales.view_branch` مش `report.view_branch`.
 *
 * تقرير الدخل فيه هوامش وتكاليف، فمقفول على المدير وفوق. أما
 * سجل اليوميات فبيوصف **حركة الوردية**: باع كام، صرف كام، رجّع
 * كام. والمندوب عنده `sales.view_branch` أصلاً عشان يستقبل
 * مرتجع لفاتورة زميله.
 *
 * ولو حصرناها في المدير، المندوب اللي المالك اختاره يقفل مش
 * هيقدر يشوف اللي بيقفله — وده زرار بيقفل على المجهول.
 */
function assertClosingAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.SALES_VIEW_BRANCH)) {
    throw Errors.forbidden(PERMISSIONS.SALES_VIEW_BRANCH);
  }
}

/**
 * نطاق القراءة.
 *
 * صاحب المحل بيشوف كل فروعه. غيره فرعه هو بس — fail-closed:
 * مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله.
 */
function scopeFor(actor: AuthenticatedUser): ListScope {
  if (actor.roleKey === 'SUPER_ADMIN') return { tenantId: actor.tenantId };
  return { tenantId: actor.tenantId, branchId: actor.branchId ?? '__none__' };
}

/**
 * تحديد الفرع المستهدف.
 *
 * ⚠ نفس نمط المنتجات والعملاء والمستخدمين: الفرع بيتاخد من هوية
 * الجالس، ماعدا صاحب المحل اللي مالوش فرع فلازم يختار.
 *
 * مدير الفرع والمندوب **مالهمش أي طريقة** يمرّروا فرع مختلف —
 * القيمة اللي في الطلب بتتجاهل تمامًا.
 */
async function resolveBranch(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  requested?: string | null,
): Promise<string> {
  if (actor.roleKey === 'SUPER_ADMIN') {
    const branchId = String(requested ?? '').trim();
    if (!branchId) throw Errors.validation('اختر الفرع.');

    // المحل جزء من فحص الوجود مش سياق حواليه
    const exists = await deps.branches.exists(actor.tenantId, branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    return branchId;
  }

  if (!actor.branchId) throw Errors.forbidden('branch scope');
  return actor.branchId;
}

// ─────────── القراءة ───────────

export async function listClosings(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  limit = 50,
): Promise<ClosingSummary[]> {
  assertClosingAccess(actor);
  return deps.closings.list(scopeFor(actor), Math.min(Math.max(limit, 1), 200));
}

/**
 * تفاصيل يومية واحدة.
 *
 * ══ ⚠ التكلفة بالصلاحية مش بالدور ══
 * `profit.view_real` — عشان أي استثناء فردي في `user_permissions`
 * يشتغل. ترميز الدور هنا كان هيكسر الآلية دي.
 *
 * والحجب بيحصل في **قاعدة البيانات**: الظرف ما بيترجعش أصلاً
 * لمن مالوش الصلاحية، فمفيش رقم يتخبّى في الشاشة.
 */
export async function getClosing(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  closingId: string,
): Promise<ClosingDetail> {
  assertClosingAccess(actor);

  const includeCost = actor.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL);

  // ⚠ المحل بيتبعت للاستعلام نفسه مش بيتفلتر بعده.
  // الجلب بالمعرّف المباشر مش محمي بفلتر القوايم — من غير كده
  // أي حد يعرف رقم يومية يقراها من محل تاني.
  const closing = await deps.closings.detail(closingId, actor.tenantId, includeCost);
  if (!closing) throw Errors.notFound('اليومية');

  // وحاجز الفرع بعد حاجز المحل
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (closing.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  return closing;
}

/**
 * المعاينة — إيه اللي هيتقفل لو ضغطت دلوقتي؟
 *
 * ══ ليه دي موجودة أصلاً؟ ══
 * التقفيل قرار ما بيترجعش فيه. والزرار اللي بيقفل من غير ما
 * يوريك إيه اللي جواه = ضغطة على المجهول.
 *
 * وكمان بترجّع `canClose` و`minutesLeft` — عشان الشاشة تعرض
 * السبب **قبل** الضغط، مش رسالة رفض بعده.
 */
export async function previewClosing(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  requestedBranchId?: string | null,
): Promise<ClosingPreview & { branchId: string }> {
  assertClosingAccess(actor);

  const branchId = await resolveBranch(deps, actor, requestedBranchId);
  const preview = await deps.closings.preview(branchId, actor.id);

  return { ...preview, branchId };
}

// ─────────── التقفيل ───────────

/**
 * تقفيل اليومية.
 *
 * ══ ⚠ الحراسة كلها جوّه القاعدة، والسبب مش كسل ══
 * تلات حاجات لازم يتفحصوا في نفس المعاملة اللي بتكتب الصف:
 *   • مين يقدر يقفل الفرع ده (`closing_roles` + صاحب المحل)
 *   • عدّت 3 ساعات على آخر تقفيل؟
 *   • قفل على صف الفرع عشان اتنين ما يضغطوش في نفس اللحظة
 *
 * لو فحصناهم هنا، بين الفحص والكتابة فيه رحلة شبكة — وفيها
 * يقدر حد تاني يقفل، ونطلع بيوميتين على نفس الفترة.
 *
 * الملف ده بيحرس النطاق وبيسجّل، والضمانة جنب البيانات.
 */
export async function closeDay(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  requestedBranchId?: string | null,
  rawNote?: string | null,
): Promise<CloseDayResult> {
  assertClosingAccess(actor);

  const branchId = await resolveBranch(deps, actor, requestedBranchId);

  const note = String(rawNote ?? '').trim() || null;
  if (note && note.length > 500) throw Errors.validation('الملاحظة أطول من الحد المسموح.');

  const result = await deps.closings.close(branchId, actor.id, note);

  await deps.audit.record({
    actorId: actor.id,
    action: 'closing.close',
    entity: 'DailyClosing',
    entityId: result.closingId,
    // ⚠ الأرقام في السجل كمان مش في اللقطة بس. لو حد شكّ في
    // يومية بعد شهور، السجل بيقول اتقفلت بكام من غير ما يفتحها.
    metadata: {
      branchId,
      periodFrom: result.periodFrom.toISOString(),
      periodTo: result.periodTo.toISOString(),
      salesCount: result.salesCount,
      salesPiastres: result.salesPiastres,
      returnsPiastres: result.returnsPiastres,
      expensesPiastres: result.expensesPiastres,
      purchasesPiastres: result.purchasesPiastres,
      cashInPiastres: result.cashInPiastres,
      cashOutPiastres: result.cashOutPiastres,
      note,
    },
  });

  return result;
}

// ─────────── الإعداد ───────────

/**
 * ضبط مين يقفل — صاحب المحل وحده.
 *
 * ══ ⚠ الفحص على الدور مباشرةً، وده مقصود ══
 * القاعدة العامة في المشروع "افحص بالمفتاح مش بالدور". والحالة
 * دي استثناء واعي: مفيش صلاحية مخصّصة ليها، وعمل واحدة عشان
 * فعل إداري بيحصل مرة كل شهور كان هيزوّد الكتالوج بلا فايدة.
 *
 * لو احتجت يوم تدّي مدير معيّن الحق ده، ساعتها تتعمل صلاحية —
 * مش قبلها.
 *
 * ══ والاختيار متعدد ══
 * ممكن مديرين الفروع بس، أو المناديب بس، أو الاتنين، أو ولا حد.
 * القايمة الفاضية معناها: صاحب المحل بس.
 */
export async function setClosingRoles(
  deps: ClosingDeps,
  actor: AuthenticatedUser,
  requestedBranchId: string,
  rawRoles: unknown,
): Promise<ClosingRolesChange & { branchId: string }> {
  if (actor.roleKey !== 'SUPER_ADMIN') {
    throw Errors.forbidden('ضبط تقفيل اليومية لصاحب المحل وحده.');
  }

  const branchId = String(requestedBranchId ?? '').trim();
  if (!branchId) throw Errors.validation('اختر الفرع.');

  const exists = await deps.branches.exists(actor.tenantId, branchId);
  if (!exists) throw Errors.validation('الفرع المختار غير موجود.');

  const roles = readRoles(rawRoles);

  const change = await deps.closings.setRoles(branchId, actor.id, roles);

  await deps.audit.record({
    actorId: actor.id,
    action: 'closing.roles.update',
    entity: 'Branch',
    entityId: branchId,
    // ⚠ القديم والجديد مع بعض. "اتغيّر" من غير "من إيه" مش سجل.
    metadata: {
      from: change.previousRoles,
      to: change.newRoles,
      tenantId: actor.tenantId,
    },
  });

  return { ...change, branchId };
}

/**
 * قراءة الأدوار من الطلب.
 *
 * ⚠ بنرفض أي قيمة مش معروفة بدل ما نتجاهلها بصمت. التجاهل
 * الصامت كان هيخلّي المالك يختار حاجة ويلاقيها ما اتحفظتش،
 * ومفيش رسالة تقوله ليه.
 */
function readRoles(raw: unknown): ClosingRole[] {
  if (raw === null || raw === undefined) return [];
  if (!Array.isArray(raw)) throw Errors.validation('صيغة الأدوار غير صحيحة.');

  const seen = new Set<ClosingRole>();

  for (const item of raw) {
    const value = String(item ?? '').trim().toUpperCase();
    if (!VALID_ROLES.includes(value as ClosingRole)) {
      throw Errors.validation('المسموح: مدير الفرع أو مندوب المبيعات.');
    }
    seen.add(value as ClosingRole);
  }

  return [...seen];
}