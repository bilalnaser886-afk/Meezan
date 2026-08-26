/**
 * شراء البضاعة
 *
 * ══ المشكلة اللي بيحلّها الملف ══
 * "شراء بضاعة ٥٠٬٠٠٠" بيتكتب في الدفتر وخلاص. بعد شهرين تفتح
 * اليومية وما تعرفش دول كانوا تلات موبايلات ولا تلاتين إسكرينة
 * ولا من مين.
 *
 * ══ ⚠ وده مش مصروف في قائمة الدخل ══
 * شرا البضاعة **تحويل فلوس لمخزون** — أصل بيتحوّل لأصل تاني.
 * المصروف بيحصل وقت البيع (تكلفة البضاعة المباعة).
 *
 * السبب معلّم `is_inventory` في قاعدة البيانات، وقائمة الدخل
 * بتستبعده وتوريه للعلم. الملف ده ما بيلمسش القاعدة دي — بيسجّل
 * تحت نفس السبب المعلّم، فبيرث نفس المعاملة تلقائيًا.
 *
 * ══ سطر واحد لكل مصروف ══
 * ⚠ ده مش فاتورة مورّد بكذا صنف. ده **بيان** للمصروف: اشتريت
 * إيه، كام قطعة، من مين. والتكلفة هي مبلغ المصروف نفسه.
 *
 * اشتريت حاجتين مختلفتين؟ سجّل مصروفين. البديل كان جدول بنود
 * بمجاميع لازم تتطابق مع الحركة — والمجاميع اللي "لازم تتطابق"
 * دي بتختلف يوم ما، وساعتها الدفتر بيقول رقمين.
 *
 * ══ ولا بيزوّد المخزون ══
 * ⚠ تسجيل شرا هنا **ما بيضيفش منتج** ولا بيرفع أي كمية.
 * التوريد لسه بيتعمل بإيدك من شاشة المنتجات.
 *
 * الربط التلقائي مؤجّل عن قصد: لو ربطناه، أي مصروف غلط هيزوّد
 * مخزون وهمي — والغلط ده أصعب في اكتشافه من نسيان توريد.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { MoneyError, parseCount, parseMoneyToPiastres } from '../../domain/money';
import { PERMISSIONS } from '../../domain/permissions';
import type { AuditLogger, AuthenticatedUser, Clock, TreasuryRepository } from '../ports';
import type {
  CreatePurchaseResult,
  PurchaseRepository,
  PurchaseRow,
} from '../ports';

export interface PurchaseDeps {
  purchases: PurchaseRepository;
  treasuries: TreasuryRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface RecordPurchaseRequest {
  treasuryId: string;
  /** نص من المستخدم — بيتحوّل لقروش عبر domain/money */
  amount: string;
  itemName: string;
  /** نص كمان — الموبايل بيكتب أرقام عربية */
  quantity: string;
  supplierId?: string | null;
  note?: string | null;
}

/**
 * حارس مشترك.
 *
 * ⚠ `expense.create` مش `supplier.manage`.
 *
 * تسجيل شرا فعل تشغيلي بيعمله أي حد بيصرف من الدرج. أما إدارة
 * الموردين وأرصدتهم فقرار مالي. لو حصرناه في `supplier.manage`،
 * المندوب اللي راح جاب البضاعة مش هيقدر يسجّلها — وهيسجّلها
 * مصروف عادي بلا بيان، وهو ده اللي بنحاول نخرج منه.
 */
function assertPurchaseAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_CREATE);
  }
}

// ─────────── الكتابة ───────────

export async function recordPurchase(
  deps: PurchaseDeps,
  actor: AuthenticatedUser,
  input: RecordPurchaseRequest,
): Promise<CreatePurchaseResult> {
  assertPurchaseAccess(actor);

  // ─── الخزينة ───
  //
  // ⚠ الفحص هنا بيطلّع رسالة عربية واضحة، والحراسة الحقيقية
  // (المحل · الفرع · السبب المعلّم) جوّه دالة قاعدة البيانات.
  if (!input.treasuryId) throw Errors.validation('اختر الخزينة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  // خزينة محل تاني = غير موجودة بالنسبة لك
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزينة');

  if (scope.branchId === null) {
    throw Errors.validation('هذه الخزينة غير تابعة لفرع، ولا يمكن تسجيل شراء عليها.');
  }
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (scope.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  // ─── المبلغ والكمية ───
  const amountPiastres = readAmount(input.amount);
  const quantity = readQuantity(input.quantity);

  // ─── الصنف ───
  const itemName = String(input.itemName ?? '').trim();
  if (itemName.length < 2 || itemName.length > 120) {
    throw Errors.validation('اسم الصنف من حرفين إلى 120 حرفًا.');
  }

  const note = readNote(input.note);
  const supplierId = String(input.supplierId ?? '').trim() || null;

  const result = await deps.purchases.create({
    // ⚠ من الجلسة مش من الطلب. الشرا بيطلّع فلوس من الدرج —
    // لو أخدناه من الطلب، أي حد يسجّل باسم زميله ويختفي من السجل.
    actorId: actor.id,
    treasuryId: input.treasuryId,
    amountPiastres,
    itemName,
    quantity,
    supplierId,
    note,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'purchase.create',
    entity: 'InventoryPurchase',
    entityId: result.purchaseId,
    metadata: {
      itemName,
      quantity,
      amountPiastres,
      supplierId,
      treasuryId: input.treasuryId,
      branchId: scope.branchId,
      movementId: result.movementId,
      status: result.status,
      note,
    },
  });

  return result;
}

// ─────────── القراءة ───────────

/**
 * قائمة المشتريات.
 *
 * ⚠ مفيهاش تكلفة محجوبة: مبلغ الحركة **هو** التكلفة، وهو ظاهر
 * في شاشة الخزينة أصلاً لأي حد بيشوف الحركات. فمفيش تسريب هنا.
 *
 * اللي محجوب هو تكلفة **المنتج المخزّن** وهامش الربح — ودول في
 * `products.cost_piastres` وقائمة الدخل، مكان تاني خالص.
 */
export async function listPurchases(
  deps: PurchaseDeps,
  actor: AuthenticatedUser,
  rawFrom?: string | null,
  rawTo?: string | null,
  limit = 200,
): Promise<PurchaseRow[]> {
  assertPurchaseAccess(actor);

  let from: string | null;
  let to: string | null;
  try {
    from = parseDateInput(rawFrom);
    to = parseDateInput(rawTo);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
  if (from && to && from > to) {
    throw Errors.validation('تاريخ البداية بعد تاريخ النهاية.');
  }

  // fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله
  const branchId = actor.roleKey === 'SUPER_ADMIN' ? null : (actor.branchId ?? '__none__');

  return deps.purchases.list({
    tenantId: actor.tenantId,
    branchId,
    from,
    to,
    limit: Math.min(Math.max(limit, 1), 500),
  });
}

/** أسماء الموردين لملء القائمة المنسدلة — بلا أي رقم مالي */
export async function listSupplierNames(
  deps: PurchaseDeps,
  actor: AuthenticatedUser,
): Promise<{ id: string; name: string }[]> {
  assertPurchaseAccess(actor);
  return deps.purchases.listSupplierNames(actor.tenantId);
}

// ─────────── فاحصات المدخلات ───────────

function readAmount(raw: string): number {
  try {
    // نفس دالة الفلوس المستخدمة في كل النظام — بتقبل الأرقام
    // العربية وبترفض السالب والكسور الزيادة
    return parseMoneyToPiastres(String(raw ?? ''));
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'المبلغ غير صالح.');
  }
}

function readQuantity(raw: string): number {
  try {
    // ⚠ السالب ممنوع هنا. الجرد ممكن يخصم كمية تالفة، لكن مفيش
    // حاجة اسمها "اشتريت سالب اتنين".
    const value = parseCount(raw);
    if (value <= 0) throw new MoneyError('الكمية لازم تكون أكبر من صفر.');
    return value;
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'الكمية غير صالحة.');
  }
}

function readNote(raw: string | null | undefined): string | null {
  const note = String(raw ?? '').trim();
  if (!note) return null;
  if (note.length > 500) throw Errors.validation('الملاحظة أطول من الحد المسموح.');
  return note;
}