/**
 * الموردين وديون التجار
 *
 * ══ ليه سجل مش نص حر؟ ══
 * عمود `products.source` كان نص حر. يعني "أحمد للموبايلات" و
 * "احمد للموبايلات" تاجرين مختلفين في أي تجميع — والدين بيتوزّع
 * عليهم وما بيقفلش.
 *
 * ══ الدفتر هو الحقيقة ══
 * الدين = مجموع ما زاد ناقص مجموع ما اتسدّد. مفيش عمود "الرصيد"
 * يتحدّث ويختلف عن حركاته. نفس مبدأ الخزينة بالظبط.
 *
 * ══ والسداد بيمسّ الخزينة ══
 * الفلوس بتطلع من الدرج فعلاً. لو سجّلناه في دفتر الموردين بس،
 * رصيد خزينتك يبقى **أكبر من الحقيقة** بمقدار كل ما دفعته لكل
 * تاجر. فالعمليتين جوّه معاملة واحدة في قاعدة البيانات.
 *
 * ══ ⚠ والسداد مش مصروف في قائمة الدخل ══
 * شرا البضاعة تحويل فلوس لمخزون — أصل بيتحوّل لأصل تاني.
 * المصروف بيحصل وقت البيع (تكلفة البضاعة المباعة). حركة السداد
 * معلّمة `is_inventory`، وقائمة الدخل بتستبعدها وتوريها للعلم.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { MoneyError, parseMoneyToPiastres } from '../../domain/money';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  SupplierBalance,
  SupplierRepository,
  TreasuryRepository,
} from '../ports';

export interface SupplierDeps {
  suppliers: SupplierRepository;
  treasuries: TreasuryRepository;
  clock: Clock;
  audit: AuditLogger;
}

/**
 * ⚠ صلاحية واحدة تحكم الشاشة كلها.
 *
 * قائمة **أسماء** الموردين مش حسّاسة وبتتقرا مع المنتجات، لكن
 * **الأرصدة والديون** معلومة مالية. الفصل ده بيخلّي المندوب
 * يختار المورّد من غير ما يشوف إنت مديون له بكام.
 */
function assertSupplierAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE)) {
    throw Errors.forbidden(PERMISSIONS.SUPPLIER_MANAGE);
  }
}

// ─────────── القراءة ───────────

export async function listSuppliers(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
): Promise<SupplierBalance[]> {
  assertSupplierAccess(actor);
  return deps.suppliers.listBalances(actor.tenantId);
}

// ─────────── الكتابة ───────────

export interface CreateSupplierRequest {
  name: string;
  phone?: string | null;
  notes?: string | null;
}

export async function createSupplier(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  input: CreateSupplierRequest,
): Promise<{ id: string }> {
  assertSupplierAccess(actor);

  const name = String(input.name ?? '').trim();
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم المورّد من حرفين إلى 80 حرفًا.');
  }

  const created = await deps.suppliers.create({
    tenantId: actor.tenantId,
    name,
    phone: readPhone(input.phone),
    notes: readNotes(input.notes),
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'supplier.create',
    entity: 'Supplier',
    entityId: created.id,
    metadata: { name },
  });

  return created;
}

export interface MovementRequest {
  /** نص من المستخدم — بيتحوّل لقروش عبر domain/money */
  amount: string;
  note?: string | null;
  date?: string | null;
  /** للسداد فقط */
  treasuryId?: string;
}

/**
 * تسجيل دين — استلمت بضاعة بالأجل.
 *
 * ⚠ ما بيمسّش الخزينة. الدين زاد والدرج ما اتغيّرش.
 */
export async function recordSupplierDebt(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  supplierId: string,
  input: MovementRequest,
): Promise<{ movementId: string; newBalance: number }> {
  assertSupplierAccess(actor);

  const supplier = await deps.suppliers.findById(supplierId);
  // مورّد محل تاني = غير موجود بالنسبة لك
  if (!supplier || supplier.tenantId !== actor.tenantId) throw Errors.notFound('المورّد');

  const amountPiastres = readAmount(input.amount);
  const date = readDate(input.date);
  const note = readNotes(input.note);

  const result = await deps.suppliers.recordDebt({
    supplierId,
    actorId: actor.id,
    amountPiastres,
    note,
    date,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'supplier.debt',
    entity: 'Supplier',
    entityId: supplierId,
    metadata: { name: supplier.name, amountPiastres, newBalance: result.newBalance, date, note },
  });

  return result;
}

/**
 * سداد — عملية ذرية بتطلّع فلوس من الخزينة.
 *
 * ⚠ الخزينة والدفتر بيتحرّكوا مع بعض جوّه قاعدة البيانات.
 * لو الاتنين اتفصلوا، أول مرة واحدة منهم تفشل يبقى عندك دين
 * مسدّد وفلوس لسه في الدرج على الورق.
 */
export async function recordSupplierPayment(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  supplierId: string,
  input: MovementRequest,
): Promise<{ movementId: string; treasuryMovementId: string; newBalance: number }> {
  assertSupplierAccess(actor);

  const supplier = await deps.suppliers.findById(supplierId);
  if (!supplier || supplier.tenantId !== actor.tenantId) throw Errors.notFound('المورّد');

  if (!input.treasuryId) throw Errors.validation('اختر الخزينة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزينة');

  // مدير الفرع بيدفع من خزينة فرعه. صاحب المحل من أي خزينة.
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (scope.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  const amountPiastres = readAmount(input.amount);
  const date = readDate(input.date);
  const note = readNotes(input.note);

  const result = await deps.suppliers.recordPayment({
    supplierId,
    actorId: actor.id,
    treasuryId: input.treasuryId,
    amountPiastres,
    note,
    date,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'supplier.payment',
    entity: 'Supplier',
    entityId: supplierId,
    metadata: {
      name: supplier.name,
      amountPiastres,
      treasuryId: input.treasuryId,
      movementId: result.treasuryMovementId,
      newBalance: result.newBalance,
      date,
      note,
    },
  });

  return result;
}

// ─────────── فاحصات المدخلات ───────────

function readAmount(raw: string): number {
  try {
    // ⚠ نفس دالة الفلوس المستخدمة في كل النظام — بتقبل الأرقام
    // العربية وبترفض السالب والكسور الزيادة
    return parseMoneyToPiastres(String(raw ?? ''));
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'المبلغ غير صالح.');
  }
}

function readDate(raw: string | null | undefined): string | null {
  try {
    return parseDateInput(raw);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
}

function readPhone(raw: string | null | undefined): string | null {
  const phone = String(raw ?? '').trim();
  if (!phone) return null;
  if (phone.length > 32) throw Errors.validation('رقم الهاتف طويل جدًا.');
  return phone;
}

function readNotes(raw: string | null | undefined): string | null {
  const notes = String(raw ?? '').trim();
  if (!notes) return null;
  if (notes.length > 500) throw Errors.validation('الملاحظات أطول من الحد المسموح.');
  return notes;
}
