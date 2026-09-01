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
 * يتحدّث ويختلف عن حركاته. نفس مبدأ الخزنة بالظبط.
 *
 * ══ والسداد بيمسّ الخزنة ══
 * الفلوس بتطلع من الدرج فعلاً. لو سجّلناه في دفتر الموردين بس،
 * رصيد خزنتك يبقى **أكبر من الحقيقة** بمقدار كل ما دفعته لكل
 * تاجر. فالعمليتين جوّه معاملة واحدة في قاعدة البيانات.
 *
 * ══ ⚠ والسداد مش مصروف في قائمة الدخل ══
 * شرا البضاعة تحويل فلوس لمخزون — أصل بيتحوّل لأصل تاني.
 * المصروف بيحصل وقت البيع (تكلفة البضاعة المباعة). حركة السداد
 * معلّمة `is_inventory`، وقائمة الدخل بتستبعدها وتوريها للعلم.
 *
 * ══ ⚠ والمجموع لوحده ما بيكفّيش ══
 * الشاشة كانت بتوري "عليك 47,000 لأحمد" وبس. والرقم ده ما
 * بيخليكش تعمل حاجة: أحمد بيقول رقم تاني، ومالكش غير تصدّقه.
 *
 * `listSupplierMovements` تحت بتفتح الدفتر سطر سطر — كل سطر
 * بيقول إمتى، على إيه، مين سجّله، وبكام.
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
  SupplierMovement,
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
 * قائمة **أسماء** الموردين مش حسّاسة وبتتقرا مع البضاعة، لكن
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

/**
 * دفتر مورّد واحد — الحركات سطر سطر.
 *
 * ══ ⚠ نفس صلاحية الأرصدة، وده مقصود ══
 * الدفتر **تفصيل** لنفس الرقم اللي في الشاشة. صلاحية منفصلة
 * كانت هتدّي حد يشوف الإجمالي ويتمنع من تفاصيله — وده مالوش
 * معنى أمني: اللي شايف إنك مديون بـ٤٧ ألف مش هيتأذّى النظام
 * لو شاف دول جم منين.
 *
 * ⚠ وحاجز المحل هنا **مرتين**: مرة على المورّد نفسه، ومرة جوّه
 * الاستعلام في قاعدة البيانات. التكرار مقصود — لو الأولانية
 * اتشالت يومًا ما بالغلط، التانية بتفضل واقفة.
 */
export async function listSupplierMovements(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  supplierId: string,
  limit = 200,
): Promise<SupplierMovement[]> {
  assertSupplierAccess(actor);

  const supplier = await deps.suppliers.findById(supplierId);
  // مورّد محل تاني = غير موجود بالنسبة لك
  if (!supplier || supplier.tenantId !== actor.tenantId) throw Errors.notFound('المورّد');

  return deps.suppliers.listMovements(supplierId, actor.tenantId, limit);
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

/**
 * تعديل بيانات المورّد.
 *
 * ⚠ الاسم والتليفون والملاحظات بس. الرصيد **مش قابل للتعديل** —
 * هو ناتج جمع الحركات، وأي خانة تعدّله مباشرةً بتخلّي الدفتر
 * يقول رقم والحركات تقول رقم تاني.
 *
 * عايز تعدّل الرصيد؟ سجّل دين أو خصم بسبب مكتوب. الرقم بيتحرّك
 * وورا كل حركة سبب — بدل رقم بيتغيّر ومحدش يعرف مين ولا ليه.
 */
export interface UpdateSupplierRequest {
  name?: string;
  phone?: string | null;
  notes?: string | null;
}

export async function updateSupplier(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  supplierId: string,
  input: UpdateSupplierRequest,
): Promise<void> {
  assertSupplierAccess(actor);

  const existing = await deps.suppliers.findById(supplierId);
  // مورّد محل تاني = غير موجود بالنسبة لك
  if (!existing || existing.tenantId !== actor.tenantId) throw Errors.notFound('المورّد');

  const patch: UpdateSupplierRequest = {};
  if (input.name !== undefined) {
    const name = String(input.name).trim();
    if (name.length < 2 || name.length > 80) {
      throw Errors.validation('اسم المورّد من حرفين إلى 80 حرفًا.');
    }
    patch.name = name;
  }
  if (input.phone !== undefined) patch.phone = readPhone(input.phone);
  if (input.notes !== undefined) patch.notes = readNotes(input.notes);

  if (Object.keys(patch).length === 0) throw Errors.validation('لم يتغيّر شيء.');

  await deps.suppliers.update(supplierId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'supplier.update',
    entity: 'Supplier',
    entityId: supplierId,
    // ⚠ الاسم القديم في السجل. "اتغيّر الاسم" من غير "من إيه"
    // مش سجل — نفس قاعدة `closing.roles.update`.
    metadata: { changed: Object.keys(patch), from: existing.name },
  });
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
 * ⚠ ما بيمسّش الخزنة. الدين زاد والدرج ما اتغيّرش.
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
 * خصم من التاجر.
 *
 * ⚠ بيقلّل الدين **بلا أي حركة فلوس**. الدرج ما بيتغيّرش.
 *
 * ══ ليه مش سداد؟ ══
 * تسجيله كسداد كان هينقّص الخزنة وهي ما نقصتش — ورصيدك على
 * الورق يبقى أقل من اللي في الدرج فعلاً، والفرق بيتراكم كل شهر
 * لحد ما تقعد تدوّر على فلوس موجودة.
 *
 * ══ ⚠ والملاحظة إلزامية هنا، على عكس باقي الحركات ══
 * الدين والسداد وراهم أثر مادي: بضاعة استلمتها، أو فلوس خرجت
 * من الدرج. الخصم **رقم بينقص وبس**.
 *
 * فمن غير سبب مكتوب، مفيش طريقة تفرّق بين خصم حقيقي وغلطة
 * وتلاعب بعد شهرين. السبب هنا هو الأثر.
 */
export async function recordSupplierDiscount(
  deps: SupplierDeps,
  actor: AuthenticatedUser,
  supplierId: string,
  input: MovementRequest,
): Promise<{ movementId: string; newBalance: number }> {
  assertSupplierAccess(actor);

  const supplier = await deps.suppliers.findById(supplierId);
  if (!supplier || supplier.tenantId !== actor.tenantId) throw Errors.notFound('المورّد');

  const amountPiastres = readAmount(input.amount);
  const date = readDate(input.date);
  const note = readNotes(input.note);
  if (!note) throw Errors.validation('اكتب سبب الخصم.');

  const result = await deps.suppliers.recordDiscount({
    supplierId,
    actorId: actor.id,
    amountPiastres,
    note,
    date,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'supplier.discount',
    entity: 'Supplier',
    entityId: supplierId,
    metadata: { name: supplier.name, amountPiastres, newBalance: result.newBalance, date, note },
  });

  return result;
}

/**
 * سداد — عملية ذرية بتطلّع فلوس من الخزنة.
 *
 * ⚠ الخزنة والدفتر بيتحرّكوا مع بعض جوّه قاعدة البيانات.
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

  if (!input.treasuryId) throw Errors.validation('اختر الخزنة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزنة');

  // مدير الفرع بيدفع من خزنة فرعه. صاحب المحل من أي خزنة.
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
