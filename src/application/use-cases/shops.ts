/**
 * حساب المحلات — البضاعة اللي بتخرج بالأجل
 *
 * ══ المرآة المقلوبة للموردين ══
 *   الموردين  →  دين **عليك**   (بضاعة دخلت بالأجل)
 *   المحلات   →  دين **ليك**    (بضاعة خرجت بالأجل)
 *
 * نفس البنية بالحرف: دفتر حركات، والرصيد ناتج جمع مش رقم
 * مخزّن. والسداد بيمسّ الخزنة — بس بالعكس: الفلوس بتدخل.
 *
 * ══ ⚠⚠ والخروج ده **مش بيعة** ══
 * قرار واعٍ اتاخد، ومكتوب هنا عشان يفضل مقروء.
 *
 * لما البضاعة تخرج لمحل بالأجل:
 *   • المخزون بينقص فورًا
 *   • الدين بيتسجّل على المحل
 *   • وقائمة الدخل **ما بتشوفش حاجة**
 *
 * ══ اللي بتخسره ══
 * بضاعة بمية ألف تخرج النهاردة، وتقرير الشهر بيقول إنك ما
 * بعتش حاجة. والربح بيظهر فجأة بعد شهرين لما المحل يسدّد.
 *
 * ⚠ يعني أرباحك الشهرية هتبقى **متذبذبة**، والتذبذب ده مش
 * بيعكس شغلك الحقيقي.
 *
 * ⚠ وأخطر من كده: بين الخروج والسداد، البضاعة مش في المخزون
 * ومش في الإيراد. هي في **مكان تالت** — وهو الدفتر ده.
 *
 * ══ اللي بيخلّي القرار مقبول ══
 * الدفتر ظاهر في شاشة مستقلة. فطول ما بتفتحها، البضاعة مش
 * ضايعة — هي مسجّلة ومعروف مين واخدها.
 *
 *    ⚠ لو الشاشة اتسابت شهر من غير ما حد يبصّ فيها، القرار
 *      ده بيبقى بلا أي رقابة.
 *
 * ودي نفس مقايضة رفّ المراجعة في الاسترجاع بالظبط: الرقابة
 * اتنقلت من **منع** لـ**كشف**، والكشف محتاج حد يكشف فعلاً.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { MoneyError, parseCount, parseMoneyToPiastres } from '../../domain/money';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  ConsignLine,
  ShopBalance,
  ShopRepository,
  TreasuryRepository,
} from '../ports';

export interface ShopDeps {
  shops: ShopRepository;
  treasuries: TreasuryRepository;
  clock: Clock;
  audit: AuditLogger;
}

/**
 * ⚠ نفس صلاحية الموردين — `supplier.manage`.
 *
 * السبب إن ده **دفتر ديون**، والديون معلومة مالية زي ديون
 * الموردين بالظبط. اللي مش مسموح له يشوف كام إنت مديون، مش
 * مسموح له يشوف كام الناس مديونة لك.
 *
 * ⚠ وصلاحية جديدة كانت هتكسر الفحص الأمني الدوري: فحص رقم ٣
 * بيفشل لو مشغّل المنصّة اتدّى أي صلاحية غير `tenant.*`، وأي
 * مفتاح جديد بيحتاج مراجعة الكتالوج كله.
 */
function assertShopAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE)) {
    throw Errors.forbidden(PERMISSIONS.SUPPLIER_MANAGE);
  }
}

// ─────────── القراءة ───────────

export async function listShopAccounts(
  deps: ShopDeps,
  actor: AuthenticatedUser,
): Promise<ShopBalance[]> {
  assertShopAccess(actor);
  return deps.shops.listBalances(actor.tenantId);
}

// ─────────── الكتابة ───────────

export interface CreateShopRequest {
  name: string;
  contactName?: string | null;
  phone?: string | null;
  notes?: string | null;
}

export async function createShopAccount(
  deps: ShopDeps,
  actor: AuthenticatedUser,
  input: CreateShopRequest,
): Promise<{ id: string }> {
  assertShopAccess(actor);

  const name = String(input.name ?? '').trim();
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم المحل من حرفين إلى 80 حرفًا.');
  }

  const created = await deps.shops.create({
    tenantId: actor.tenantId,
    // ⚠ الفرع من الجلسة مش من الطلب — نفس نمط المنتجات
    // والعملاء والمستخدمين. المالك بلا فرع بيفتح حساب على
    // مستوى المحل كله.
    branchId: actor.branchId ?? null,
    name,
    contactName: readText(input.contactName, 80, 'اسم المسؤول طويل جدًا.'),
    phone: readText(input.phone, 32, 'رقم الهاتف طويل جدًا.'),
    notes: readText(input.notes, 500, 'الملاحظات أطول من الحد المسموح.'),
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'shop.create',
    entity: 'ShopAccount',
    entityId: created.id,
    metadata: { name, tenantId: actor.tenantId },
  });

  return created;
}

export async function updateShopAccount(
  deps: ShopDeps,
  actor: AuthenticatedUser,
  shopId: string,
  input: { name?: string; contactName?: string | null; phone?: string | null },
): Promise<void> {
  assertShopAccess(actor);

  const existing = await deps.shops.findById(shopId);
  // حساب محل تاني = غير موجود بالنسبة لك
  if (!existing || existing.tenantId !== actor.tenantId) throw Errors.notFound('الحساب');

  const patch: { name?: string; contactName?: string | null; phone?: string | null } = {};
  if (input.name !== undefined) {
    const name = String(input.name).trim();
    if (name.length < 2 || name.length > 80) {
      throw Errors.validation('اسم المحل من حرفين إلى 80 حرفًا.');
    }
    patch.name = name;
  }
  if (input.contactName !== undefined) {
    patch.contactName = readText(input.contactName, 80, 'اسم المسؤول طويل جدًا.');
  }
  if (input.phone !== undefined) {
    patch.phone = readText(input.phone, 32, 'رقم الهاتف طويل جدًا.');
  }

  if (Object.keys(patch).length === 0) throw Errors.validation('لم يتغيّر شيء.');

  await deps.shops.update(shopId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'shop.update',
    entity: 'ShopAccount',
    entityId: shopId,
    // ⚠ الاسم القديم في السجل. "اتغيّر" من غير "من إيه" مش سجل.
    metadata: { changed: Object.keys(patch), from: existing.name },
  });
}

export interface ConsignRequest {
  items: Array<{ productId?: string; quantity?: unknown; unitPrice?: string }>;
  note?: string | null;
  date?: string | null;
}

/**
 * خروج بضاعة أجل.
 *
 * ⚠ الحراسة الحقيقية (الكمية المتاحة · قفل الصفوف · حاجز
 * المحل) جوّه دالة قاعدة البيانات، جنب البيانات.
 *
 * الفحوصات هنا بتطلّع رسايل عربية واضحة قبل ما نروح للقاعدة —
 * سلة فاضية أو سعر مكتوب غلط مالوش لزوم يوصل لرحلة شبكة.
 */
export async function consignToShop(
  deps: ShopDeps,
  actor: AuthenticatedUser,
  shopId: string,
  input: ConsignRequest,
): Promise<{ movementId: string; totalPiastres: number; newBalance: number }> {
  assertShopAccess(actor);

  const shop = await deps.shops.findById(shopId);
  if (!shop || shop.tenantId !== actor.tenantId) throw Errors.notFound('الحساب');

  if (!Array.isArray(input.items) || input.items.length === 0) {
    throw Errors.validation('اختر صنف واحد على الأقل.');
  }
  // ⚠ سقف احترازي. سلة بألف بند معناها غالبًا غلط في الواجهة
  // مش خروج حقيقي، والقاعدة هتقفل ألف صف قبل ما نكتشفه.
  if (input.items.length > 100) {
    throw Errors.validation('الحد 100 صنف في الخروج الواحد.');
  }

  const items: ConsignLine[] = input.items.map((line) => {
    const productId = String(line?.productId ?? '').trim();
    if (!productId) throw Errors.validation('صنف غير محدّد في السلة.');

    let quantity: number;
    let unitPricePiastres: number;
    try {
      quantity = parseCount(line?.quantity);
      unitPricePiastres = parseMoneyToPiastres(String(line?.unitPrice ?? ''));
    } catch (error) {
      throw Errors.validation(
        error instanceof MoneyError ? error.message : 'بيانات السلة غير صالحة.',
      );
    }
    if (quantity <= 0) throw Errors.validation('الكمية لازم تكون أكبر من صفر.');

    return { productId, quantity, unitPricePiastres };
  });

  const result = await deps.shops.consign({
    shopId,
    // ⚠ من الجلسة مش من الطلب. البضاعة بتخرج من المخزون —
    // لو أخدناه من الطلب، أي حد يخرّج باسم زميله ويختفي من السجل.
    actorId: actor.id,
    items,
    note: readText(input.note, 500, 'الملاحظة أطول من الحد المسموح.'),
    date: readDate(input.date),
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'shop.consign',
    entity: 'ShopAccount',
    entityId: shopId,
    metadata: {
      name: shop.name,
      movementId: result.movementId,
      totalPiastres: result.totalPiastres,
      newBalance: result.newBalance,
      // ⚠ البنود في السجل كمان مش في الجدول بس. لو حصل خلاف
      // بعد شهور، السجل بيقول خرج إيه من غير ما تفتح الحركة.
      lines: items.map((l) => ({
        productId: l.productId,
        quantity: l.quantity,
        unitPricePiastres: l.unitPricePiastres,
      })),
    },
  });

  return result;
}

export interface ShopPaymentRequest {
  amount: string;
  treasuryId?: string;
  note?: string | null;
  date?: string | null;
}

/**
 * سداد من المحل — عملية ذرية بتدخّل فلوس الخزنة.
 *
 * ⚠ عكس سداد المورّد بالظبط: هناك الفلوس بتطلع، وهنا بتدخل.
 * والاتنين لازم يمسّوا الدفتر والخزنة مع بعض، وإلا رصيدك على
 * الورق بيختلف عن اللي في الدرج.
 */
export async function recordShopPayment(
  deps: ShopDeps,
  actor: AuthenticatedUser,
  shopId: string,
  input: ShopPaymentRequest,
): Promise<{ movementId: string; treasuryMovementId: string; newBalance: number }> {
  assertShopAccess(actor);

  const shop = await deps.shops.findById(shopId);
  if (!shop || shop.tenantId !== actor.tenantId) throw Errors.notFound('الحساب');

  if (!input.treasuryId) throw Errors.validation('اختر الخزنة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزنة');

  // مدير الفرع بيقبض في خزنة فرعه. صاحب المحل في أي خزنة.
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (scope.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  let amountPiastres: number;
  try {
    amountPiastres = parseMoneyToPiastres(String(input.amount ?? ''));
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'المبلغ غير صالح.');
  }

  const result = await deps.shops.recordPayment({
    shopId,
    actorId: actor.id,
    treasuryId: input.treasuryId,
    amountPiastres,
    note: readText(input.note, 500, 'الملاحظة أطول من الحد المسموح.'),
    date: readDate(input.date),
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'shop.payment',
    entity: 'ShopAccount',
    entityId: shopId,
    metadata: {
      name: shop.name,
      amountPiastres,
      treasuryId: input.treasuryId,
      movementId: result.treasuryMovementId,
      newBalance: result.newBalance,
    },
  });

  return result;
}

// ─────────── فاحصات المدخلات ───────────

function readText(raw: string | null | undefined, max: number, message: string): string | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  if (text.length > max) throw Errors.validation(message);
  return text;
}

function readDate(raw: string | null | undefined): string | null {
  try {
    return parseDateInput(raw);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
}
