/**
 * الصيانة
 *
 * ══ نوعين مختلفين تمامًا ══
 * فيه حالتين اسمهم "جهاز في الصيانة"، ولو دمجناهم هيبقى عندنا
 * جدول نصّه أعمدة فاضية:
 *
 *  ١) جهاز **المحل** — بضاعتك، ليها تكلفة وسعر بيع وبتدخل
 *     المخزون والتقارير. مربوطة بـ `products`.
 *
 *  ٢) جهاز **العميل** — مش بضاعتك، ما دخلش مخزونك، وعمره ما
 *     هيتباع. ليه صاحب ورقم وشكوى وكلمة مرور.
 *
 * تشبيه: عربيتك في الورشة، وعربية زبونك في ورشتك. الاتنين
 * "في الصيانة"، ومحدش بيكتبهم في نفس الدفتر.
 *
 * ══ وجهاز المحل بيتخصم من المخزون وقت الإرسال ══
 * نفس منطق التحويل بين الفروع: الجهاز ساب الرفّ، فما ينفعش
 * يفضل متاح للبيع وهو في الورشة.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { MoneyError, parseCostToPiastres } from '../../domain/money';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  MaintenanceFilter,
  MaintenanceRecord,
  MaintenanceRepository,
  ProductMaintenanceRow,
  RepairShop,
  RepairTicket,
  ShopHistoryRow,
  TicketStatus,
} from '../ports';

export interface MaintenanceDeps {
  maintenance: MaintenanceRepository;
  /** لازم للتحقق إن الفرع اللي المالك اختاره جوّه محله */
  branches: BranchRepository;
  clock: Clock;
  audit: AuditLogger;
}

const TICKET_STATUSES: TicketStatus[] = [
  'CHECKING',
  'WAITING_PART',
  'READY',
  'DELIVERED',
  'CANCELLED',
];

// ─────────── حراسة ───────────

function assertView(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.MAINTENANCE_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.MAINTENANCE_VIEW);
  }
}

function assertManage(actor: AuthenticatedUser): void {
  assertView(actor);
  if (!actor.permissions.includes(PERMISSIONS.MAINTENANCE_MANAGE)) {
    throw Errors.forbidden(PERMISSIONS.MAINTENANCE_MANAGE);
  }
}

/** fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله */
function branchScope(actor: AuthenticatedUser): string | null {
  return actor.roleKey === 'SUPER_ADMIN' ? null : (actor.branchId ?? '__none__');
}

// ─────────── الورش ───────────

export async function listRepairShops(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
): Promise<RepairShop[]> {
  assertView(actor);
  return deps.maintenance.listShops(actor.tenantId);
}

export async function createRepairShop(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  input: { name: string; phone?: string | null; notes?: string | null },
): Promise<{ id: string }> {
  assertManage(actor);

  const name = String(input.name ?? '').trim();
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم محل الصيانة من حرفين إلى 80 حرفًا.');
  }

  const created = await deps.maintenance.createShop({
    tenantId: actor.tenantId,
    name,
    phone: text(input.phone, 32, 'رقم الهاتف طويل جدًا.'),
    notes: text(input.notes, 500, 'الملاحظات أطول من الحد المسموح.'),
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'repair_shop.create',
    entity: 'RepairShop',
    entityId: created.id,
    metadata: { name },
  });

  return created;
}

export async function getShopHistory(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  shopId: string,
): Promise<ShopHistoryRow[]> {
  assertView(actor);
  // ⚠ المحل بيتبعت للدالة، فالورشة بتاعة محل تاني بترجّع فاضي
  return deps.maintenance.shopHistory(shopId, actor.tenantId);
}

// ─────────── أجهزة المحل ───────────

export async function sendToMaintenance(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  productId: string,
  input: { shopId?: string | null; fault: string; cost?: string | null },
): Promise<{ recordId: string; productName: string }> {
  assertManage(actor);

  const fault = String(input.fault ?? '').trim();
  if (fault.length < 3 || fault.length > 500) {
    throw Errors.validation('اكتب وصف العطل (من 3 إلى 500 حرف).');
  }

  const result = await deps.maintenance.sendToShop({
    productId,
    actorId: actor.id,
    shopId: input.shopId || null,
    fault,
    costPiastres: money(input.cost),
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'maintenance.send',
    entity: 'MaintenanceRecord',
    entityId: result.recordId,
    // ⚠ الإرسال بيخصم من المخزون. لازم يتسجّل مين ولإيه —
    // وإلا الجهاز بيختفي من المخزن والدفتر ساكت.
    metadata: { productId, productName: result.productName, fault, shopId: input.shopId ?? null },
  });

  return result;
}

export async function returnFromMaintenance(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  recordId: string,
  input: { status: string; cost?: string | null; note?: string | null },
): Promise<{ productName: string; finalStatus: string }> {
  assertManage(actor);

  const status = String(input.status ?? '');
  if (status !== 'RETURNED' && status !== 'CANCELLED') {
    throw Errors.validation('الحالة غير صحيحة.');
  }

  const result = await deps.maintenance.returnFromShop(
    recordId,
    actor.id,
    status,
    input.cost === undefined || input.cost === null ? null : money(input.cost),
    text(input.note, 500, 'الملاحظة طويلة جدًا.'),
  );

  await deps.audit.record({
    actorId: actor.id,
    action: 'maintenance.return',
    entity: 'MaintenanceRecord',
    entityId: recordId,
    metadata: { productName: result.productName, status: result.finalStatus },
  });

  return result;
}

export interface FilterInput {
  scope?: string;
  search?: string | null;
  from?: string | null;
  to?: string | null;
  shopId?: string | null;
}

/**
 * قراءة الفلاتر.
 *
 * ⚠ الفترة بتتفحص بـ `parseDateInput` — بترفض المستقبل والصيغة
 * الغلط، وبترجّع null للفاضي (يعني بلا حد).
 */
function readFilter(input: FilterInput, allowed: string[]): MaintenanceFilter {
  const scope = String(input.scope ?? allowed[0]);
  if (!allowed.includes(scope)) throw Errors.validation('النطاق غير صحيح.');

  let from: string | null;
  let to: string | null;
  try {
    from = parseDateInput(input.from);
    to = parseDateInput(input.to);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
  if (from && to && from > to) throw Errors.validation('تاريخ البداية بعد تاريخ النهاية.');

  return {
    scope,
    search: (input.search ?? '').trim() || null,
    from,
    to,
    shopId: input.shopId || null,
  };
}

export async function listMaintenanceRecords(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  input: FilterInput = {},
): Promise<MaintenanceRecord[]> {
  assertView(actor);
  return deps.maintenance.listRecords(
    actor.tenantId,
    branchScope(actor),
    readFilter(input, ['OPEN', 'RETURNED', 'ALL']),
  );
}

/**
 * تاريخ صيانة منتج — بيتعرض في كارت المنتج.
 *
 * ⚠ مفيش فحص محل هنا لأن المنتج نفسه محروس: اللي وصل لكارته
 * عدّى على فلتر المحل في `listProducts` أصلاً.
 */
export async function getProductMaintenance(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  productId: string,
): Promise<ProductMaintenanceRow[]> {
  assertView(actor);
  return deps.maintenance.productHistory(productId);
}

// ─────────── تذاكر العملاء ───────────

export interface TicketInput {
  customerName: string;
  customerPhone?: string | null;
  deviceName: string;
  serialNumber?: string | null;
  deviceColor?: string | null;
  conditionNote?: string | null;
  complaint: string;
  unlockKind?: string;
  unlockValue?: string | null;
  repairShopId?: string | null;
  cost?: string | null;
  promisedDate?: string | null;
  /**
   * تاريخ استلام الجهاز.
   *
   * ⚠ فاضي = النهاردة (افتراضي الجدول). والتعديل مسموح لأن
   * الجهاز بيتسلّم على الكاونتر وبيتسجّل بعدين — والموظّف
   * اللي بيسجّل الصبح جهاز دخل امبارح لازم يقدر يقول كده.
   *
   * ⚠ والمستقبل مرفوض: جهاز ما بيدخلش الورشة بكرة.
   */
  receivedDate?: string | null;
  /** لو موجود، دي زيارة تانية لنفس الجهاز */
  parentTicketId?: string | null;
  /** مطلوب من صاحب المحل بس — غيره مقفول على فرعه */
  branchId?: string | null;
}

export async function listTickets(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  input: FilterInput = {},
): Promise<RepairTicket[]> {
  assertView(actor);
  return deps.maintenance.listTickets(
    actor.tenantId,
    branchScope(actor),
    readFilter(input, ['OPEN', 'DELIVERED', 'ALL']),
  );
}

/**
 * استلام جهاز عميل.
 *
 * ⚠ صلاحية **العرض** كافية — المندوب هو اللي بيستلم على
 * الكاونتر. الإدارة (الحالة والتكلفة) هي المحصورة.
 */
export async function createTicket(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  input: TicketInput,
): Promise<{ id: string }> {
  assertView(actor);

  /**
   * ══ 🔴 الفرع — الغلطة اللي وقعنا فيها هنا ══
   *
   * الحارس القديم كان بيعدّي صاحب المحل من غير فرع، وبعدين
   * `branch_id` بيتبعت `null` لعمود **إلزامي** في الجدول.
   * النتيجة: خطأ 500 غامض "حدث خطأ غير متوقّع".
   *
   * صاحب المحل مالوش فرع بطبيعته (بيشوف كل فروعه)، فلازم
   * **يختار** الفرع — نفس نمط المنتجات والعملاء بالظبط.
   *
   * ⚠ الدرس: عمود not null + قيمة nullable من الجلسة = عطل
   * بيظهر عند أول استخدام حقيقي مش وقت الكتابة.
   */
  let targetBranchId: string;

  if (actor.roleKey === 'SUPER_ADMIN') {
    if (!input.branchId) throw Errors.validation('اختر الفرع.');

    // المحل جزء من الفحص مش سياق حواليه — من غيره، معرّف
    // مخمَّن يقدر يربط تذكرة بفرع محل تاني
    const exists = await deps.branches.exists(actor.tenantId, input.branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    targetBranchId = input.branchId;
  } else {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    targetBranchId = actor.branchId;
  }

  const customerName = String(input.customerName ?? '').trim();
  if (customerName.length < 2 || customerName.length > 80) {
    throw Errors.validation('اسم العميل من حرفين إلى 80 حرفًا.');
  }

  const deviceName = String(input.deviceName ?? '').trim();
  if (deviceName.length < 2 || deviceName.length > 80) {
    throw Errors.validation('اكتب اسم الجهاز.');
  }

  const complaint = String(input.complaint ?? '').trim();
  if (complaint.length < 3 || complaint.length > 1000) {
    throw Errors.validation('اكتب شكوى العميل (من 3 إلى 1000 حرف).');
  }

  const unlockKind = String(input.unlockKind ?? 'NONE');
  if (!['NONE', 'PASSWORD', 'PATTERN'].includes(unlockKind)) {
    throw Errors.validation('نوع الفتح غير صحيح.');
  }

  const unlockValue = unlockKind === 'NONE'
    ? null
    : text(input.unlockValue, 200, 'بيانات الفتح أطول من الحد المسموح.');

  if (unlockKind !== 'NONE' && !unlockValue) {
    throw Errors.validation('اكتب بيانات الفتح أو اختر «الجهاز مفتوح».');
  }

  let promisedDate: string | null;
  try {
    // ⚠ تاريخ التسليم المتوقّع **في المستقبل** — و`parseDateInput`
    // بترفض المستقبل لأنها متعمّلة لتواريخ حصلت فعلاً.
    // فبنفحصه بإيدنا هنا.
    promisedDate = readFutureDate(input.promisedDate);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  // ══ تاريخ الاستلام ══
  //
  // ⚠ `parseDateInput` هي نفسها المستخدمة في البيع والمرتجع
  // والموردين: بتقبل الأرقام العربية، وبترفض المستقبل، وبترجّع
  // null للفاضي — والـnull هنا معناه "سيب افتراضي الجدول
  // (تاريخ القاهرة) يشتغل".
  let receivedDate: string | null;
  try {
    receivedDate = parseDateInput(input.receivedDate);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  // ══ ⚠ المرتجع لازم يكون على جهاز **اتسلّم** ══
  //
  // الشاشة بتخبّي زرار «رجع تاني» لغير المسلَّم، لكن الإخفاء
  // لافتة مش قفل: أي طلب معدّل بإيد كان بيقدر يربط زيارة
  // جديدة بتذكرة لسه مفتوحة.
  //
  // ⚠ والنتيجة مش شكلية: تذكرتين مفتوحتين لنفس الجهاز في نفس
  // الوقت، وشاشة المرتجعات بتعدّ إصلاح ما فشلش أصلاً — لأنه
  // ما خلصش لسه.
  const parentTicketId = String(input.parentTicketId ?? '').trim() || null;
  if (parentTicketId) {
    const parent = await deps.maintenance.findTicket(parentTicketId);
    if (!parent || parent.tenantId !== actor.tenantId) {
      throw Errors.notFound('الزيارة السابقة');
    }
    if (parent.status !== 'DELIVERED') {
      throw Errors.validation('المرتجع بيتفتح على جهاز اتسلّم للعميل بس.');
    }
  }

  const created = await deps.maintenance.createTicket({
    tenant_id: actor.tenantId,
    branch_id: targetBranchId,
    customer_name: customerName,
    customer_phone: text(input.customerPhone, 32, 'رقم الهاتف طويل جدًا.'),
    device_name: deviceName,
    serial_number: text(input.serialNumber, 64, 'السريال طويل جدًا.'),
    device_color: text(input.deviceColor, 32, 'اللون طويل جدًا.'),
    condition_note: text(input.conditionNote, 500, 'ملاحظة الحالة طويلة جدًا.'),
    complaint,
    unlock_kind: unlockKind,
    unlock_value: unlockValue,
    repair_shop_id: input.repairShopId || null,
    cost_piastres: money(input.cost),
    promised_date: promisedDate,
    // ⚠ بنشيل المفتاح خالص لو فاضي، مش بنبعت null.
    // العمود له افتراضي في الجدول (تاريخ القاهرة)، و`null`
    // الصريح بيدهس على الافتراضي ده.
    ...(receivedDate ? { received_date: receivedDate } : {}),
    parent_ticket_id: parentTicketId,
    created_by_id: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'ticket.create',
    entity: 'RepairTicket',
    entityId: created.id,
    // ⚠ بيانات الفتح **مش** في السجل. تسجيلها هنا كان هيخلّي
    // سجل التدقيق نسخة تانية منها بلا أي حصر على القراءة.
    metadata: {
      customerName,
      deviceName,
      hasUnlock: unlockKind !== 'NONE',
      isRevisit: Boolean(parentTicketId),
      receivedDate,
    },
  });

  return created;
}

/** تحديث الحالة والتكلفة وملاحظة العمل — للإدارة */
export async function updateTicket(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  ticketId: string,
  input: {
    status?: string;
    cost?: string | null;
    workNote?: string | null;
    repairShopId?: string | null;
  },
): Promise<void> {
  assertManage(actor);

  const ticket = await deps.maintenance.findTicket(ticketId);
  if (!ticket || ticket.tenantId !== actor.tenantId) throw Errors.notFound('التذكرة');

  if (actor.roleKey !== 'SUPER_ADMIN' && ticket.branchId !== actor.branchId) {
    throw Errors.forbidden('branch scope');
  }

  const patch: Record<string, unknown> = {};

  if (input.status !== undefined) {
    if (!TICKET_STATUSES.includes(input.status as TicketStatus)) {
      throw Errors.validation('الحالة غير صحيحة.');
    }
    patch.status = input.status;
    // التسليم بيثبّت تاريخه لوحده — الموظّف مش بيكتبه
    if (input.status === 'DELIVERED') patch.delivered_date = new Date().toISOString().slice(0, 10);
  }

  if (input.cost !== undefined) patch.cost_piastres = money(input.cost);
  if (input.workNote !== undefined) {
    patch.work_note = text(input.workNote, 1000, 'ملاحظة العمل طويلة جدًا.');
  }
  if (input.repairShopId !== undefined) patch.repair_shop_id = input.repairShopId || null;

  if (Object.keys(patch).length === 0) throw Errors.validation('لم يتغيّر شيء.');

  await deps.maintenance.updateTicket(ticketId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'ticket.update',
    entity: 'RepairTicket',
    entityId: ticketId,
    metadata: { changed: Object.keys(patch) },
  });
}

/**
 * تعديل بيانات فتح الجهاز.
 *
 * ══ ليه دالة منفصلة عن `updateTicket`؟ ══
 * `updateTicket` محصورة على `maintenance.manage` — الحالة
 * والتكلفة قرارات إدارية.
 *
 * لكن تصحيح كلمة المرور مش قرار إداري: الموظّف اللي كتبها غلط
 * لازم يقدر يصلّح غلطته فورًا، والزبون ممكن يغيّرها ويرجع.
 * لو خلّيناها للمدير، الرقم الغلط هيفضل مكتوب لحد ما المدير
 * يفضى — والجهاز مقفول طول الوقت ده.
 *
 * ⚠ الفعل ده **بيمسح القيمة القديمة**. سجل التدقيق بيقول مين
 * عدّل وإمتى، لكن **مش بيحتفظ بالقيمة القديمة** — تسجيلها كان
 * هيخلّي نسخة تانية من مفتاح الجهاز في مكان أوسع في القراءة.
 */
export async function updateTicketUnlock(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  ticketId: string,
  input: { unlockKind: string; unlockValue?: string | null },
): Promise<void> {
  // صلاحية العرض تكفي — نفس مستوى قراءة البيانات
  assertView(actor);

  const ticket = await deps.maintenance.findTicket(ticketId);
  if (!ticket || ticket.tenantId !== actor.tenantId) throw Errors.notFound('التذكرة');

  if (actor.roleKey !== 'SUPER_ADMIN' && ticket.branchId !== actor.branchId) {
    throw Errors.forbidden('branch scope');
  }

  const kind = String(input.unlockKind ?? 'NONE');
  if (!['NONE', 'PASSWORD', 'PATTERN'].includes(kind)) {
    throw Errors.validation('نوع الفتح غير صحيح.');
  }

  const value = kind === 'NONE'
    ? null
    : text(input.unlockValue, 200, 'بيانات الفتح أطول من الحد المسموح.');

  if (kind !== 'NONE' && !value) {
    throw Errors.validation('اكتب بيانات الفتح أو اختر «الجهاز مفتوح».');
  }

  await deps.maintenance.updateTicket(ticketId, {
    unlock_kind: kind,
    unlock_value: value,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'ticket.unlock.update',
    entity: 'RepairTicket',
    entityId: ticketId,
    // ⚠ النوع بس. القيمة نفسها — القديمة والجديدة — مش بتدخل
    // السجل: ده كان هيخلّي مفتاح الجهاز مكتوب في مكانين.
    metadata: { kind },
  });
}

/**
 * بيانات فتح الجهاز.
 *
 * ⚠ متاحة لأي حد عنده صلاحية الصيانة — الحصر القديم (اللي
 * استلم أو مدير) اتشال بقرار واعٍ.
 *
 * السبب العملي: الموظّف على الكاونتر بيحتاج يفتح الجهاز عشان
 * يوري الزبون النتيجة، حتى لو مش هو اللي استلمه.
 *
 * ⚠ واللي فضل هو **التسجيل**: كل قراءة بتتكتب في سجل التدقيق
 * باسم صاحبها ووقتها. الرقابة اتنقلت من منع لكشف — نفس مقايضة
 * المرتجعات للمندوب، ومقبولة بشرط إن السجل يتبصّ فيه لو حصلت
 * شكوى.
 */
export async function getTicketUnlock(
  deps: MaintenanceDeps,
  actor: AuthenticatedUser,
  ticketId: string,
): Promise<{ kind: string; value: string | null }> {
  assertView(actor);

  const canManage = actor.permissions.includes(PERMISSIONS.MAINTENANCE_MANAGE);
  const result = await deps.maintenance.unlock(ticketId, actor.id, canManage);

  await deps.audit.record({
    actorId: actor.id,
    action: 'ticket.unlock.read',
    entity: 'RepairTicket',
    entityId: ticketId,
    metadata: { kind: result.kind },
  });

  return result;
}

// ─────────── أدوات ───────────

function text(raw: string | null | undefined, max: number, message: string): string | null {
  const value = String(raw ?? '').trim();
  if (!value) return null;
  if (value.length > max) throw Errors.validation(message);
  return value;
}

/** التكلفة — الصفر مقبول (لسه ما اتسعّرش) */
function money(raw: string | null | undefined): number {
  try {
    return parseCostToPiastres(raw);
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'المبلغ غير صالح.');
  }
}

/**
 * تاريخ في المستقبل — عكس `parseDateInput` اللي بترفض المستقبل.
 * تاريخ التسليم المتوقّع لسه ما جاش، فالقاعدة العامة ما تنفعش هنا.
 */
function readFutureDate(raw: string | null | undefined): string | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) throw new DateError('صيغة التاريخ غير صحيحة.');

  const parsed = new Date(`${text}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime()) || !parsed.toISOString().startsWith(text)) {
    throw new DateError('التاريخ غير موجود في التقويم.');
  }
  return text;
}