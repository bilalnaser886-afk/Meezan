/**
 * البيع
 *
 * ══ العملية الذرية ══
 * البيع أربع خطوات لازم يحصلوا كلهم أو ولا واحد فيهم:
 *   1) الكمية كافية؟          ← يرفض البيع لو لأ
 *   2) اخصم من المخزون
 *   3) اكتب الفاتورة وبنودها
 *   4) سجّل الفلوس في الخزينة
 *
 * تشبيه: التحويل البنكي. الفلوس ما بتقفش في النص بين الحسابين.
 * يا بتوصل يا بترجع مكانها. مفيش حالة تالتة.
 *
 * الأربع خطوات دول بيحصلوا **جوّه قاعدة البيانات** في معاملة
 * واحدة، مش هنا. الملف ده بيحرس وبيتحقّق وبيبعت الطلب — لكن
 * الضمانة الحقيقية جنب البيانات، مش على مسافة رحلة شبكة منها.
 *
 * ══ ليه ده مهم قوي؟ ══
 * لو الموظّف قفل المتصفح في نص العملية، أو النت قطع، أو الخادم
 * وقع — مفيش صف يتيم ولا خصم مخزون بلا سبب. القاعدة بترجّع كل
 * حاجة زي ما كانت لوحدها.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  CreateSaleResult,
  EnrichedSale,
  ListScope,
  SaleDetail,
  SaleLineInput,
  SaleRepository,
  TreasuryRepository,
  UserRepository,
} from '../ports';

export interface SaleDeps {
  sales: SaleRepository;
  treasuries: TreasuryRepository;
  users: UserRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateSaleRequest {
  treasuryId: string;
  items: SaleLineInput[];
  customerName?: string | null;
  customerPhone?: string | null;
  /** فاضي = تاريخ النهاردة بتوقيت القاهرة */
  exitDate?: string | null;
}

/** سقف السلة — نفس الرقم الموجود في دالة قاعدة البيانات */
const MAX_LINES = 100;
const MAX_QTY_PER_LINE = 10_000;

export async function createSale(
  deps: SaleDeps,
  actor: AuthenticatedUser,
  input: CreateSaleRequest,
): Promise<CreateSaleResult> {
  if (!actor.permissions.includes(PERMISSIONS.SALES_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.SALES_CREATE);
  }

  // ─── السلة ───
  if (!Array.isArray(input.items) || input.items.length === 0) {
    throw Errors.validation('السلة فارغة.');
  }
  if (input.items.length > MAX_LINES) {
    throw Errors.validation(`السلة تتجاوز الحد المسموح (${MAX_LINES} بندًا).`);
  }

  const items: SaleLineInput[] = input.items.map((line) => {
    const productId = typeof line?.productId === 'string' ? line.productId.trim() : '';
    const quantity = Number(line?.quantity);

    if (!productId) throw Errors.validation('يوجد بند بلا منتج.');
    if (!Number.isInteger(quantity) || quantity <= 0) {
      throw Errors.validation('كمية غير صالحة في السلة.');
    }
    if (quantity > MAX_QTY_PER_LINE) {
      throw Errors.validation('الكمية في البند أكبر من الحد المسموح.');
    }

    // السعر اليدوي — للمنتجات اللي مالهاش سعر مسجّل.
    //
    // ⚠ الحراسة الحقيقية جوّه دالة قاعدة البيانات: لو المنتج له
    // سعر، بتتجاهل القيمة دي تمامًا. الفحص هنا للشكل بس، عشان
    // نطلّع رسالة عربية واضحة بدل خطأ من القاعدة.
    let unitPricePiastres: number | null = null;
    if (line?.unitPricePiastres != null) {
      const price = Number(line.unitPricePiastres);
      if (!Number.isInteger(price) || price <= 0) {
        throw Errors.validation('السعر المكتوب غير صالح.');
      }
      unitPricePiastres = price;
    }

    return { productId, quantity, unitPricePiastres };
  });

  // ─── الخزينة ───
  // الخزينة هي اللي بتحدد الفرع ووسيلة الدفع مع بعض.
  //
  // ⚠ مفيش حقل اسمه payment_method في النظام عن قصد. لو خزّنّا
  // وسيلة الدفع ورقم الخزينة مع بعض، أول ما حد يختار غلط هيبقى
  // عندنا فاتورة مكتوب عليها "كاش" ومربوطة بخزينة فيزا، ومحدش
  // هيعرف مين الصح. مصدر واحد للحقيقة.
  if (!input.treasuryId) throw Errors.validation('اختر الخزينة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  // خزينة محل تاني = غير موجودة بالنسبة لك
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزينة');

  if (scope.branchId === null) {
    throw Errors.validation('هذه الخزينة غير تابعة لفرع، ولا يمكن تسجيل بيع عليها.');
  }
  // المالك (بلا فرع) بيبيع في أي فرع. غيره في فرعه بس.
  if (actor.roleKey !== 'SUPER_ADMIN') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (scope.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  // ─── بيانات العميل (اختيارية) ───
  const customerName = trimOrNull(input.customerName, 80, 'اسم العميل طويل جدًا.');
  const customerPhone = trimOrNull(input.customerPhone, 32, 'رقم الهاتف غير صالح.');

  // ─── تاريخ الخروج ───
  // فاضي = النهاردة. قيمة = بيع اتسجّل متأخر بتاريخه الحقيقي.
  let exitDate: string | null;
  try {
    exitDate = parseDateInput(input.exitDate);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  // ─── التنفيذ ───
  // ⚠ أهم سطر في الملف: `staffId` بيتاخد من **الجلسة** مش من
  // جسم الطلب. لو أخدناه من الطلب، أي موظّف يقدر يسجّل بيع باسم
  // زميله بتعديل بسيط في المتصفح — والعمولات والمحاسبة تبقى
  // بلا معنى.
  const result = await deps.sales.create({
    tenantId: actor.tenantId,
    staffId: actor.id,
    treasuryId: input.treasuryId,
    items,
    customerName,
    customerPhone,
    exitDate,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'sale.create',
    entity: 'Sale',
    entityId: result.saleId,
    metadata: {
      totalPiastres: result.totalPiastres,
      itemCount: result.itemCount,
      treasuryId: input.treasuryId,
      branchId: scope.branchId,
      movementId: result.movementId,
      exitDate,
    },
  });

  return result;
}

// ─────────── القراءة ───────────

/**
 * ثلاث درجات رؤية، بتتفحص من الأوسع للأضيق.
 *
 * تشبيه أحزمة: المالك بيدخل كل الصالات، مدير الفرع صالته،
 * والموظّف بساطه هو بس.
 *
 * ⚠ الترتيب مهم: لو بدأنا بالأضيق، صاحب الصلاحية الأوسع كان
 * هيتحبس في الأضيق لأن عنده الاتنين.
 */
function readScope(actor: AuthenticatedUser): { scope: ListScope; staffId?: string } {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  // ⚠ "كل الفروع" بقت "كل فروع **محله**".
  // الصلاحية sales.view_all عمرها ما كانت معناها كل المحلات —
  // بس النوع القديم كان بيسمح بده. دلوقتي مستحيل.
  if (actor.permissions.includes(PERMISSIONS.SALES_VIEW_ALL)) {
    return { scope: { tenantId: actor.tenantId } };
  }

  if (actor.permissions.includes(PERMISSIONS.SALES_VIEW_BRANCH)) {
    // fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله
    return { scope: { tenantId: actor.tenantId, branchId: actor.branchId ?? '__none__' } };
  }

  if (actor.permissions.includes(PERMISSIONS.SALES_VIEW_OWN)) {
    return {
      scope: { tenantId: actor.tenantId, branchId: actor.branchId ?? '__none__' },
      staffId: actor.id,
    };
  }

  throw Errors.forbidden(PERMISSIONS.SALES_VIEW_OWN);
}

export async function listSales(
  deps: SaleDeps,
  actor: AuthenticatedUser,
  limit = 50,
): Promise<EnrichedSale[]> {
  const { scope, staffId } = readScope(actor);

  // قوايم صغيرة على التوازي وبنركّب الأسماء منهم — نفس النمط
  // المستخدم في الخزينة. أرخص وأمتن من ربط جدول المستخدمين
  // مرتين في نفس الاستعلام.
  //
  // ⚠ لو النطاق محصور في فواتيري أنا، مش بنجيب قائمة الفريق خالص.
  // الاسم الوحيد اللي هيظهر هو اسمي، وأنا عارفه. جلب قائمة زمايلي
  // عشان أقرا اسمي منها = بيانات ما ليش لازمة بيها.
  const [sales, team, treasuries] = await Promise.all([
    deps.sales.list({ scope, staffId, limit: Math.min(Math.max(limit, 1), 200) }),
    staffId ? Promise.resolve([]) : deps.users.listInScope(scope),
    deps.treasuries.listBalances(
      actor.tenantId,
      actor.roleKey === 'SUPER_ADMIN' ? null : actor.branchId,
    ),
  ]);

  const staffNames = new Map(team.map((u) => [u.id, u.fullName]));
  if (staffId) staffNames.set(actor.id, actor.fullName);

  const treasuryNames = new Map(treasuries.map((t) => [t.treasuryId, t.name]));

  return sales.map((s) => ({
    ...s,
    staffName: staffNames.get(s.staffId) ?? null,
    treasuryName: treasuryNames.get(s.treasuryId) ?? null,
  }));
}

export async function getSale(
  deps: SaleDeps,
  actor: AuthenticatedUser,
  saleId: string,
): Promise<SaleDetail> {
  const { scope, staffId } = readScope(actor);

  const includeCost = actor.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL);
  const sale = await deps.sales.findById(saleId, { includeCost });
  if (!sale) throw Errors.notFound('الفاتورة');

  // الحراسة بتتعمل تاني هنا على السجل نفسه. الفلتر في الاستعلام
  // بيخدم القوايم، لكن الجلب بالمعرّف المباشر لازم يتفحص بإيده —
  // وإلا أي حد يعرف رقم فاتورة يقراها.
  // ⚠ حاجز المحل الأول ودايمًا. الجلب بالمعرّف المباشر لازم
  // يتفحص بإيده — الفلتر في القوايم مش بيحمي النداء ده.
  if (sale.tenantId !== actor.tenantId) throw Errors.notFound('الفاتورة');

  if ('branchId' in scope && sale.branchId !== scope.branchId) {
    throw Errors.forbidden('branch scope');
  }
  if (staffId && sale.staffId !== staffId) {
    throw Errors.forbidden('sale scope');
  }

  return sale;
}

/**
 * تعديل تاريخ الخروج بعد تسجيل البيع.
 *
 * ══ مين يقدر؟ ══
 * اللي سجّل البيع، والمالك.
 *
 * ليه اللي سجّله؟ لأنه هو اللي عارف البضاعة خرجت إمتى فعلاً.
 * ولو حصرناها في المدير، هيبقى لازم يسأله في كل تصحيح — والنتيجة
 * إن التصحيح ما بيحصلش أصلاً والتاريخ يفضل غلط.
 *
 * ══ الحريّة معاها أثر ══
 * تعديل التاريخ بينقل إيراد من شهر لشهر. فكل تعديل بيتسجّل في
 * سجل التدقيق بالقيمة القديمة والجديدة ومين عمله.
 *
 * تشبيه محاسبي: القيد العكسي مسموح، بس بيتكتب في الدفتر بتوقيع.
 * مش ممنوع — مكتوب.
 */
export async function updateSaleExitDate(
  deps: SaleDeps,
  actor: AuthenticatedUser,
  saleId: string,
  rawExitDate: string,
): Promise<{ exitDate: string }> {
  if (!actor.permissions.includes(PERMISSIONS.SALES_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.SALES_CREATE);
  }

  const includeCost = actor.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL);
  const sale = await deps.sales.findById(saleId, { includeCost });
  if (!sale) throw Errors.notFound('الفاتورة');

  if (sale.tenantId !== actor.tenantId) throw Errors.notFound('الفاتورة');

  const isOwner = actor.roleKey === 'SUPER_ADMIN';
  if (!isOwner && sale.staffId !== actor.id) {
    throw Errors.forbidden('يمكن تعديل تاريخ الفواتير التي سجّلتها فقط.');
  }
  if (!isOwner) {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    if (sale.branchId !== actor.branchId) throw Errors.forbidden('branch scope');
  }

  let exitDate: string | null;
  try {
    exitDate = parseDateInput(rawExitDate);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
  if (!exitDate) throw Errors.validation('اكتب تاريخ الخروج.');

  if (exitDate === sale.exitDate) throw Errors.validation('التاريخ نفسه لم يتغيّر.');

  await deps.sales.updateExitDate(saleId, exitDate);

  await deps.audit.record({
    actorId: actor.id,
    action: 'sale.exit_date.update',
    entity: 'Sale',
    entityId: saleId,
    // ⚠ القيمة القديمة والجديدة مع بعض. من غير القديمة، السجل
    // بيقول "اتغيّر" من غير ما يقول "من إيه" — وده مش سجل.
    metadata: {
      from: sale.exitDate,
      to: exitDate,
      totalPiastres: sale.totalPiastres,
      staffId: sale.staffId,
    },
  });

  return { exitDate };
}

// ─────────── أدوات ───────────

function trimOrNull(value: string | null | undefined, max: number, message: string): string | null {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) return null;
  if (trimmed.length > max) throw Errors.validation(message);
  return trimmed;
}
