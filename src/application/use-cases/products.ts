/**
 * المنتجات
 *
 * ══ المبدأ اللي بيحكم الملف كله ══
 * التكلفة سرّ. السعر مش سرّ.
 *
 * أي حد عنده `inventory.view` بيشوف الاسم والسعر والكمية.
 * التكلفة (`cost_piastres`) بيشوفها صاحب `profit.view_real` بس —
 * وده المالك افتراضيًا.
 *
 * ⚠ نقطة التصميم الأهم: الحجب مش في الواجهة.
 * الحقل بيتشال من الكائن في طبقة قاعدة البيانات قبل ما يرجع.
 * مدير الفرع لو فتح تبويب الشبكة في المتصفح وبصّ على الرد الخام،
 * هيلاقي الحقل **مش موجود أصلاً** — مش موجود وفاضي، ولا موجود
 * ومخفي بـ CSS.
 *
 * تشبيه: الفرق بين إنك تدّي حد ملف وتقوله "متبصّش على الصفحة
 * التالتة"، وبين إنك تشيل الصفحة التالتة قبل ما تديله الملف.
 *
 * ══ نقطة تانية تستاهل توضيح ══
 * مدير الفرع **يقدر يكتب** التكلفة وهو **مش قادر يقراها**.
 * ده مقصود ومنطقي: هو اللي بيستلم البضاعة وبيعرف اشتراها بكام،
 * فلازم يقدر يسجّلها. لكن قراءة تكلفة منتج قديم = معرفة هامش
 * الربح، وده قرار ملكية مش قرار تشغيلي.
 *
 * والكتابة ما بتسرّبش قراءة: لما تكتب رقم إنت عارفه أصلاً، إنت
 * ما اتعلمتش حاجة جديدة عن الرقم القديم.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  ListScope,
  PriceChange,
  ProductRecord,
  ProductRepository,
  ProductType,
  UserRepository,
} from '../ports';

export interface ProductDeps {
  products: ProductRepository;
  branches: BranchRepository;
  /** لتحويل معرّفات من غيّر السعر لأسماء */
  users: UserRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateProductRequest {
  name: string;
  productType: ProductType;
  serialNumber?: string | null;
  source?: string | null;
  entryDate?: string | null;
  /** null = المنتج دخل من غير ما يتسعّر بعد */
  pricePiastres: number | null;
  costPiastres: number;
  quantityOnHand: number;
  /** مطلوب من المالك بس — مدير الفرع مقفول على فرعه */
  branchId?: string | null;
}

export interface UpdateProductRequest {
  name?: string;
  pricePiastres?: number | null;
  costPiastres?: number;
  isActive?: boolean;
  source?: string | null;
  serialNumber?: string | null;
  entryDate?: string | null;
}

/** حد أقصى احترازي للكمية — يمنع صفر زيادة بالغلط */
const MAX_QUANTITY = 1_000_000;

/**
 * هل الشخص ده يشوف التكلفة؟
 *
 * ⚠ الفحص بالصلاحية مش بالدور. الفرق مش شكلي:
 * لو كتبنا `roleKey === 'SUPER_ADMIN'`، هنكسر آلية الاستثناءات
 * الفردية — يعني لو حبيت بكرة تدّي محاسب معيّن حق رؤية التكلفة،
 * مش هتقدر. وكل باقي النظام بيفحص صلاحيات، فالاستثناء ده كان
 * هيبقى شاذ.
 */
function canSeeCost(actor: AuthenticatedUser): boolean {
  return actor.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL);
}

/**
 * نطاق القراءة.
 * المالك يشوف كل الفروع. غيره فرعه هو بس، ولو مالوش فرع ما يشوفش
 * حاجة — fail-closed.
 */
function scopeFor(actor: AuthenticatedUser): ListScope {
  if (actor.roleKey === 'SUPER_ADMIN') return { allBranches: true };
  return { branchId: actor.branchId ?? '__none__' };
}

/** حراسة: المنتج ده في نطاقك ولا لأ؟ */
function assertBranchAccess(actor: AuthenticatedUser, targetBranchId: string): void {
  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');
  if (targetBranchId !== actor.branchId) throw Errors.forbidden('branch scope');
}

// ─────────── القراءة ───────────

export async function listProducts(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  options: { activeOnly?: boolean } = {},
): Promise<ProductRecord[]> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_VIEW);
  }

  return deps.products.list(scopeFor(actor), {
    includeCost: canSeeCost(actor),
    activeOnly: options.activeOnly ?? false,
  });
}

/** قائمة شاشة الكاشير: المفعّل والمتاح بس */
export async function listSellableProducts(
  deps: ProductDeps,
  actor: AuthenticatedUser,
): Promise<ProductRecord[]> {
  const all = await listProducts(deps, actor, { activeOnly: true });
  return all.filter((p) => p.quantityOnHand > 0);
}

// ─────────── الكتابة ───────────

/**
 * إضافة منتج.
 *
 * ══ القسمة اللي بتحكم كل حاجة تحت ══
 * الجهاز قطعة فعلية واحدة بسريال. الإكسسوار صنف بكمية.
 * القاعدتين مختلفتين، والخلط بينهم بيدّي مخزون بيكذب:
 * "عندي 3 آيفون" مفيدة، لكن لما واحد فيهم يترجع للصيانة مش
 * هتعرف أنهي واحد.
 */
export async function createProduct(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  input: CreateProductRequest,
): Promise<{ id: string }> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }

  const targetBranchId = await resolveBranch(deps, actor, input.branchId);

  const name = input.name.trim();
  assertName(name);

  const productType = input.productType;
  if (productType !== 'device' && productType !== 'accessory') {
    throw Errors.validation('اختر نوع المنتج: جهاز أو إكسسوار.');
  }

  // ─── قواعد النوع ───
  let serialNumber: string | null = null;
  let quantityOnHand: number;

  if (productType === 'device') {
    serialNumber = (input.serialNumber ?? '').trim();
    if (!serialNumber) {
      throw Errors.validation('اكتب الرقم التسلسلي للجهاز.');
    }
    assertSerial(serialNumber);

    // الكمية مقفولة على واحد — مش بنسأل المستخدم أصلاً.
    // لو سمحنا بغيرها، هيبقى عندنا "جهازين بنفس السريال" وده
    // تناقض في نفسه.
    quantityOnHand = 1;
  } else {
    if ((input.serialNumber ?? '').trim()) {
      throw Errors.validation('الرقم التسلسلي للأجهزة فقط.');
    }
    assertQuantity(input.quantityOnHand);
    quantityOnHand = input.quantityOnHand;
  }

  // ─── السعر اختياري ───
  if (input.pricePiastres !== null) assertPrice(input.pricePiastres);
  assertCost(input.costPiastres);

  const source = trimOrNull(input.source, 80, 'اسم المصدر طويل جدًا.');
  const entryDate = readDate(input.entryDate);

  const created = await deps.products.create({
    branchId: targetBranchId,
    name,
    productType,
    serialNumber,
    source,
    entryDate,
    pricePiastres: input.pricePiastres,
    costPiastres: input.costPiastres,
    quantityOnHand,
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'product.create',
    entity: 'Product',
    entityId: created.id,
    metadata: {
      name,
      productType,
      branchId: targetBranchId,
      hasSerial: serialNumber !== null,
      hasPrice: input.pricePiastres !== null,
      quantityOnHand,
    },
  });

  return created;
}

/**
 * تحديد الفرع المستهدف.
 *
 * نفس نمط إنشاء المستخدم: الفرع بيتاخد من هوية المنشئ مش من جسم
 * الطلب. مندوب المبيعات ومدير الفرع الاتنين مقفولين على فرعهم،
 * ومفيش طريقة يمرّروا فرع تاني حتى لو عدّلوا الطلب بإيدهم.
 */
async function resolveBranch(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  requested: string | null | undefined,
): Promise<string> {
  if (actor.roleKey === 'SUPER_ADMIN') {
    if (!requested) throw Errors.validation('اختر الفرع.');
    const exists = await deps.branches.exists(requested);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    return requested;
  }

  if (!actor.branchId) throw Errors.forbidden('branch scope');
  return actor.branchId; // أي قيمة في الطلب تُتجاهل
}

export async function updateProduct(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  productId: string,
  input: UpdateProductRequest,
): Promise<void> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }

  // بنقرا من غير تكلفة: محتاجين الفرع والنوع للحراسة بس، ومفيش
  // سبب نجيب حقل حسّاس مش هنستخدمه
  const existing = await deps.products.findById(productId, { includeCost: false });
  if (!existing) throw Errors.notFound('المنتج');
  assertBranchAccess(actor, existing.branchId);

  const patch: {
    name?: string;
    pricePiastres?: number | null;
    costPiastres?: number;
    isActive?: boolean;
    source?: string | null;
    serialNumber?: string | null;
    entryDate?: string;
    updatedById: string;
  } = { updatedById: actor.id };

  let changedPrice = false;

  if (input.name !== undefined) {
    const name = input.name.trim();
    assertName(name);
    patch.name = name;
  }

  if (input.pricePiastres !== undefined) {
    if (input.pricePiastres !== null) assertPrice(input.pricePiastres);
    patch.pricePiastres = input.pricePiastres;
    changedPrice = input.pricePiastres !== existing.pricePiastres;
  }

  if (input.costPiastres !== undefined) {
    assertCost(input.costPiastres);
    patch.costPiastres = input.costPiastres;
  }

  if (input.isActive !== undefined) patch.isActive = input.isActive;

  if (input.source !== undefined) {
    patch.source = trimOrNull(input.source, 80, 'اسم المصدر طويل جدًا.');
  }

  if (input.entryDate !== undefined && input.entryDate !== null) {
    const parsed = readDate(input.entryDate);
    if (parsed) patch.entryDate = parsed;
  }

  // السريال يتعدّل للأجهزة بس، وما ينفعش يتفضّى.
  // جهاز بلا سريال = صفّين متطابقين ومفيش طريقة تفرّق بينهم.
  if (input.serialNumber !== undefined) {
    if (existing.productType !== 'device') {
      throw Errors.validation('الرقم التسلسلي للأجهزة فقط.');
    }
    const serial = (input.serialNumber ?? '').trim();
    if (!serial) throw Errors.validation('الجهاز لازم يكون له رقم تسلسلي.');
    assertSerial(serial);
    patch.serialNumber = serial;
  }

  // مفتاح updatedById موجود دايمًا، فبنعدّ اللي غيره
  if (Object.keys(patch).length <= 1) {
    throw Errors.validation('لم يتغيّر شيء.');
  }

  await deps.products.update(productId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'product.update',
    entity: 'Product',
    entityId: productId,
    // ⚠ بنسجّل **إن** التكلفة اتغيّرت، مش قيمتها. سجل التدقيق
    // بيتقرا بصلاحية تانية خالص، فما ينفعش يبقى باب خلفي للتكلفة.
    //
    // السعر مختلف: مش سرّ، وسجل الأسعار المستقل بيحفظ قيمه كاملة.
    metadata: {
      changed: Object.keys(patch).filter((k) => k !== 'updatedById'),
      costChanged: patch.costPiastres !== undefined,
      priceChanged: changedPrice,
    },
  });
}

/**
 * سجل أسعار المنتج — كان كام وبقى كام ومين غيّره.
 *
 * السجل نفسه بتكتبه قاعدة البيانات بمشغّل، مش الكود ده. الدالة
 * بتقراه وبتركّب الأسماء فوق المعرّفات، نفس نمط حركات الخزينة.
 */
export async function getPriceHistory(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  productId: string,
  limit = 10,
): Promise<PriceChange[]> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_VIEW);
  }

  const product = await deps.products.findById(productId, { includeCost: false });
  if (!product) throw Errors.notFound('المنتج');
  assertBranchAccess(actor, product.branchId);

  const [history, team] = await Promise.all([
    deps.products.listPriceHistory(productId, Math.min(Math.max(limit, 1), 50)),
    deps.users.listInScope(scopeFor(actor)),
  ]);

  const names = new Map(team.map((u) => [u.id, u.fullName]));

  return history.map((h) => ({
    ...h,
    changedByName: h.changedById ? (names.get(h.changedById) ?? null) : null,
  }));
}

/**
 * توريد أو خصم كمية.
 *
 * `delta` موجب = توريد، سالب = خصم (تالف، جرد ناقص).
 *
 * ⚠ ليه فرق مش رقم نهائي؟
 * لو بعتنا الرقم النهائي، المدير هيقرا الكمية (10)، وفي نفس اللحظة
 * الموظّف يبيع واحدة (تبقى 9)، وبعدين المدير يكتب 15 وهو قاصد
 * "زوّدت 5" — فيمسح البيعة. الفرق بيخلّي الحسبة تتعمل عند البيانات
 * مش في دماغ المستخدم.
 */
export async function restockProduct(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  productId: string,
  delta: number,
): Promise<{ quantityOnHand: number }> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }

  if (!Number.isInteger(delta) || delta === 0) {
    throw Errors.validation('اكتب كمية صحيحة: موجبة للتوريد، سالبة للخصم.');
  }
  if (Math.abs(delta) > MAX_QUANTITY) {
    throw Errors.validation('الكمية أكبر من الحد المسموح.');
  }

  const existing = await deps.products.findById(productId, { includeCost: false });
  if (!existing) throw Errors.notFound('المنتج');
  assertBranchAccess(actor, existing.branchId);

  // ⚠ الجهاز قطعة واحدة بسريال. توريد كمية ليه معناه إن نفس
  // السريال بقى عليه حتتين — وده مستحيل في الواقع.
  // عايز جهاز تاني؟ أضفه كمنتج جديد بسرياله هو.
  if (existing.productType === 'device') {
    throw Errors.validation('كمية الجهاز ثابتة. أضف الجهاز الثاني كمنتج مستقل برقمه التسلسلي.');
  }

  const quantityOnHand = await deps.products.adjustQuantity(productId, delta);

  await deps.audit.record({
    actorId: actor.id,
    action: delta > 0 ? 'product.restock' : 'product.deduct',
    entity: 'Product',
    entityId: productId,
    metadata: { delta, quantityOnHand, name: existing.name },
  });

  return { quantityOnHand };
}

// ─────────── فاحصات المدخلات ───────────

function assertName(name: string): void {
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم المنتج من حرفين إلى 80 حرفًا.');
  }
}

function assertSerial(serial: string): void {
  if (serial.length < 2 || serial.length > 64) {
    throw Errors.validation('الرقم التسلسلي من حرفين إلى 64 حرفًا.');
  }
}

function trimOrNull(value: string | null | undefined, max: number, message: string): string | null {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return null;
  if (trimmed.length > max) throw Errors.validation(message);
  return trimmed;
}

/** بيحوّل أخطاء التاريخ لأخطاء تطبيق برسايل عربية جاهزة للعرض */
function readDate(raw: string | null | undefined): string | null {
  try {
    return parseDateInput(raw);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
}

function assertPrice(pricePiastres: number): void {
  if (!Number.isInteger(pricePiastres) || pricePiastres <= 0) {
    throw Errors.validation('يجب أن يكون سعر البيع أكبر من صفر.');
  }
}

function assertCost(costPiastres: number): void {
  // التكلفة بتقبل صفر: منتج هدية أو عيّنة تكلفته صفر فعلاً
  if (!Number.isInteger(costPiastres) || costPiastres < 0) {
    throw Errors.validation('التكلفة غير صالحة.');
  }
}

function assertQuantity(quantity: number): void {
  if (!Number.isInteger(quantity) || quantity < 0) {
    throw Errors.validation('يجب أن تكون الكمية رقمًا صحيحًا غير سالب.');
  }
  if (quantity > MAX_QUANTITY) {
    throw Errors.validation('الكمية أكبر من الحد المسموح.');
  }
}
