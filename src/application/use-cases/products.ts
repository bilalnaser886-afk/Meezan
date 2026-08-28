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
  /**
   * ══ مواصفات الجهاز — بتتسجّل مع الإنشاء ══
   *
   * ⚠ التلاتة دول كانوا في التعديل بس. المستلم كان بيسجّل الجهاز
   * الأول، وبعدين يفتحه تاني ويكمّل مواصفاته — خطوتين لفعل واحد.
   *
   * والخطوة التانية هي اللي بتتنسي. فبتلاقي أجهزة في المخزن
   * مالهاش مساحة ولا بطارية، والملصق بيطلع ناقص.
   *
   * ⚠ وللأجهزة بس. الإكسسوار مالوش بطارية ولا مساحة، والقيم
   * بتتصفّر تحت لو النوع إكسسوار — بدل ما نرفض الطلب. الرفض
   * كان هيكسر أي نموذج بيبعت الحقول فاضية وهو سليم.
   */
  customsCleared?: boolean;
  /** 0–100. null = ما اتقاسش — وهي **غير** الصفر. */
  batteryHealth?: number | null;
  /** "256GB" · "8/256" · "1TB" — نص عن قصد، شوف 23_device_specs.sql */
  storageCapacity?: string | null;
}

export interface UpdateProductRequest {
  name?: string;
  pricePiastres?: number | null;
  costPiastres?: number;
  isActive?: boolean;
  source?: string | null;
  serialNumber?: string | null;
  entryDate?: string | null;
  /** ⚠ محكوم بصلاحية منفصلة — شوف updateProduct */
  reorderPoint?: number | null;
  customsCleared?: boolean;
  /** 0–100. null = ما اتقاسش. */
  batteryHealth?: number | null;
  /** "256GB" · "8/256" · "1TB" */
  storageCapacity?: string | null;
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
/**
 * نطاق القراءة.
 *
 * ⚠ الترتيب هنا هو الحماية نفسها:
 *   مشغّل المنصّة  → مالوش أي وصول لبيانات المحلات. بيرمي.
 *   صاحب المحل     → كل فروع **محله**
 *   غيره           → فرعه في محله
 *
 * ومفيش فرع في الدالة دي بيرجّع نطاق من غير محل. لو حد ضاف واحد
 * بكرة، النوع نفسه هيرفضه.
 */
function scopeFor(actor: AuthenticatedUser): ListScope {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (actor.roleKey === 'SUPER_ADMIN') {
    return { tenantId: actor.tenantId };
  }
  // fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف كل المحل
  return { tenantId: actor.tenantId, branchId: actor.branchId ?? '__none__' };
}

/**
 * حراسة السجل الواحد.
 *
 * ⚠ حاجز المحل الأول، وبعدين الفرع. الترتيب مهم: لو فحصنا الفرع
 * بس، معرّف فرع من محل تاني كان ممكن يعدّي لو اتخمّن.
 *
 * والمستودع بيفلتر بالمحل برضه. الاتنين مع بعض مش زيادة —
 * ده الفرق بين قفل واحد وقفلين.
 */
function assertScopeAccess(
  actor: AuthenticatedUser,
  targetTenantId: string,
  targetBranchId: string,
): void {
  if (targetTenantId !== actor.tenantId) throw Errors.notFound('المنتج');
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

  // ─── مواصفات الجهاز ───
  //
  // ⚠ الإكسسوار بياخد صفر/فاضي مش رفض. النموذج بيبعت الحقول
  // موجودة دايمًا، وهي مخفية بس لما النوع إكسسوار — فالرفض كان
  // هيكسر طلب سليم تمامًا.
  const isDevice = productType === 'device';

  const customsCleared = isDevice ? Boolean(input.customsCleared) : false;
  const batteryHealth = isDevice ? readBatteryHealth(input.batteryHealth) : null;
  const storageCapacity = isDevice
    ? trimOrNull(input.storageCapacity, 32, 'المساحة أطول من 32 حرفًا.')
    : null;

  const created = await deps.products.create({
    tenantId: actor.tenantId,
    branchId: targetBranchId,
    name,
    productType,
    serialNumber,
    source,
    entryDate,
    pricePiastres: input.pricePiastres,
    costPiastres: input.costPiastres,
    quantityOnHand,
    customsCleared,
    batteryHealth,
    storageCapacity,
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
      customsCleared,
      batteryHealth,
      storageCapacity,
    },
  });

  return created;
}

/**
 * قراءة صحة البطارية.
 *
 * ⚠ الفاضي معناه **"ما اتقاسش"** مش صفر. والفرق مش لغوي:
 * جهاز جديد ما حدش قاس بطاريته، وجهاز بطاريته خربانة قيمته صفر.
 * لو خلطناهم، أول جهاز يتسجّل بلا قياس هيبان كأن بطاريته تالفة.
 *
 * نفس المنطق المكتوب في `23_device_specs.sql` بالحرف، والقيد
 * في قاعدة البيانات بيحرسه من الناحية التانية.
 */
function readBatteryHealth(raw: number | null | undefined): number | null {
  if (raw === null || raw === undefined || (raw as unknown) === '') return null;

  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0 || value > 100) {
    throw Errors.validation('صحة البطارية رقم صحيح من 0 إلى 100.');
  }
  return value;
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
    // ⚠ الفحص بياخد المحل معاه. من غيره، صاحب محل يقدر يضيف
    // منتج في فرع محل تاني لو عرف معرّفه.
    const exists = await deps.branches.exists(actor.tenantId, requested);
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
  assertScopeAccess(actor, existing.tenantId, existing.branchId);

  const patch: {
    name?: string;
    pricePiastres?: number | null;
    costPiastres?: number;
    isActive?: boolean;
    source?: string | null;
    serialNumber?: string | null;
    entryDate?: string;
    reorderPoint?: number;
    customsCleared?: boolean;
    batteryHealth?: number | null;
    storageCapacity?: string | null;
    updatedById: string;
  } = { updatedById: actor.id };

  let changedPrice = false;

  /**
   * ══ الحد الأدنى — صلاحية منفصلة عن تعديل الكمية ══
   *
   * المندوب ومدير الفرع عندهم `inventory.adjust`، يعني بيعدّلوا
   * الكميات كل يوم. لكن **تحديد الحد** قرار سياسة مش عملية
   * يومية — مين يقرر إن الجراب لازم يفضل منه ٥؟ صاحب المحل.
   *
   * ⚠ صلاحية مش فحص دور: لو حبيت بكرة تدّي مدير فرع واحد الحق
   * ده، استثناء فردي في `user_permissions` يكفي — من غير ما
   * تعمله صاحب محل ويشوف التكلفة والأرباح.
   */
  if (input.reorderPoint !== undefined && input.reorderPoint !== null) {
    if (!actor.permissions.includes(PERMISSIONS.INVENTORY_REORDER_POINT)) {
      throw Errors.forbidden(PERMISSIONS.INVENTORY_REORDER_POINT);
    }

    const point = Number(input.reorderPoint);
    if (!Number.isInteger(point) || point < 0) {
      throw Errors.validation('الحد الأدنى لازم يكون رقمًا صحيحًا غير سالب.');
    }
    if (point > MAX_QUANTITY) {
      throw Errors.validation('الحد الأدنى أكبر من المسموح.');
    }

    // ⚠ الأجهزة مستبعدة. الجهاز كميته 1 وبتبقى صفر بعد البيع —
    // ده بيع ناجح مش نقص. حدّ على جهاز معناه إنذار مع كل بيعة.
    if (existing.productType === 'device' && point > 0) {
      throw Errors.validation('الحد الأدنى للإكسسوارات فقط — الجهاز قطعة واحدة.');
    }

    patch.reorderPoint = point;
  }

  // ══ تفاصيل الجهاز ══
  //
  // الأعمدة دي بتتكتب على الملصق، فالزبون بيقرا منها. غلطة هنا
  // بتوصل لإيده مطبوعة — عشان كده الفحص أصرم من باقي الحقول.
  if (input.customsCleared !== undefined) {
    patch.customsCleared = Boolean(input.customsCleared);
  }

  if (input.batteryHealth !== undefined) {
    if (input.batteryHealth === null || input.batteryHealth === ('' as unknown)) {
      // ⚠ الفاضي معناه "ما اتقاسش" مش صفر. المسح مقصود ومسموح.
      patch.batteryHealth = null;
    } else {
      const battery = Number(input.batteryHealth);
      if (!Number.isInteger(battery) || battery < 0 || battery > 100) {
        throw Errors.validation('صحة البطارية رقم من 0 إلى 100، أو اتركها فارغة.');
      }
      patch.batteryHealth = battery;
    }
  }

  if (input.storageCapacity !== undefined) {
    const storage = String(input.storageCapacity ?? '').trim();
    if (!storage) {
      patch.storageCapacity = null;
    } else {
      if (storage.length > 32) throw Errors.validation('المساحة أطول من الحد المسموح.');
      patch.storageCapacity = storage;
    }
  }

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
  assertScopeAccess(actor, product.tenantId, product.branchId);

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
  assertScopeAccess(actor, existing.tenantId, existing.branchId);

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
