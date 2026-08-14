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

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  ListScope,
  ProductRecord,
  ProductRepository,
} from '../ports';

export interface ProductDeps {
  products: ProductRepository;
  branches: BranchRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateProductRequest {
  name: string;
  pricePiastres: number;
  costPiastres: number;
  quantityOnHand: number;
  /** مطلوب من المالك بس — مدير الفرع مقفول على فرعه */
  branchId?: string | null;
}

export interface UpdateProductRequest {
  name?: string;
  pricePiastres?: number;
  costPiastres?: number;
  isActive?: boolean;
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

export async function createProduct(
  deps: ProductDeps,
  actor: AuthenticatedUser,
  input: CreateProductRequest,
): Promise<{ id: string }> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }

  // نفس نمط إنشاء المستخدم بالظبط: الفرع بيتحدّد من هوية المنشئ،
  // مش من جسم الطلب. مدير الفرع مالوش أي طريقة يمرّر فرع تاني
  // حتى لو عدّل الطلب بإيده.
  let targetBranchId: string;

  if (actor.roleKey === 'SUPER_ADMIN') {
    if (!input.branchId) throw Errors.validation('اختار الفرع.');
    const exists = await deps.branches.exists(input.branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    targetBranchId = input.branchId;
  } else if (actor.roleKey === 'BRANCH_MANAGER') {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    targetBranchId = actor.branchId; // إجباري — أي قيمة في الطلب تُتجاهل
  } else {
    // الموظّف مالوش inventory.adjust في الأدوار الافتراضية، لكن
    // بنفحص صراحةً تحسّبًا لاستثناء فردي اتمنح بالغلط
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }

  const name = input.name.trim();
  assertName(name);
  assertPrice(input.pricePiastres);
  assertCost(input.costPiastres);
  assertQuantity(input.quantityOnHand);

  const created = await deps.products.create({
    branchId: targetBranchId,
    name,
    pricePiastres: input.pricePiastres,
    costPiastres: input.costPiastres,
    quantityOnHand: input.quantityOnHand,
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'product.create',
    entity: 'Product',
    entityId: created.id,
    metadata: {
      name,
      branchId: targetBranchId,
      pricePiastres: input.pricePiastres,
      quantityOnHand: input.quantityOnHand,
    },
  });

  return created;
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

  // بنقرا من غير تكلفة: إحنا محتاجين الفرع للحراسة بس، ومفيش
  // سبب نجيب حقل حسّاس مش هنستخدمه
  const existing = await deps.products.findById(productId, { includeCost: false });
  if (!existing) throw Errors.notFound('المنتج');
  assertBranchAccess(actor, existing.branchId);

  const patch: UpdateProductRequest = {};

  if (input.name !== undefined) {
    const name = input.name.trim();
    assertName(name);
    patch.name = name;
  }
  if (input.pricePiastres !== undefined) {
    assertPrice(input.pricePiastres);
    patch.pricePiastres = input.pricePiastres;
  }
  if (input.costPiastres !== undefined) {
    assertCost(input.costPiastres);
    patch.costPiastres = input.costPiastres;
  }
  if (input.isActive !== undefined) {
    patch.isActive = input.isActive;
  }

  if (Object.keys(patch).length === 0) {
    throw Errors.validation('مفيش حاجة اتغيّرت.');
  }

  await deps.products.update(productId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'product.update',
    entity: 'Product',
    entityId: productId,
    // ⚠ بنسجّل **إن** التكلفة اتغيّرت، مش قيمتها. سجل التدقيق
    // بيتقرا بصلاحية تانية خالص، فما ينفعش يبقى باب خلفي للتكلفة.
    metadata: {
      changed: Object.keys(patch),
      costChanged: patch.costPiastres !== undefined,
    },
  });
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
    throw Errors.validation('اكتب كمية صحيحة (موجبة للتوريد، سالبة للخصم).');
  }
  if (Math.abs(delta) > MAX_QUANTITY) {
    throw Errors.validation('الكمية أكبر من الحد المسموح.');
  }

  const existing = await deps.products.findById(productId, { includeCost: false });
  if (!existing) throw Errors.notFound('المنتج');
  assertBranchAccess(actor, existing.branchId);

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
    throw Errors.validation('اسم المنتج من حرفين لـ 80 حرف.');
  }
}

function assertPrice(pricePiastres: number): void {
  if (!Number.isInteger(pricePiastres) || pricePiastres <= 0) {
    throw Errors.validation('سعر البيع لازم يكون أكبر من صفر.');
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
    throw Errors.validation('الكمية لازم تكون رقم صحيح مش سالب.');
  }
  if (quantity > MAX_QUANTITY) {
    throw Errors.validation('الكمية أكبر من الحد المسموح.');
  }
}
