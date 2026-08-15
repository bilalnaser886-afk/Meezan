/**
 * العقود (Ports)
 *
 * الملف ده بيوصف **الوظيفة** المطلوبة، مش الأداة.
 * تشبيه: خطة المدرّب بتقول "قِس النبض"، مش "استخدم جهاز ماركة كذا".
 *
 * وده اللي خلّى نقلة المشروع من Node إلى كلاودفلير رخيصة:
 * العقد اتغيّر في سطرين بس (التوكنات بقت async لأن Web Crypto async)،
 * وكل المنطق فوقه فضل زي ما هو.
 */

import type { PermissionKey } from '../domain/permissions';

export type RoleKey = 'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF';

export interface AuthenticatedUser {
  id: string;
  username: string;
  fullName: string;
  roleKey: RoleKey;
  branchId: string | null;
  permissions: PermissionKey[];
  mustChangePassword: boolean;
}

/** محتوى بطاقة الدخول. خفيف عمداً — بتتحمل مع كل طلب. */
export interface AccessTokenPayload {
  sub: string; // معرّف المستخدم
  sid: string; // معرّف الجلسة
  role: RoleKey;
  branchId: string | null;
  perms: string[];
  ver: number;
}

export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(stored: string, plain: string): Promise<boolean>;
  needsRehash(stored: string): boolean;
}

export interface TokenService {
  signAccessToken(payload: AccessTokenPayload, ttlSeconds: number, secret: string): Promise<string>;
  verifyAccessToken(token: string, secret: string): Promise<AccessTokenPayload>;
  createRefreshToken(): Promise<{ raw: string; digest: string }>;
  digestRefreshToken(raw: string): Promise<string>;
}

export interface Clock {
  now(): Date;
}

export interface AuditLogger {
  record(entry: {
    actorId?: string | null;
    action: string;
    entity?: string;
    entityId?: string;
    metadata?: Record<string, unknown>;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<void>;
}

export interface RateLimiter {
  /** بترجع الثواني المتبقية لو محظور، أو null لو مسموح */
  check(key: string, limit: number, windowSeconds: number): Promise<number | null>;
  reset(key: string): Promise<void>;
}

export interface UserRecord {
  id: string;
  username: string;
  fullName: string;
  passwordHash: string;
  adminPasskeyHash: string | null;
  isActive: boolean;
  mustChangePassword: boolean;
  failedLoginCount: number;
  lockedUntil: Date | null;
  deletedAt: Date | null;
  branchId: string | null;
  roleKey: RoleKey;
  permissions: PermissionKey[];
}

export interface UserRepository {
  findByUsername(username: string): Promise<UserRecord | null>;
  findById(id: string): Promise<UserRecord | null>;
  registerFailedLogin(userId: string, lockUntil: Date | null): Promise<void>;
  clearLoginFailures(userId: string, loginAt: Date): Promise<void>;
  updatePasswordHash(userId: string, hash: string): Promise<void>;
  create(data: CreateUserInput): Promise<{ id: string }>;
  listInScope(scope: ListScope): Promise<TeamMember[]>;
  setActive(userId: string, isActive: boolean): Promise<void>;
}

/**
 * نطاق البحث — صريح عمداً.
 *
 * ليه مش `branchId: string | null`؟
 * لأن null معناها الغامض "كل الفروع"، ولو وصلت بالغلط من مدير فرع
 * (مثلاً حسابه من غير فرع)، كان هيشوف كل مستخدمي النظام.
 * ده اسمه fail-open: القفل يتعطّل فيفتح.
 *
 * النوع ده بيخلّي الغلطة دي **مستحيلة**: لازم تكتب `allBranches: true`
 * صراحةً عشان تشوف الكل. مفيش طريقة توصلها بالصدفة.
 */
export type ListScope = { allBranches: true } | { branchId: string };

/** بيانات إنشاء حساب جديد. الهاش يوصل هنا جاهز — المستودع لا يعرف شيئاً عن التشفير. */
export interface CreateUserInput {
  username: string;
  fullName: string;
  passwordHash: string;
  roleKey: RoleKey;
  branchId: string | null;
}

/** صف واحد في قائمة "الفريق" المعروضة للمدير أو المالك */
export interface TeamMember {
  id: string;
  username: string;
  fullName: string;
  roleKey: RoleKey;
  branchId: string | null;
  isActive: boolean;
  createdAt: Date;
}

export interface BranchSummary {
  id: string;
  code: string;
  name: string;
  isActive: boolean;
}

export interface CreateBranchInput {
  code: string;
  name: string;
  address: string | null;
  phone: string | null;
}

export interface BranchRepository {
  /** الفروع النشطة فقط — للقوائم المنسدلة */
  listActive(): Promise<BranchSummary[]>;
  /** كل الفروع غير المحذوفة، بما فيها المعطّلة — لشاشة الإدارة */
  listAll(): Promise<BranchSummary[]>;
  /** فحص وجود الفرع قبل ربط مستخدم جديد به — يمنع ربطه بمعرّف وهمي */
  exists(branchId: string): Promise<boolean>;
  findByCode(code: string): Promise<BranchSummary | null>;
  create(data: CreateBranchInput): Promise<{ id: string }>;
}

// ═══════════════════ الخزينة ═══════════════════

export type MovementDirection = 'IN' | 'OUT';

/**
 * كل أنواع الحركة الموجودة في قاعدة البيانات.
 *
 * ⚠ التحويلات (TRANSFER_*) موجودة في القاعدة لكن لسه مش مفعّلة
 * في التطبيق، فمش مدرجة هنا.
 */
export type MovementType =
  | 'DEPOSIT'
  | 'WITHDRAWAL'
  | 'EXPENSE'
  | 'ADVANCE'
  | 'ADJUSTMENT'
  | 'SALE';

/**
 * الأنواع اللي المستخدم يقدر يسجّلها **بإيده** من شاشة الخزينة.
 *
 * ══ ليه البيع مستثنى بنوع منفصل؟ ══
 * حركة البيع مش بتتكتب من شاشة الخزينة أبدًا — بتتولّد جوّه دالة
 * البيع الذرية مع الفاتورة وخصم المخزون في نفس اللحظة.
 *
 * لو سمحنا بتسجيلها يدويًا، هيبقى ممكن تدخل فلوس على إنها "بيع"
 * من غير فاتورة ولا خصم مخزون — يعني إيراد من غير بضاعة خرجت.
 *
 * `Exclude` هنا بتخلّي ده **خطأ في وقت البناء** مش خطأ وقت التشغيل.
 * تشبيه: مش لافتة مكتوب عليها "ممنوع الدخول"، ده حيط.
 */
export type ManualMovementType = Exclude<MovementType, 'SALE'>;

export type MovementStatus = 'PENDING' | 'APPROVED' | 'REJECTED';

export interface TreasuryBalance {
  treasuryId: string;
  name: string;
  type: string;
  branchId: string | null;
  isActive: boolean;
  /** بالقرش دايمًا */
  balancePiastres: number;
  movementCount: number;
}

export interface ExpenseReason {
  id: string;
  name: string;
  isAdvance: boolean;
  branchId: string | null;
}

export interface MovementRecord {
  id: string;
  treasuryId: string;
  branchId: string | null;
  direction: MovementDirection;
  type: MovementType;
  amountPiastres: number;
  status: MovementStatus;
  expenseReasonId: string | null;
  relatedUserId: string | null;
  note: string | null;
  occurredAt: Date;
  createdById: string;
}

/** سجل حركة بعد إضافة الأسماء — المستودع بيرجّع معرّفات، وحالة
 *  الاستخدام بتحوّلها لأسماء من قوائم عندها أصلاً. ده بيتجنّب
 *  ربط أربع علاقات في استعلام واحد (المستخدمون مربوطين 4 مرات
 *  بجدول الحركات) — أبسط وأقل عرضة للكسر. */
export interface EnrichedMovement extends MovementRecord {
  treasuryName: string;
  reasonName: string | null;
  relatedUserName: string | null;
  createdByName: string | null;
}

export interface CreateMovementInput {
  treasuryId: string;
  branchId: string | null;
  direction: MovementDirection;
  /** المستودع بيقدر يكتب أي نوع — الحراسة فوق في حالة الاستخدام */
  type: MovementType;
  amountPiastres: number;
  status: MovementStatus;
  expenseReasonId: string | null;
  relatedUserId: string | null;
  note: string | null;
  occurredAt: Date;
  createdById: string;
  approvedById: string | null;
  approvedAt: Date | null;
}

export interface MovementFilter {
  /** null = كل الفروع (للمالك فقط) */
  branchId: string | null;
  status?: MovementStatus;
  limit: number;
}

export interface SalaryStatement {
  baseSalaryPiastres: number;
  totalAdvancesPiastres: number;
  netDuePiastres: number;
  carriedDebtPiastres: number;
  advanceCount: number;
}

export interface TreasuryRepository {
  listBalances(branchId: string | null): Promise<TreasuryBalance[]>;
  /** بيرجّع الفرع التابع له، أو null لو الخزينة مش موجودة */
  findScope(treasuryId: string): Promise<{ branchId: string | null } | null>;
}

export interface MovementRepository {
  create(data: CreateMovementInput): Promise<{ id: string }>;
  list(filter: MovementFilter): Promise<MovementRecord[]>;
  findById(id: string): Promise<MovementRecord | null>;
  review(
    id: string,
    status: 'APPROVED' | 'REJECTED',
    reviewerId: string,
    at: Date,
  ): Promise<void>;
  salaryStatement(userId: string, from: Date, to: Date): Promise<SalaryStatement>;
}

export interface ExpenseReasonRepository {
  /** أسباب الفرع + الأسباب العامة (branch_id = null) */
  listForBranch(branchId: string | null): Promise<ExpenseReason[]>;
  findById(id: string): Promise<ExpenseReason | null>;
}

// ═══════════════════ المنتجات ═══════════════════

/**
 * ⚠ لاحظ إن `costPiastres` **اختياري** في النوع ده، وده مقصود
 * ومركزي في التصميم.
 *
 * التكلفة مش بتتخفي في الواجهة — بتتشال من الكائن نفسه في طبقة
 * قاعدة البيانات قبل ما يرجع. اللي مالوش `profit.view_real`
 * بيوصله كائن **مفيهوش الحقل أصلاً**، مش كائن فيه الحقل مخفي.
 *
 * تشبيه: الفرق بين إنك تدّي حد ملف وتقوله "متبصّش على الصفحة
 * التالتة"، وبين إنك تشيل الصفحة التالتة قبل ما تديله الملف.
 * الأولى شرف، والتانية أمان.
 *
 * علامة `?` هنا هي اللي بتخلّي تايب سكريبت يفكّرك إن الحقل ممكن
 * ما يكونش موجود، فما تكتبش كود بيفترض وجوده.
 */
/**
 * نوع المنتج — قسمة بتغيّر قواعد اللعب مش مجرد تصنيف.
 *
 *   device    جهاز. قطعة فعلية واحدة بسريال. كل وحدة صف منفصل،
 *             حتى لو نفس الموديل بالظبط.
 *   accessory إكسسوار. صنف بكمية، زي ما كان.
 *
 * تشبيه المخزن: علب الشاي كلها "علبة شاي" فبتعدّها. الموبايلات
 * كل واحد ليه رقم على ضهره فبتسجّله بالرقم.
 */
export type ProductType = 'device' | 'accessory';

export interface ProductRecord {
  id: string;
  branchId: string;
  name: string;
  productType: ProductType;
  /** للأجهزة فقط. الإكسسوار بيفضل null. */
  serialNumber: string | null;
  /** اسم التاجر أو المحل اللي اتشترى منه. نص حر. */
  source: string | null;
  /** YYYY-MM-DD — نص مش Date، عشان ما يتزحلقش يوم بالتوقيت */
  entryDate: string;
  /**
   * ⚠ بقى اختياري. منتج ممكن يدخل المخزن قبل ما يتسعّر.
   * والبيع بيطلب السعر يدويًا وقت الفاتورة لو الحقل ده فاضي.
   */
  pricePiastres: number | null;
  costPiastres?: number;
  quantityOnHand: number;
  isActive: boolean;
}

export interface CreateProductInput {
  branchId: string;
  name: string;
  productType: ProductType;
  serialNumber: string | null;
  source: string | null;
  /** null = سيب الافتراضي (تاريخ النهاردة بتوقيت القاهرة) */
  entryDate: string | null;
  pricePiastres: number | null;
  costPiastres: number;
  quantityOnHand: number;
  createdById: string;
}

export interface UpdateProductInput {
  name?: string;
  pricePiastres?: number | null;
  costPiastres?: number;
  isActive?: boolean;
  source?: string | null;
  serialNumber?: string | null;
  entryDate?: string;
  /**
   * ⚠ إلزامي في كل تعديل.
   * سجل الأسعار في قاعدة البيانات بيقرا منه مين غيّر السعر —
   * والمشغّل ما بيعرفش المستخدم من نفسه.
   */
  updatedById: string;
}

/**
 * سطر في سجل الأسعار.
 *
 * القيمتين بيقبلوا null: منتج كان بلا سعر واتسعّر أول مرة
 * (القديم null)، أو سعره اتشال (الجديد null).
 */
export interface PriceChangeRecord {
  oldPricePiastres: number | null;
  newPricePiastres: number | null;
  changedById: string | null;
  changedAt: Date;
}

/** نفس نمط EnrichedMovement — المستودع بيرجّع معرّف، والاسم بيتركّب فوق */
export interface PriceChange extends PriceChangeRecord {
  changedByName: string | null;
}

export interface ProductListOptions {
  /** بيتحدّد من صلاحية `profit.view_real` بس. مفيش مصدر تاني. */
  includeCost: boolean;
  /** المنتجات المفعّلة بس — لشاشة الكاشير */
  activeOnly?: boolean;
}

export interface ProductRepository {
  list(scope: ListScope, options: ProductListOptions): Promise<ProductRecord[]>;
  findById(id: string, options: { includeCost: boolean }): Promise<ProductRecord | null>;
  create(data: CreateProductInput): Promise<{ id: string }>;
  update(id: string, data: UpdateProductInput): Promise<void>;
  /**
   * تعديل الكمية بفرق (زيادة أو نقص) وبترجع الكمية الجديدة.
   *
   * ⚠ التنفيذ لازم يكون آمن ضد التزامن: لو الموظّف باع في نفس
   * اللحظة اللي المدير بيورّد فيها، البيع ما يضيعش.
   */
  adjustQuantity(id: string, delta: number): Promise<number>;
  /** آخر تغييرات السعر، الأحدث الأول */
  listPriceHistory(productId: string, limit: number): Promise<PriceChangeRecord[]>;
}

// ═══════════════════ المبيعات ═══════════════════

export interface SaleLineInput {
  productId: string;
  quantity: number;
  /**
   * السعر اليدوي — للمنتجات اللي مالهاش سعر مسجّل بس.
   *
   * ⚠ لو المنتج له سعر، دالة قاعدة البيانات بتتجاهل القيمة دي
   * تمامًا وبتستخدم سعر المنتج. من غير القاعدة دي، أي حد يقدر
   * يبيع بأي سعر بتعديل بسيط في الطلب.
   */
  unitPricePiastres?: number | null;
}

export interface CreateSaleInput {
  staffId: string;
  treasuryId: string;
  items: SaleLineInput[];
  customerName: string | null;
  customerPhone: string | null;
  /** null = تاريخ النهاردة بتوقيت القاهرة */
  exitDate: string | null;
}

export interface CreateSaleResult {
  saleId: string;
  totalPiastres: number;
  movementId: string;
  itemCount: number;
}

export interface SaleSummary {
  id: string;
  branchId: string;
  staffId: string;
  customerName: string | null;
  customerPhone: string | null;
  totalPiastres: number;
  treasuryId: string;
  createdAt: Date;
  /**
   * YYYY-MM-DD — إمتى البضاعة سابت المحل فعلاً.
   *
   * ⚠ منفصل تمامًا عن createdAt. ده تاريخ تجاري قابل للتعديل،
   * وده ختم تقني ما بيتغيّرش. تعديل الأول ما بيلمسش التاني.
   */
  exitDate: string;
}

/** صف الفاتورة بعد إضافة اسم الموظّف — نفس نمط EnrichedMovement */
export interface EnrichedSale extends SaleSummary {
  staffName: string | null;
  treasuryName: string | null;
}

export interface SaleItemLine {
  productId: string;
  productName: string;
  quantity: number;
  unitPricePiastres: number;
  /** محجوب عن غير `profit.view_real` — نفس قاعدة المنتجات */
  unitCostPiastres?: number;
  lineTotalPiastres: number;
}

export interface SaleDetail extends SaleSummary {
  items: SaleItemLine[];
}

export interface SaleFilter {
  scope: ListScope;
  /** لو موجود، بيحصر النتيجة في فواتير موظّف واحد (`sales.view_own`) */
  staffId?: string;
  limit: number;
}

export interface SaleRepository {
  /**
   * إنشاء بيع كامل في عملية واحدة لا تتجزّأ.
   *
   * التنفيذ بينادي دالة في قاعدة البيانات بتعمل الأربع خطوات
   * (فحص الكمية، الخصم، الفاتورة، حركة الخزينة) مع بعض:
   * يا كلها تنجح يا مفيش حاجة فيها تحصل.
   */
  create(input: CreateSaleInput): Promise<CreateSaleResult>;
  list(filter: SaleFilter): Promise<SaleSummary[]>;
  findById(id: string, options: { includeCost: boolean }): Promise<SaleDetail | null>;
  /**
   * تعديل تاريخ الخروج وحده.
   *
   * ⚠ التنفيذ ممنوع يلمس `created_at` بأي شكل. الختم التقني هو
   * أساس سجل المراجعة — لو اتحرّك معاه، القدرة على اكتشاف
   * التسجيل المتأخر بتضيع.
   */
  updateExitDate(id: string, exitDate: string): Promise<void>;
}

// ═══════════════════ العملاء ═══════════════════

export interface CustomerRecord {
  id: string;
  branchId: string;
  name: string;
  phone: string | null;
  notes: string | null;
  createdAt: Date;
  /**
   * عدد **الأجهزة** اللي اشتراها — مش عدد القطع.
   *
   * اللي أخد تلات أجهزة عميل مختلف عن اللي أخد تلاتين جراب.
   * عدد القطع بيساوي بينهم، والأجهزة هي اللي بتفرق.
   */
  deviceCount: number;
  purchaseCount: number;
  totalPiastres: number;
}

export interface CreateCustomerInput {
  branchId: string;
  name: string;
  phone: string | null;
  notes: string | null;
  createdById: string;
}

export interface UpdateCustomerInput {
  name?: string;
  phone?: string | null;
  notes?: string | null;
}

export interface CustomerRepository {
  /**
   * القائمة مرتّبة بعدد الأجهزة تنازليًا.
   * `search` بيدوّر في الاسم والرقم مع بعض.
   */
  list(scope: ListScope, search: string | null, limit: number): Promise<CustomerRecord[]>;
  findById(id: string): Promise<CustomerRecord | null>;
  create(data: CreateCustomerInput): Promise<{ id: string }>;
  update(id: string, data: UpdateCustomerInput): Promise<void>;
  /** حذف ناعم — السجل بيفضل في القاعدة ومش بيظهر في القوائم */
  softDelete(id: string, actorId: string, at: Date): Promise<void>;
}

export interface SessionRecord {
  id: string;
  userId: string;
  lastSeenAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  /** لو مش null، الشاشة مقفولة والجلسة لسه حيّة */
  lockedAt: Date | null;
}

export interface SessionRepository {
  create(data: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<SessionRecord>;
  findActiveByDigest(digest: string): Promise<SessionRecord | null>;
  findActiveById(id: string): Promise<SessionRecord | null>;
  touch(id: string, at: Date): Promise<void>;
  rotate(id: string, newDigest: string, at: Date): Promise<void>;
  revoke(id: string, reason: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, reason: string, at: Date): Promise<void>;
  /** قفل الشاشة — الجلسة تفضل حيّة */
  lock(id: string, at: Date): Promise<void>;
  /** فك القفل + تصفير عدّاد الخمول في نفس العملية */
  unlock(id: string, at: Date): Promise<void>;
}

export interface AnnouncementRecord {
  id: string;
  title: string;
  body: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  isMandatory: boolean;
  createdAt: Date;
}

export interface AnnouncementRepository {
  findPendingFor(user: AuthenticatedUser, now: Date): Promise<AnnouncementRecord[]>;
  acknowledge(announcementId: string, userId: string, at: Date): Promise<void>;
  create(data: {
    title: string;
    body: string;
    severity: 'INFO' | 'WARNING' | 'CRITICAL';
    audience: 'ALL' | 'MANAGERS_ONLY' | 'STAFF_ONLY' | 'SINGLE_BRANCH';
    branchId: string | null;
    isMandatory: boolean;
    startsAt: Date;
    endsAt: Date | null;
    createdById: string;
  }): Promise<{ id: string }>;
}
