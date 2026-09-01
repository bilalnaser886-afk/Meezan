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

/**
 * ⚠ لاحظ إن "المالك" اتقسم لاتنين.
 *
 *   PLATFORM_ADMIN  إنت. بتفتح محلات وتوقف اللي ما دفعش،
 *                   وما بتقراش أرباح حد.
 *   SUPER_ADMIN     صاحب المحل. "مالك" جوّه محله بس، وما يعرفش
 *                   إن فيه محلات تانية في النظام أصلاً.
 *
 * الكلمة كان معناها واحد لما كان المحل واحد.
 */
export type RoleKey = 'PLATFORM_ADMIN' | 'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF';

export interface AuthenticatedUser {
  id: string;
  username: string;
  fullName: string;
  roleKey: RoleKey;
  /** ⚠ null معناها "كل فروع **محله هو**" — مش كل فروع النظام */
  branchId: string | null;
  /** المحل اللي المستخدم تابع له. مفيش مستخدم بلا محل. */
  tenantId: string;
  tenantCode: string;
  tenantName: string;
  permissions: PermissionKey[];
  mustChangePassword: boolean;
}

/**
 * محتوى بطاقة الدخول. خفيف عمداً — بتتحمل مع كل طلب.
 *
 * ⚠ **المحل مش هنا عن قصد.**
 *
 * الحارس بيقرا `sid` و `sub` بس، وبيجيب المستخدم وصلاحياته ومحله
 * من قاعدة البيانات في كل طلب. باقي الحقول هنا معلوماتية.
 *
 * ولو حطّينا المحل في البطاقة، هيبقى عندنا نسخة تانية من الحقيقة
 * بتعيش خمس دقايق: محل يتوقف اشتراكه، وموظّفه يفضل شغّال لحد ما
 * بطاقته تنتهي. القراءة من القاعدة كل طلب بتخلّي الإيقاف فوري.
 */
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
  tenantId: string;
  tenantCode: string;
  tenantName: string;
  /** اشتراك المحل مفعّل؟ لو لأ، الدخول بيترفض برسالة مختلفة */
  tenantActive: boolean;
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
  /**
   * ⚠ الاسم لوحده مش كافي يميّز حد بعد نظام المحلات.
   * نفس اسم المستخدم في محلّين = شخصين مختلفين تمامًا.
   */
  findByTenantAndUsername(tenantCode: string, username: string): Promise<UserRecord | null>;
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
 * ══ ليه مش `branchId: string | null`؟ ══
 * لأن null معناها الغامض "كل الفروع"، ولو وصلت بالغلط من مدير فرع
 * كان هيشوف كل مستخدمي النظام. ده اسمه fail-open: القفل يتعطّل
 * فيفتح.
 *
 * ══ ⚠ التغيير الأخطر في المشروع كله ══
 * النوع ده كان `{ allBranches: true } | { branchId }`.
 * و `allBranches` كانت معناها في الكود: **ما تحطّش أي فلتر**.
 *
 * ده كان صح لما كل الفروع لمحل واحد. مع محلات كتير في نفس قاعدة
 * البيانات، الجملة دي معناها إن كل صاحب محل بيشوف مبيعات وتكاليف
 * وأرباح كل المحلات التانية.
 *
 * دلوقتي **مفيش حالة بلا محل** غير حالة واحدة صريحة اسمها
 * `allTenants` لمشغّل المنصّة. أي استعلام ناسي المحل مش هيتبني
 * أصلاً — المترجم بيقف عنده.
 *
 * تشبيه: قفل الباب مش لافتة عليه. اللافتة بتتقرا أو ما تتقراش،
 * القفل بيشتغل في الحالتين.
 */
export type ListScope =
  | { allTenants: true }
  | { tenantId: string }
  | { tenantId: string; branchId: string };

/** بيانات إنشاء حساب جديد. الهاش يوصل هنا جاهز — المستودع لا يعرف شيئاً عن التشفير. */
export interface CreateUserInput {
  tenantId: string;
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
  tenantId: string;
  code: string;
  name: string;
  isActive: boolean;
}

export interface CreateBranchInput {
  tenantId: string;
  code: string;
  name: string;
  address: string | null;
  phone: string | null;
}

export interface BranchRepository {
  /** الفروع النشطة فقط — للقوائم المنسدلة */
  listActive(tenantId: string): Promise<BranchSummary[]>;
  /** كل الفروع غير المحذوفة، بما فيها المعطّلة — لشاشة الإدارة */
  listAll(tenantId: string): Promise<BranchSummary[]>;
  /**
   * ⚠ المحل جزء من الفحص مش سياق حواليه.
   * من غيره، صاحب محل يقدر يربط موظّف بفرع محل تاني لو خمّن معرّفه.
   */
  exists(tenantId: string, branchId: string): Promise<boolean>;
  findByCode(tenantId: string, code: string): Promise<BranchSummary | null>;
  create(data: CreateBranchInput): Promise<{ id: string }>;
  /** عدد الفروع الحالية — لفحص حد الاشتراك */
  countActive(tenantId: string): Promise<number>;
}

// ═══════════════════ المحلات ═══════════════════

export interface TenantRecord {
  id: string;
  code: string;
  name: string;
  isActive: boolean;
  maxBranches: number;
  notes: string | null;
  createdAt: Date;
}

/** صف في شاشة إدارة المحلات — حجم استخدام، مش أرقام مالية */
export interface TenantOverview extends TenantRecord {
  branchCount: number;
  userCount: number;
  ownerName: string | null;
}

export interface TenantBranchInput {
  code: string;
  name: string;
}

export interface TenantUserInput {
  username: string;
  fullName: string;
  /** الهاش بيوصل جاهز — المستودع ما بيعرفش حاجة عن كلمات المرور */
  passwordHash: string;
  role: 'BRANCH_MANAGER' | 'STAFF';
  /** كود الفرع جوّه نفس المحل — بيتحوّل لمعرّف في قاعدة البيانات */
  branchCode: string;
}

export interface CreateTenantInput {
  code: string;
  name: string;
  maxBranches: number;
  ownerUsername: string;
  ownerFullName: string;
  ownerPasswordHash: string;
  /** فرع واحد على الأقل. كل فرع بياخد خزنة كاش تلقائيًا. */
  branches: TenantBranchInput[];
  /** ممكن تبقى فاضية — صاحب المحل يقدر يضيف بعدين */
  users: TenantUserInput[];
}

/**
 * جرد المحل قبل المحو.
 *
 * ⚠ ده الاستثناء الوحيد اللي بيوصل فيه رقم مالي لمشغّل المنصّة،
 * وبيوصل في لحظة واحدة بس: شاشة تأكيد الحذف.
 *
 * السبب إنه **مش تقرير**، ده عدّاد خطورة. الفرق بين محل تجربة
 * ومحل زبون حقيقي بيبان في رقم واحد — وبدونه المحو بيبقى دوسة
 * في الضلمة.
 */
export interface TenantCensus {
  code: string;
  name: string;
  isActive: boolean;
  branchCount: number;
  userCount: number;
  productCount: number;
  customerCount: number;
  saleCount: number;
  salesTotalPiastres: number;
  movementCount: number;
  auditCount: number;
  /** لو true، المحو مرفوض: الحساب ده جوّاه ومسحه بيقفلك بره */
  hasPlatformAdmin: boolean;
}

export interface TenantRepository {
  findById(id: string): Promise<TenantRecord | null>;
  findByCode(code: string): Promise<TenantRecord | null>;
  /**
   * ⚠ بترجّع حجم الاستخدام بس: عدد الفروع والمستخدمين.
   * مفيش مبيعات ولا أرباح ولا أرصدة. مشغّل المنصّة بيحاسب على
   * الاشتراك، مش بيتفرّج على الشغل.
   */
  listOverview(): Promise<TenantOverview[]>;
  /**
   * بتنشئ المحل وفروعه وحساباته وأسباب الصرف وخزنه — كله معًا.
   * يا الكل يتعمل يا مفيش حاجة تتعمل.
   */
  create(data: CreateTenantInput): Promise<{
    tenantId: string;
    ownerId: string;
    branchCount: number;
    userCount: number;
  }>;
  setActive(id: string, isActive: boolean): Promise<void>;
  setMaxBranches(id: string, maxBranches: number): Promise<void>;
  platformAdminExists(): Promise<boolean>;
  createPlatformAdmin(data: {
    tenantId: string;
    username: string;
    fullName: string;
    passwordHash: string;
    passkeyHash: string;
  }): Promise<{ id: string }>;
  /** جرد قبل المحو — قراءة بس، ما بتغيّرش ولا صف */
  census(id: string): Promise<TenantCensus | null>;
  /**
   * المحو النهائي. **مفيش تراجع.**
   *
   * الأقفال الأربعة كلها متطبّقة جوّه دالة قاعدة البيانات كمان،
   * مش هنا بس — عشان أي نداء من أي مكان يفضل محروس.
   */
  purge(id: string, actorId: string): Promise<{
    code: string;
    name: string;
    deletedUsers: number;
    deletedSales: number;
  }>;

  // ─────────── الإعلانات ───────────
  //
  // ⚠ البثّ بقى لمشغّل المنصّة وحده، ومن غير أي صلاحية جديدة.
  // القدرة جاية من فحص الدور جوّه دوال القاعدة — لأن الفحص
  // الأمني الدوري بيفشل لو مشغّل المنصّة اتدّى أي صلاحية غير
  // `tenant.view` و`tenant.manage`.

  /**
   * أسماء فروع محل — لشاشة التوجيه.
   *
   * ⚠ الأسماء بس. ولا رقم مالي ولا مبيعات ولا مستخدمين.
   * كل عمود زيادة هنا بيوسّع اللي المنصّة بتشوفه عن عملائها،
   * وده الحد الأدنى اللي التوجيه لفرع محتاجه.
   */
  branchesOf(actorId: string, tenantId: string): Promise<TenantBranchOption[]>;

  /**
   * البثّ.
   *
   * ⚠ `tenantId: null` معناها **كل المحلات المفعّلة**، والدالة
   * بتكتب **صف لكل محل** مش صف واحد للكل.
   *
   * الصف الواحد كان هيكسر تلات حاجات: قاعدة "المحل على كل صف"،
   * ومحو المحل ما يعرفش يشيل نصيبه، والإقرار بالقراءة يبقى
   * مشترك بين محلات ما تعرفش بعض.
   */
  broadcast(input: PlatformBroadcastInput): Promise<{ sentCount: number }>;
  announcements(actorId: string, limit: number): Promise<PlatformAnnouncementRow[]>;
  withdrawAnnouncement(actorId: string, announcementId: string): Promise<void>;
}

// ─────────── إعلانات المنصّة ───────────

export interface TenantBranchOption {
  branchId: string;
  branchName: string;
  branchCode: string;
}

/**
 * جمهور الإعلان.
 *
 * ⚠ نص مش enum في القاعدة — عشان أي قيمة جديدة تبقى سطر واحد
 * بدل تشغيلتين منفصلتين. نفس اللي اتعمل في `product_type`
 * و`treasuries.type`.
 */
export type AnnouncementAudience =
  | 'ALL'
  | 'OWNERS_ONLY'
  | 'MANAGERS_ONLY'
  | 'STAFF_ONLY'
  | 'SINGLE_BRANCH';

export interface PlatformBroadcastInput {
  actorId: string;
  /** null = كل المحلات المفعّلة */
  tenantId: string | null;
  audience: AnnouncementAudience;
  /** إلزامي مع SINGLE_BRANCH بس */
  branchId: string | null;
  title: string;
  body: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  isMandatory: boolean;
  endsAt: Date | null;
}

export interface PlatformAnnouncementRow {
  id: string;
  tenantId: string;
  tenantName: string;
  title: string;
  body: string;
  severity: string;
  audience: string;
  branchName: string | null;
  isMandatory: boolean;
  startsAt: Date;
  endsAt: Date | null;
  createdAt: Date;
  /** كام واحد ضغط "قرأت وفهمت" */
  readCount: number;
  /**
   * كام المفروض يشوفوه.
   *
   * ⚠ إعلان إلزامي من غير الرقم ده = بثّ في الفراغ. "٣ قروه"
   * مالهاش معنى من غير ما تعرف ٣ من كام.
   */
  targetCount: number;
}

// ═══════════════════ الخزنة ═══════════════════

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
  | 'SALE'
  | 'REFUND';

/**
 * الأنواع اللي المستخدم يقدر يسجّلها **بإيده** من شاشة الخزنة.
 *
 * ══ ليه البيع مستثنى بنوع منفصل؟ ══
 * حركة البيع مش بتتكتب من شاشة الخزنة أبدًا — بتتولّد جوّه دالة
 * البيع الذرية مع الفاتورة وخصم المخزون في نفس اللحظة.
 *
 * لو سمحنا بتسجيلها يدويًا، هيبقى ممكن تدخل فلوس على إنها "بيع"
 * من غير فاتورة ولا خصم مخزون — يعني إيراد من غير بضاعة خرجت.
 *
 * `Exclude` هنا بتخلّي ده **خطأ في وقت البناء** مش خطأ وقت التشغيل.
 * تشبيه: مش لافتة مكتوب عليها "ممنوع الدخول"، ده حيط.
 */
export type ManualMovementType = Exclude<MovementType, 'SALE' | 'REFUND'>;

export type MovementStatus = 'PENDING' | 'APPROVED' | 'REJECTED';

/** أنواع الخزن — نص + CHECK في القاعدة، مش enum */
export type TreasuryType = 'CASH' | 'WALLET' | 'VISA' | 'INSTAPAY';

export interface TreasuryBalance {
  treasuryId: string;
  name: string;
  type: string;
  branchId: string | null;
  isActive: boolean;
  /** بالقرش دايمًا */
  balancePiastres: number;
  movementCount: number;
  /**
   * الجهة — البنك للفيزا، وشركة الاتصالات للمحفظة.
   *
   * ⚠ عمود واحد للاتنين عن قصد: دول نفس السؤال — "الفلوس دي
   * عند مين؟". عمودين معناهم إن كل تجميع لازم يفحص النوع الأول
   * عشان يعرف يقرا من أنهي عمود، وأول واحد ينسى يطلّع تجميع
   * ناقص وساكت.
   *
   * `null` للنقدي — الدرج مش بنك.
   */
  provider: string | null;
}

/** صف في الملخّص المالي — رصيد خزنة واحدة باسم فرعها */
export interface TreasurySummaryRow extends TreasuryBalance {
  branchName: string | null;
  lastMovementAt: Date | null;
}

export interface CreateTreasuryInput {
  actorId: string;
  branchId: string;
  name: string;
  type: TreasuryType;
  provider: string | null;
}

export interface UpdateTreasuryInput {
  treasuryId: string;
  actorId: string;
  name?: string | null;
  provider?: string | null;
  isActive?: boolean | null;
}

// ─────────── التحويل بين الخزن ───────────

export interface TransferTreasuryInput {
  actorId: string;
  fromTreasuryId: string;
  toTreasuryId: string;
  /** اللي طلع من المصدر */
  sentPiastres: number;
  /** اللي وصل للوجهة */
  receivedPiastres: number;
  note: string | null;
  date: string | null;
}

export interface TransferTreasuryResult {
  transferId: string;
  sentPiastres: number;
  receivedPiastres: number;
  /**
   * ⚠ محسوبة مش مكتوبة — الفرق بين اللي طلع واللي وصل.
   * وفيه قيد في القاعدة بيفرض إنها تساويه، فمستحيل تختلف.
   */
  feePiastres: number;
  outMovementId: string;
  inMovementId: string;
  fromBalance: number;
  toBalance: number;
}

export interface TransferRow {
  id: string;
  fromName: string;
  toName: string;
  sentPiastres: number;
  receivedPiastres: number;
  feePiastres: number;
  transferDate: string;
  note: string | null;
  createdByName: string | null;
  createdAt: Date;
}

export interface ExpenseReason {
  id: string;
  tenantId: string;
  name: string;
  isAdvance: boolean;
  /**
   * سبب "شراء بضاعة" — أصل بيتحوّل لأصل، مش مصروف.
   *
   * ⚠ قائمة الدخل بتستبعده، وشاشة الخزنة بتخفيه من قائمة أسباب
   * المصروف: الشرا له مساره الخاص اللي بيكتب بيان (صنف · كمية ·
   * مورّد) جنب الحركة.
   *
   * من غير العلم ده، هيبقى فيه **طريقتين** لتسجيل نفس الحاجة —
   * واحدة ببيان وواحدة من غير. والتانية بتلغي الميزة كلها.
   */
  isInventory: boolean;
  branchId: string | null;
}

export interface MovementRecord {
  id: string;
  tenantId: string;
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
  tenantId: string;
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
  tenantId: string;
  /** null = كل فروع المحل (لصاحب المحل فقط) */
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
  /** ⚠ المحل إلزامي. الفرع اختياري (null = كل فروع المحل). */
  listBalances(tenantId: string, branchId: string | null): Promise<TreasuryBalance[]>;
  /** بيرجّع المحل والفرع، أو null لو الخزنة مش موجودة */
  findScope(treasuryId: string): Promise<{ tenantId: string; branchId: string | null } | null>;

  /**
   * الملخّص المالي — صف لكل خزنة، باسم فرعها.
   *
   * ⚠ دالة واحدة، والتطبيق بيجمّع منها المجموع الكلي ومجموع كل
   * فرع ومجموع كل نوع. ليه مش تلات دوال؟ عشان **يستحيل المجموع
   * يخالف الأجزاء**.
   *
   * لو كل رقم له استعلامه، هييجي يوم واحد يتعدّل ويفضل الباقي
   * قديم — والشاشة تقول "الإجمالي ١٠٠٠" وتحته خزن مجموعهم ٩٠٠.
   */
  summary(tenantId: string, branchId: string | null): Promise<TreasurySummaryRow[]>;

  /** ⚠ صاحب المحل وحده — الحراسة جوّه دالة القاعدة */
  create(input: CreateTreasuryInput): Promise<{ treasuryId: string }>;
  update(input: UpdateTreasuryInput): Promise<{ treasuryId: string; balancePiastres: number }>;

  /**
   * تحويل بين خزنتين — عملية ذرية.
   *
   * ⚠ حركتين بمعرّف مجموعة مشترك (`transfer_group_id`)، عشان
   * الطرفين يتعاملوا كوحدة واحدة في الدفتر.
   */
  transfer(input: TransferTreasuryInput): Promise<TransferTreasuryResult>;
  listTransfers(
    tenantId: string,
    branchId: string | null,
    from: string | null,
    to: string | null,
    limit: number,
  ): Promise<TransferRow[]>;
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
  /** أسباب الفرع + أسباب المحل العامة (branch_id = null) */
  listForBranch(tenantId: string, branchId: string | null): Promise<ExpenseReason[]>;
  findById(id: string): Promise<ExpenseReason | null>;
  /**
   * سبب جديد — **على مستوى المحل** دايمًا (`branch_id` فاضي).
   *
   * ⚠ مفيش أسباب خاصة بفرع من الشاشة، وده مقصود. الفهرس الفريد
   * على (المحل · الفرع · الاسم)، فسبب فرعي اسمه "إيجار" جنب سبب
   * عام اسمه "إيجار" **مسموح** في القاعدة — والمدير هيلاقي
   * "إيجار" مرتين في قايمته ومش عارف الفرق.
   *
   * ⚠ و`is_advance` و`is_inventory` بيفضلوا false دايمًا:
   * الاتنين بيغيّروا معاملة الحركة في قائمة الدخل، ومش قرار
   * يتاخد من خانة نص في شاشة الخزنة.
   */
  create(input: { tenantId: string; name: string }): Promise<{ id: string }>;
}

// ═══════════════════ البضاعة ═══════════════════

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
  tenantId: string;
  branchId: string;
  name: string;
  productType: ProductType;
  /** للأجهزة فقط. الإكسسوار بيفضل null. */
  serialNumber: string | null;
  /**
   * ⚠ "مش متاح سريال" — قرار صريح مش خانة فاضية.
   * الإكسسوار بيفضل false دايمًا.
   */
  serialUnavailable: boolean;
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
  /**
   * الحد الأدنى للتنبيه. **صفر = معطّل** وهو الافتراضي.
   * للإكسسوارات فقط — الجهاز كميته 1 وبتبقى صفر بعد البيع،
   * وده بيع ناجح مش نقص مخزون.
   */
  reorderPoint: number;
  /** مرتجع مستنّي المراجعة — مش متاح للبيع */
  quarantinedQuantity: number;
  /**
   * درج المنتج. `null` = غير مصنّف.
   *
   * ⚠ الاسم مش هنا — الشاشة عندها شجرة الأدراج كاملة وبتوصّل
   * بالمعرّف. لو رجّعنا الاسم مع كل منتج، أول ما حد يسمّي درج
   * من جديد يبقى عندنا اسمين لنفس الدرج في نفس الشاشة.
   */
  categoryId: string | null;
  /**
   * موديل الجهاز. `null` = غير محدّد.
   *
   * ⚠ للنوعين مع بعض، ومعناه بيتغيّر:
   *   الجهاز    → موديله هو
   *   الإكسسوار → الجهاز اللي بيركب عليه
   *
   * ودمجهم في عمود واحد هو اللي بيخلّي "وريني كل حاجة ليها
   * علاقة بالـ١٢ برو ماكس" سؤال ممكن.
   */
  modelId: string | null;
  /** لون المنتج. `null` = غير محدّد. للنوعين. */
  colorId: string | null;
  /**
   * خلوّ الجمارك — تسجيل يدوي من المستلم.
   * ⚠ false معناها **"مش متأكد"** مش "مش مخلّص". غياب المعلومة
   * مش نفي.
   */
  customsCleared: boolean;
  /**
   * صحة البطارية من 0 لـ 100.
   * ⚠ null معناها **"ما اتقاسش"** مش صفر. جهاز جديد ما حدش قاس
   * بطاريته، وجهاز بطاريته خربانة قيمته 0 — والاتنين مختلفين.
   */
  batteryHealth: number | null;
  /** المساحة كنص: "256GB" · "8/256" · "1TB". نص عشان يستوعب الكل. */
  storageCapacity: string | null;
  isActive: boolean;
}

export interface CreateProductInput {
  tenantId: string;
  branchId: string;
  name: string;
  productType: ProductType;
  serialNumber: string | null;
  serialUnavailable: boolean;
  source: string | null;
  /** مورّد مسجّل. null = مصدر غير محدّد أو نص قديم في `source` */
  supplierId: string | null;
  /**
   * تسوية التكلفة وقت الإضافة.
   *
   * ⚠ 'PAID' بتطلّع فلوس من الخزنة فعلاً، و'CREDIT' بتزوّد
   * دين المورّد. الاتنين بيتكتبوا مع المنتج في **معاملة واحدة**
   * جوّه قاعدة البيانات — لو اتفصلوا، بيبقى عندك جهاز بلا دين
   * أو دين بلا جهاز، والاتنين بيبانوا كأنهم نجاح.
   */
  settle?: 'NONE' | 'PAID' | 'CREDIT';
  /** مطلوبة مع 'PAID' بس */
  treasuryId?: string | null;
  /** null = سيب الافتراضي (تاريخ النهاردة بتوقيت القاهرة) */
  entryDate: string | null;
  pricePiastres: number | null;
  costPiastres: number;
  quantityOnHand: number;
  /**
   * ⚠ التلاتة دول **للأجهزة بس**، وإلزاميين في العقد ده عن قصد.
   *
   * لو خلّيناهم اختياريين، أي مستودع جديد يقدر يسيبهم من غير ما
   * حاجة تزعّق — والجهاز بيتسجّل ناقص مواصفاته وما حدش بيلاحظ.
   * حالة الاستخدام بتصفّرهم للإكسسوار قبل ما يوصلوا هنا.
   */
  customsCleared: boolean;
  batteryHealth: number | null;
  storageCapacity: string | null;
  /**
   * درج المنتج. `null` = غير مصنّف.
   *
   * ⚠ فاضي مسموح عن قصد: البضاعة اللي كانت موجودة قبل الأدراج
   * مالهاش درج، وتخمين مكانها أوحش من تركه فاضي — الفاضي بيبان
   * في الشاشة وبتتصرّف، والتخمين الغلط بيتصدّق.
   */
  categoryId: string | null;
  modelId: string | null;
  colorId: string | null;
  createdById: string;
}

export interface UpdateProductInput {
  name?: string;
  pricePiastres?: number | null;
  costPiastres?: number;
  isActive?: boolean;
  source?: string | null;
  serialNumber?: string | null;
  serialUnavailable?: boolean;
  entryDate?: string;
  /** محكوم بصلاحية `inventory.reorder_point` — صاحب المحل وحده */
  reorderPoint?: number;
  customsCleared?: boolean;
  batteryHealth?: number | null;
  storageCapacity?: string | null;
  /** `null` = شيل الدرج (رجّعه غير مصنّف) */
  categoryId?: string | null;
  /** `null` = شيل الموديل */
  modelId?: string | null;
  /** `null` = شيل اللون */
  colorId?: string | null;
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
  /** البضاعة المفعّلة بس — لشاشة الكاشير */
  activeOnly?: boolean;
}

/**
 * درج بضاعة.
 *
 * ══ شجرة على مستويين ══
 *   `parentId` فاضي  →  قسم رئيسي   (إكسسوار · مكملات)
 *   `parentId` موجود →  درج جوّه قسم (جرابات · شواحن)
 *
 * ⚠ `productCount` **محسوب مش مخزّن** — بيتعدّ في نفس استعلام
 * القراءة. نفس مبدأ رصيد الخزنة والتنبيهات: الرقم المخزّن
 * بيختلف عن مصدره يوم ما، وساعتها الدرج بيقول حاجة والمخزون
 * بيقول حاجة تانية.
 */
export interface ProductCategory {
  id: string;
  parentId: string | null;
  name: string;
  sortOrder: number;
  /** مزروع مع فتح المحل — مقفول ضد الحذف مش ضد التسمية */
  isSystem: boolean;
  productCount: number;
}

export interface CategoryRepository {
  /** الشجرة كلها + عدد بضاعة كل درج. `branchId` فاضي = كل الفروع. */
  list(tenantId: string, branchId: string | null): Promise<ProductCategory[]>;
  create(input: {
    tenantId: string;
    parentId: string | null;
    name: string;
  }): Promise<{ id: string }>;
  rename(id: string, tenantId: string, name: string): Promise<void>;
  /** حذف ناعم. الحارس (مزروع؟ فيه بضاعة؟) في حالة الاستخدام. */
  softDelete(id: string, tenantId: string, actorId: string, at: Date): Promise<void>;
  /** للحراسة قبل التعديل والحذف */
  findById(id: string, tenantId: string): Promise<ProductCategory | null>;
}

/**
 * موديل موبايل.
 *
 * ══ ⚠ سجل مش نص حرّ ══
 * "١٢ برو ماكس" و"12 promax" و"١٢ بروماكس" لازم يكونوا حاجة
 * واحدة. لو النص حرّ، الجراب بيتسجّل تحت اسم والجهاز تحت اسم
 * تاني ومحدش بيلاقي حد.
 *
 * ⚠ ونفس غلطة `products.source` اللي اتصلّحت بسجل موردين في
 * ملف ٢٢. ده نفس العلاج.
 */
export type ModelFamily = 'IPHONE' | 'ANDROID' | null;

export interface DeviceModel {
  id: string;
  name: string;
  /** ⚠ عمود مستقل عن الاسم عشان "كل الآيفون" تبقى سؤال ممكن */
  brand: string | null;
  /**
   * عيلة الجهاز — 'IPHONE' أو 'ANDROID'، و null = غير مصنّف.
   *
   * ⚠ دي **مش** الماركة. الماركة نص حر بيوصف المصنّع
   * (سامسونج · شاومي · ريلمي)، والعيلة قيمتين بس بيتقسّم
   * عليهم الدرجين في الشاشة.
   *
   * ⚠ والموديل بيفضل صف واحد مهما كانت عيلته. الإكسسوار
   * بيشاور على نفس الصف اللي الجهاز بيشاور عليه — ولو
   * فصلناهم، السؤال "وريني كل حاجة للـ12 برو ماكس" بيموت.
   */
  family: ModelFamily;
  sortOrder: number;
  /** أجهزة متاحة للبيع — **بالكمية** مش بعدد الصفوف */
  deviceCount: number;
  /** أصناف إكسسوار مرتبطة بالموديل */
  accessoryCount: number;
}

export interface ModelRepository {
  list(tenantId: string, branchId: string | null): Promise<DeviceModel[]>;
  create(input: {
    tenantId: string;
    name: string;
    brand: string | null;
    family: ModelFamily;
  }): Promise<{ id: string }>;
  update(
    id: string,
    tenantId: string,
    patch: { name?: string; brand?: string | null; family?: ModelFamily },
  ): Promise<void>;
  softDelete(id: string, tenantId: string, actorId: string, at: Date): Promise<void>;
  findById(id: string, tenantId: string): Promise<DeviceModel | null>;
}

/**
 * لون منتج.
 *
 * ⚠ سجل مش نص حرّ — نفس سبب الموديل: أنا بجمّع بيه، و"أسود"
 * و"اسود" و"black" لازم يكونوا حاجة واحدة.
 *
 * ⚠ وبيتزرع مع فتح المحل، على عكس الموديلات. الموديلات بتقدم
 * (موديل ٢٠٢٧ مش في أي قايمة النهاردة)، والألوان ما بتقدمش.
 */
export interface ProductColor {
  id: string;
  name: string;
  /** كود اللون للنقطة الملوّنة. فاضي = يتعرض بالاسم بس. */
  hex: string | null;
  sortOrder: number;
  isSystem: boolean;
  productCount: number;
}

export interface ColorRepository {
  list(tenantId: string, branchId: string | null): Promise<ProductColor[]>;
  create(input: { tenantId: string; name: string; hex: string | null }): Promise<{ id: string }>;
  update(id: string, tenantId: string, patch: { name?: string; hex?: string | null }): Promise<void>;
  softDelete(id: string, tenantId: string, actorId: string, at: Date): Promise<void>;
  findById(id: string, tenantId: string): Promise<ProductColor | null>;
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
   * السعر اليدوي — للبضاعة اللي مالهاش سعر مسجّل بس.
   *
   * ⚠ لو المنتج له سعر، دالة قاعدة البيانات بتتجاهل القيمة دي
   * تمامًا وبتستخدم سعر المنتج. من غير القاعدة دي، أي حد يقدر
   * يبيع بأي سعر بتعديل بسيط في الطلب.
   */
  unitPricePiastres?: number | null;
}

export interface CreateSaleInput {
  tenantId: string;
  staffId: string;
  treasuryId: string;
  items: SaleLineInput[];
  customerName: string | null;
  customerPhone: string | null;
  /** null = تاريخ النهاردة بتوقيت القاهرة */
  exitDate: string | null;
  /**
   * مدة الضمان بالأيام.
   *
   * ⚠ `null` معناها **مفيش ضمان**، مش "الافتراضي".
   * الافتراضي (30) بيتحطّ في حالة الاستخدام قبل ما يوصل هنا،
   * فاللي بيوصل للقاعدة دايمًا قرار صريح.
   */
  warrantyDays: number | null;
}

export interface CreateSaleResult {
  saleId: string;
  totalPiastres: number;
  movementId: string;
  itemCount: number;
}

export interface SaleSummary {
  id: string;
  tenantId: string;
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
  /**
   * مدة الضمان بالأيام — `null` يعني الفاتورة بلا ضمان.
   *
   * ⚠ تاريخ انتهاء الضمان = `exitDate + warrantyDays`. يعني
   * تعديل تاريخ الخروج بيحرّك الضمان معاه، وده الصح: الضمان
   * بيبدأ يوم ما البضاعة تخرج للزبون مش يوم تسجيل الفاتورة.
   */
  warrantyDays: number | null;
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
  /** محجوب عن غير `profit.view_real` — نفس قاعدة البضاعة */
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

// ─────────── المرتجعات ورفّ المراجعة ───────────

/**
 * بند قابل للاسترجاع من فاتورة.
 *
 * ⚠ `quantityRemaining` هو الرقم اللي بيحكم. اللي اترجّع قبل كده
 * محسوب فيه، فالبند اللي خلص بيرجع بصفر والواجهة بتعرضه باهت.
 * من غير الرقم ده، حد يقدر يرجّع ٣ من حاجة اتباع منها ٢.
 */
export interface ReturnableLine {
  saleItemId: string;
  productId: string;
  productName: string;
  productType: string;
  serialNumber: string | null;
  quantitySold: number;
  quantityReturned: number;
  quantityRemaining: number;
  unitPricePiastres: number;
}

export interface ReturnLineInput {
  saleItemId: string;
  quantity: number;
  /** المرتجع للوحدة — ممكن يكون أقل من سعر البيع، والفرق رسوم */
  unitRefundPiastres: number;
}

export interface CreateReturnInput {
  saleId: string;
  actorId: string;
  treasuryId: string;
  items: ReturnLineInput[];
  reason: string | null;
  /** فاضي = النهاردة بتوقيت القاهرة */
  returnDate: string | null;
  /**
   * تجاوز الضمان — صاحب المحل وحده.
   *
   * ⚠ القيمة دي **نيّة** مش نتيجة. القاعدة هي اللي بتقرر لو
   * الضمان انتهى فعلاً؛ لو الفاتورة لسه في الضمان، العلم ده
   * ما بيعملش حاجة والنتيجة بترجع `warrantyOverridden: false`.
   */
  overrideWarranty: boolean;
}

export interface CreateReturnResult {
  returnId: string;
  refundedPiastres: number;
  /** الفرق اللي ما خرجش من الدرج — إيراد رسوم استرجاع */
  feePiastres: number;
  itemCount: number;
  movementId: string;
  /**
   * هل حصل تجاوز ضمان فعلاً؟
   *
   * ⚠ دي **النتيجة** مش النيّة — وسجل التدقيق بيكتب منها هي،
   * مش من اللي الطلب بعته. الفرق بيبان لما حد يبعت العلم على
   * فاتورة لسه في الضمان: مفيش تجاوز حصل، والسجل لازم يقول كده.
   */
  warrantyOverridden: boolean;
}

/** صف في رفّ المراجعة — مرتجع مستنّي قرار */
export interface QuarantineRow {
  productId: string;
  productName: string;
  productType: string;
  serialNumber: string | null;
  branchId: string;
  quarantinedQuantity: number;
  lastReturnDate: string | null;
  lastReason: string | null;
}

export type QuarantineDecision = 'RELEASE' | 'SCRAP';

export interface QuarantineReviewResult {
  productName: string;
  movedQuantity: number;
  remainingHeld: number;
  nowOnHand: number;
}

// ─────────── الصيانة ───────────

export interface RepairShop {
  id: string;
  name: string;
  phone: string | null;
  notes: string | null;
  isActive: boolean;
}

/** جهاز **المحل** في الورشة — مربوط بالمخزون */
export interface MaintenanceRecord {
  id: string;
  productId: string;
  productName: string;
  serialNumber: string | null;
  shopName: string | null;
  repairShopId: string | null;
  faultNote: string;
  costPiastres: number;
  sentDate: string;
  returnedDate: string | null;
  status: 'SENT' | 'RETURNED' | 'CANCELLED';
  resultNote: string | null;
  /** كام يوم بره — بيغذّي التنبيه بعد 3 أيام */
  daysOut: number;
}

export type TicketStatus =
  | 'CHECKING'
  | 'WAITING_PART'
  | 'READY'
  | 'DELIVERED'
  | 'CANCELLED';

/**
 * تذكرة جهاز **عميل** — مالهاش أي علاقة بـ `products`.
 *
 * ⚠ `hasUnlock` بتقول إن فيه بيانات فتح، **من غير ما تبعتها**.
 * القيمة نفسها بتتجاب بنداء منفصل محصور على اللي استلم الجهاز
 * أو صاحب صلاحية الإدارة.
 */
export interface RepairTicket {
  id: string;
  customerName: string;
  customerPhone: string | null;
  deviceName: string;
  serialNumber: string | null;
  deviceColor: string | null;
  conditionNote: string | null;
  complaint: string;
  shopName: string | null;
  repairShopId: string | null;
  costPiastres: number;
  receivedDate: string;
  promisedDate: string | null;
  deliveredDate: string | null;
  status: TicketStatus;
  workNote: string | null;
  /** NONE · PASSWORD · PATTERN — النوع بس، القيمة بنداء منفصل */
  unlockKind: string;
  hasUnlock: boolean;
  parentId: string | null;
  /** 1 للأصلية، 2 لأول رجعة… بيتحسب في القاعدة */
  visitNumber: number;
  createdById: string;
  createdByName: string | null;
  daysOpen: number;
}

export interface ShopHistoryRow {
  kind: 'OWN' | 'CUSTOMER';
  refId: string;
  title: string;
  detail: string;
  costPiastres: number;
  onDate: string;
  status: string;
}

/** فلاتر مشتركة بين التذاكر وأجهزة المحل */
export interface MaintenanceFilter {
  /** OPEN عندنا · DELIVERED/RETURNED اتسلّمت · ALL */
  scope: string;
  search: string | null;
  from: string | null;
  to: string | null;
  shopId: string | null;
}

/** سطر في تاريخ صيانة منتج — بيتعرض في كارت المنتج */
export interface ProductMaintenanceRow {
  id: string;
  shopName: string | null;
  faultNote: string;
  resultNote: string | null;
  costPiastres: number;
  sentDate: string;
  returnedDate: string | null;
  status: string;
  daysOut: number;
}

export interface MaintenanceRepository {
  listShops(tenantId: string): Promise<RepairShop[]>;
  createShop(data: {
    tenantId: string;
    name: string;
    phone: string | null;
    notes: string | null;
    createdById: string;
  }): Promise<{ id: string }>;
  shopHistory(shopId: string, tenantId: string): Promise<ShopHistoryRow[]>;

  /** إرسال جهاز المحل — بيخصم من المخزون ذريًا */
  sendToShop(input: {
    productId: string;
    actorId: string;
    shopId: string | null;
    fault: string;
    costPiastres: number;
  }): Promise<{ recordId: string; productName: string }>;
  returnFromShop(
    recordId: string,
    actorId: string,
    status: 'RETURNED' | 'CANCELLED',
    costPiastres: number | null,
    note: string | null,
  ): Promise<{ productName: string; finalStatus: string }>;
  listRecords(
    tenantId: string,
    branchId: string | null,
    filter: MaintenanceFilter,
  ): Promise<MaintenanceRecord[]>;
  /** تاريخ صيانة منتج واحد */
  productHistory(productId: string): Promise<ProductMaintenanceRow[]>;

  listTickets(
    tenantId: string,
    branchId: string | null,
    filter: MaintenanceFilter,
  ): Promise<RepairTicket[]>;
  createTicket(data: Record<string, unknown>): Promise<{ id: string }>;
  updateTicket(id: string, patch: Record<string, unknown>): Promise<void>;
  /**
   * ⚠ بترجّع الحالة كمان.
   *
   * السبب إن فتح مرتجع لازم يتأكد إن الزيارة السابقة **اتسلّمت**
   * فعلاً. من غير الحالة، الفحص ده كان محتاج رحلة تانية للقاعدة
   * أو كان بيتساب للشاشة — والشاشة لافتة مش قفل.
   */
  findTicket(id: string): Promise<
    { id: string; tenantId: string; branchId: string; status: string } | null
  >;
  /** ⚠ محصور — الحراسة جوّه دالة القاعدة كمان */
  unlock(
    ticketId: string,
    actorId: string,
    canManage: boolean,
  ): Promise<{ kind: string; value: string | null }>;

  // ─── دفتر الورش ───
  //
  // ⚠ في نفس المستودع مش في مستودع جديد. السبب إن الورشة
  // كيان واحد: نفس الصف اللي بيستقبل الأجهزة هو اللي عليه
  // الحساب. مستودعين معناهم إن حاجز المحل بيتكتب مرتين —
  // وأول واحد يتنسي بيفتح ورشة محل تاني.

  shopBalances(tenantId: string): Promise<RepairShopBalance[]>;
  shopLedger(
    shopId: string,
    tenantId: string,
    limit: number,
  ): Promise<RepairShopMovement[]>;
  /** دين يدوي — ما بيمسّش الخزنة */
  recordShopDebt(input: {
    shopId: string;
    actorId: string;
    amountPiastres: number;
    note: string;
    date: string | null;
  }): Promise<{ movementId: string; newBalance: number }>;
  /** سداد — ذري، بيمسّ الخزنة وبيقسّم نفسه */
  recordShopPayment(input: {
    shopId: string;
    actorId: string;
    treasuryId: string;
    amountPiastres: number;
    note: string | null;
    date: string | null;
  }): Promise<RepairShopPaymentResult>;
}

// ─────────── حساب محلات الصيانة ───────────

/**
 * رصيد ورشة واحدة.
 *
 * ══ ⚠ التقسيم مش شكلي ══
 * `deviceDebt` تكلفتها **دخلت المخزون** خلاص (بتزوّد تكلفة
 * الجهاز)، و`ticketDebt` مصروف خدمة. والاتنين في رصيد واحد
 * لأنك بتدفع للورشة مبلغ واحد.
 *
 * والسداد بيتقسّم بينهم تلقائيًا في القاعدة — من غير كده،
 * إصلاح جهاز محلّك بيتحمّل مرتين في قائمة الدخل.
 *
 * ⚠ و`openDevices` و`openTickets` **بره الرصيد** عن قصد: شغل
 * لسه في الورشة ومفيش دين عليه لحد ما يرجع. بيتعرضوا عشان
 * تعرف إن فيه حاجة جاية، مش عشان تحسبها.
 */
export interface RepairShopBalance {
  shopId: string;
  name: string;
  phone: string | null;
  isActive: boolean;
  /** أجهزة المحل — تكلفتها دخلت المخزون */
  deviceDebt: number;
  /** أجهزة الزباين — مصروف خدمة */
  ticketDebt: number;
  /** دين اتكتب بإيدك (قطع غيار مثلاً) */
  manualDebt: number;
  paidPiastres: number;
  /** موجب = إنت مديون للورشة */
  balancePiastres: number;
  /** لسه في الورشة — مش في الرصيد */
  openDevices: number;
  openTickets: number;
  lastMovement: string | null;
}

export interface RepairShopMovement {
  id: string;
  direction: 'DEBT' | 'PAYMENT';
  amountPiastres: number;
  /** DEVICE جهاز محل · TICKET جهاز عميل · MANUAL بإيدك */
  sourceKind: 'DEVICE' | 'TICKET' | 'MANUAL';
  sourceId: string | null;
  isInventory: boolean;
  note: string | null;
  occurredAt: string;
  /**
   * ⚠ السداد الواحد بيولّد سطرين (مخزون + خدمة). الرقم ده
   * بيخلّي الشاشة تجمّعهم في بند واحد بدل ما توري المستخدم
   * دفعتين وهو دفع مرة.
   */
  paymentGroupId: string | null;
  createdByName: string | null;
}

/** نتيجة السداد — بيرجّع القسمة عشان الشاشة توضّحها */
export interface RepairShopPaymentResult {
  groupId: string;
  inventoryPiastres: number;
  servicePiastres: number;
  newBalance: number;
}

// ─────────── الموردين والديون ───────────

/**
 * رصيد المورّد عند فرع واحد.
 *
 * ══ ⚠ ليه التوزيع أصلاً؟ ══
 * البضاعة بتدخل فرع معيّن، والسداد بيخرج من خزنة فرع معيّن.
 * البُعد ده موجود على الأرض سواء سجّلناه أو لأ.
 *
 * ولما ما نسجّلوش: مدير الفرع الأول بيسدّد دين بضاعة دخلت
 * الفرع التاني، والدفتر بيقول "تمام" — وخزنة فرعه ناقصة فلوس
 * مش بتاعته ومفيش رقم بيقول كده.
 *
 * ⚠ و`branchId` فاضي معناه **غير موزّع** مش "كل الفروع": دي
 * حركات قديمة ما اتحدّدش فرعها، وبتتعرض في مجموعة مستقلة.
 */
export interface SupplierBranchBalance {
  branchId: string | null;
  branchName: string | null;
  debtPiastres: number;
  paidPiastres: number;
  balancePiastres: number;
  movementCount: number;
  lastMovement: string | null;
}

export interface SupplierBalance {
  supplierId: string;
  name: string;
  phone: string | null;
  notes: string | null;
  isActive: boolean;
  productCount: number;
  debtPiastres: number;
  paidPiastres: number;
  /** الدين = الزيادات ناقص السداد. ناتج جمع مش رقم مخزّن. */
  balancePiastres: number;
  lastMovement: string | null;
  /**
   * التوزيع على الفروع.
   *
   * ⚠ مجموع `balancePiastres` بتوعهم = `balancePiastres` فوق
   * بالظبط. الاتنين بيتعرضوا مع بعض عن قصد: الخوف الأصلي في
   * ملف ٢٢ كان من ضياع الإجمالي، والحل إنك توري الاتنين مش
   * إنك تختار واحد.
   */
  branches: SupplierBranchBalance[];
}

/**
 * سطر واحد في دفتر المورّد.
 *
 * ══ ⚠ اسم الجهاز جاي من السجل مش من النص ══
 * `itemName` بيتقرا من `products.name` عبر الربط، والملاحظة
 * احتياطي للحركات اليدوية والصفوف القديمة.
 *
 * الفرق مش شكلي: النص الحر بيتجمّد وقت الكتابة، والسجل بيفضل
 * صح لو الجهاز اتغيّر اسمه — ودي نفس غلطة `products.source`
 * اللي المشروع اتعلّمها مرتين.
 */
export interface SupplierMovement {
  id: string;
  direction: 'DEBT' | 'PAYMENT';
  /** سداد بلا فلوس — بيقلّل الدين والدرج ما بيتغيّرش */
  isDiscount: boolean;
  amountPiastres: number;
  note: string | null;
  /** تاريخ العملية — للدين ده تاريخ دخول البضاعة */
  occurredAt: string;
  branchId: string | null;
  /** اسم الفرع، أو فاضي لو الحركة غير موزّعة */
  branchName: string | null;
  productId: string | null;
  itemName: string | null;
  /** تاريخ دخول الجهاز المخزن، لو الحركة مربوطة بجهاز */
  entryDate: string | null;
  serialNumber: string | null;
  actorName: string;
  /** مفتاح الدور خام — الواجهة هي اللي بتترجمه لكلمة عربية */
  actorRole: string;
  /** الخزنة اللي السداد خرج منها. فاضية للدين والخصم. */
  treasuryName: string | null;
}

export interface SupplierRepository {
  /**
   * ⚠ `branchId` هنا **فلتر نطاق** مش اختيار عرض.
   *
   * صاحب المحل بيبعت null فبيشوف كل الفروع موزّعة. مدير الفرع
   * بيبعت فرعه، وساعتها الأرقام الكلية بتتحسب من فرعه وحده —
   * مش إجمالي المحل مع تفصيل جزئي، لأن ده كان هيوريه رقم أكبر
   * من اللي هو مسؤول عنه.
   */
  listBalances(tenantId: string, branchId: string | null): Promise<SupplierBalance[]>;
  /**
   * دفتر حركات مورّد واحد.
   *
   * ⚠ المحل معامل في الاستعلام مش فلترة بعدية — دفتر مورّد محل
   * تاني بيرجع فاضي، مش بيترجع ويتفلتر.
   */
  listMovements(
    supplierId: string,
    tenantId: string,
    branchId: string | null,
    limit?: number,
  ): Promise<SupplierMovement[]>;
  create(data: {
    tenantId: string;
    name: string;
    phone: string | null;
    notes: string | null;
    createdById: string;
  }): Promise<{ id: string }>;
  update(
    id: string,
    data: { name?: string; phone?: string | null; notes?: string | null; isActive?: boolean },
  ): Promise<void>;
  findById(id: string): Promise<{ id: string; tenantId: string; name: string } | null>;
  /**
   * خصم — بيقلّل الدين **بلا أي حركة فلوس**.
   *
   * ⚠ الفرق عن السداد إن الدرج ما بيتغيّرش. تسجيله كسداد كان
   * هينقّص الخزنة وهي ما نقصتش، ورصيدك على الورق يبقى أقل
   * من اللي في الدرج فعلاً.
   *
   * ⚠ والملاحظة إلزامية: رقم بينقص بلا أثر مادي محتاج سبب
   * مكتوب، وإلا مفيش طريقة تفرّق بين خصم وغلطة بعد شهرين.
   */
  recordDiscount(input: {
    supplierId: string;
    actorId: string;
    amountPiastres: number;
    note: string;
    date: string | null;
    /**
     * ⚠ بيتجاهل تمامًا لغير صاحب المحل.
     *
     * دالة قاعدة البيانات بتاخد الفرع من **جلسة المنفّذ** لو
     * كان ليه فرع، وما بتبصّش على القيمة دي أصلاً. فمدير الفرع
     * مالوش أي طريقة يعلّم خصم على فرع تاني حتى لو عدّل الطلب.
     */
    branchId: string | null;
  }): Promise<{ movementId: string; newBalance: number }>;
  /** دين — ما بيمسّش الخزنة */
  recordDebt(input: {
    supplierId: string;
    actorId: string;
    amountPiastres: number;
    note: string | null;
    date: string | null;
    /** ⚠ بيتجاهل لغير صاحب المحل — الفرع من الجلسة جوّه القاعدة */
    branchId: string | null;
  }): Promise<{ movementId: string; newBalance: number }>;
  /**
   * سداد — **بيمسّ الخزنة ذريًا**.
   *
   * الفلوس بتطلع من الدرج فعلاً. لو سجّلناه في دفتر الموردين
   * بس، رصيد الخزنة يبقى أكبر من الحقيقة بمقدار كل ما دفعته.
   */
  recordPayment(input: {
    supplierId: string;
    actorId: string;
    treasuryId: string;
    amountPiastres: number;
    note: string | null;
    date: string | null;
  }): Promise<{ movementId: string; treasuryMovementId: string; newBalance: number }>;
}

// ─────────── التحويل بين الفروع ───────────

/**
 * ⚠ الاتجاه بيتحسب من فرع القارئ:
 *   IN   جايلك، وإنت اللي بتأكّد الاستلام
 *   OUT  بعتّها، وإنت اللي تقدر تلغيها
 *   BOTH صاحب المحل — بيشوف الاتنين
 */
export type TransferDirection = 'IN' | 'OUT' | 'BOTH';
export type TransferDecision = 'RECEIVE' | 'CANCEL';

export interface PendingTransfer {
  id: string;
  direction: TransferDirection;
  productName: string;
  productType: string;
  serialNumber: string | null;
  quantity: number;
  fromBranch: string;
  toBranch: string;
  note: string | null;
  createdAt: string;
  createdBy: string;
}

export interface TransferRepository {
  /**
   * الإنشاء بيخصم الكمية **فورًا**.
   *
   * البضاعة سابت الرفّ، فما ينفعش تفضل متاحة للبيع. بتبقى في
   * حالة "طايرة" — مش عند حد — لحد ما تتستلم أو تتلغى.
   */
  create(input: {
    productId: string;
    actorId: string;
    toBranchId: string;
    quantity: number;
    note: string | null;
  }): Promise<{ transferId: string; productName: string; moved: number }>;

  /** استلام أو إلغاء — الحراسة على الفرع جوّه دالة القاعدة */
  resolve(
    transferId: string,
    actorId: string,
    decision: TransferDecision,
  ): Promise<{ productName: string; moved: number; finalStatus: string }>;

  listPending(tenantId: string, branchId: string | null): Promise<PendingTransfer[]>;
}

// ─────────── التنبيهات ───────────

/**
 * ⚠ التنبيه **بيتحسب** لحظة الطلب، مش بيتقرا من جدول.
 *
 * السبب: كل التنبيهات دي بتوصف حالة قائمة ("باقي ٢")، مش حدث
 * حصل. ولو خزّنّاها، هتفضل معلّقة بعد ما المشكلة تتحل.
 *
 * نفس مبدأ رصيد الخزنة: ناتج جمع، مش رقم مخزّن.
 */
export type AlertType = 'LOW_STOCK' | 'QUARANTINE_STALE';
export type AlertSeverity = 'HIGH' | 'MEDIUM';

export interface AlertRow {
  alertType: AlertType;
  severity: AlertSeverity;
  entityId: string;
  title: string;
  detail: string;
  metric: number;
}

export interface AlertRepository {
  list(tenantId: string, branchId: string | null): Promise<AlertRow[]>;
}

// ─────────── التقارير ───────────

/**
 * قائمة الدخل لفترة.
 *
 * ⚠ أعمدة التكلفة والربح **nullable** عن قصد. مين مالوش
 * `profit.view_real` بيرجعله `null` — مش صفر ومش رقم مخفي في
 * الواجهة. الفرق مهم: الصفر رقم، و null معناها "مش من حقك".
 *
 * والقيمة ما بتتحسبش في قاعدة البيانات أصلاً لما الصلاحية غايبة.
 */
export interface IncomeStatement {
  salesCount: number;
  salesPiastres: number;
  refundsCount: number;
  refundsPiastres: number;
  refundFeesPiastres: number;
  netSalesPiastres: number;

  cogsPiastres: number | null;
  returnedCogsPiastres: number | null;
  grossProfitPiastres: number | null;
  netProfitPiastres: number | null;

  expensesPiastres: number;
  /**
   * عمولات تحويل الخزن — **جوّه الحساب**.
   *
   * ⚠ ودي عكس السُلفة تحتها بالظبط. العمولة فلوس **خرجت
   * ومارجعتش** — الوكيل خدها. فهي تكلفة حقيقية بتقلّل الربح.
   *
   * السُلفة فلوس خرجت و**هترجع** من الراتب، فهي دَين مش مصروف.
   *
   * ⚠ ومش محجوبة بصلاحية التكلفة: العمولة رسم دفعته مش هامش
   * ربح، ومدير الفرع بيشوف المصروفات أصلاً.
   */
  transferFeesPiastres: number;
  /**
   * ⚠ بره الحساب عن قصد. السُلفة دَين على الموظّف بيتخصم من
   * راتبه، مش مصروف على المحل. لو حسبناها مصروف هتتحسب مرتين:
   * مرة كسُلفة ومرة لما الراتب يتصرف.
   */
  advancesPiastres: number;
  /**
   * ⚠ بره الحساب لنفس السبب. شرا البضاعة تحويل فلوس لمخزون —
   * أصل بيتحوّل لأصل تاني، مش مصروف. والتكلفة بتتحسب وقت البيع
   * في `cogsPiastres`. لو حسبناها الاتنين، كل بضاعة تشتريها
   * بتقلّل أرباحك المعروضة مرتين.
   */
  inventoryPurchasesPiastres: number;
}

export interface ExpenseLine {
  reasonName: string;
  movementCount: number;
  totalPiastres: number;
}

export interface ReportRepository {
  incomeStatement(
    tenantId: string,
    branchId: string | null,
    from: string,
    to: string,
    includeCost: boolean,
  ): Promise<IncomeStatement>;
  expenseBreakdown(
    tenantId: string,
    branchId: string | null,
    from: string,
    to: string,
  ): Promise<ExpenseLine[]>;
}

export interface ReturnRepository {
  /** البنود القابلة للاسترجاع في فاتورة — قراءة بس */
  returnableLines(saleId: string): Promise<ReturnableLine[]>;
  /**
   * الاسترجاع في عملية واحدة لا تتجزّأ.
   *
   * الأربع خطوات (فحص المتبقي · رفّ المراجعة · سجل المرتجع ·
   * حركة الخزنة) بتحصل جوّه دالة قاعدة البيانات: يا كلها يا
   * ولا واحدة. مفيش حالة "الفلوس طلعت والبضاعة ما رجعتش".
   */
  create(input: CreateReturnInput): Promise<CreateReturnResult>;
  /** رفّ المراجعة — المرتجعات اللي لسه مستنية قرار */
  quarantineList(tenantId: string, branchId: string | null): Promise<QuarantineRow[]>;
  /** سليم (يرجع للبيع) أو تالف (يتشطب) */
  review(
    productId: string,
    actorId: string,
    quantity: number,
    decision: QuarantineDecision,
  ): Promise<QuarantineReviewResult>;
}

export interface SaleRepository {
  /**
   * إنشاء بيع كامل في عملية واحدة لا تتجزّأ.
   *
   * التنفيذ بينادي دالة في قاعدة البيانات بتعمل الأربع خطوات
   * (فحص الكمية، الخصم، الفاتورة، حركة الخزنة) مع بعض:
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
  /**
   * ملاحظة الفاتورة — بتتكتب بعد الإنشاء.
   *
   * ⚠ منفصلة عن `create` عن قصد. الملاحظة نص وبس، ودخولها
   * المعاملة الذرّية كان معناه تعديل أخطر دالة في النظام
   * عشان سطر مالوش أي أثر حسابي.
   */
  setNote(id: string, actorId: string, note: string): Promise<void>;
}

// ═══════════════════ حساب المحلات ═══════════════════
//
// ⚠ المرآة المقلوبة للموردين:
//     الموردين  →  دين **عليك**   (بضاعة دخلت بالأجل)
//     المحلات   →  دين **ليك**    (بضاعة خرجت بالأجل)
//
// ⚠ ومنفصل عن `CustomerRecord` عن قصد. العميل بيشتري قطعة
// ويمشي؛ المحل جهة ليها حساب جاري بيفضل مفتوح لشهور. دمجهم
// كان هيخلّي شاشة العملاء فيها أرصدة لناس مالهمش أرصدة.

export interface ShopBalance {
  shopId: string;
  name: string;
  contactName: string | null;
  phone: string | null;
  /** إجمالي اللي خرج بالأجل */
  totalOut: number;
  totalPaid: number;
  /** موجب = المحل مديون لك */
  balancePiastres: number;
  lastMovement: string | null;
}

export interface ConsignLine {
  productId: string;
  quantity: number;
  /** سعر الوحدة اللي اتفقت عليه مع المحل — ممكن يختلف عن سعر البيع */
  unitPricePiastres: number;
}

export interface ShopRepository {
  listBalances(tenantId: string): Promise<ShopBalance[]>;
  create(data: {
    tenantId: string;
    branchId: string | null;
    name: string;
    contactName: string | null;
    phone: string | null;
    notes: string | null;
    createdById: string;
  }): Promise<{ id: string }>;
  update(
    id: string,
    data: { name?: string; contactName?: string | null; phone?: string | null },
  ): Promise<void>;
  findById(id: string): Promise<{ id: string; tenantId: string; name: string } | null>;
  /**
   * خروج بضاعة أجل — **عملية ذرية**.
   *
   * ⚠ تلات كتابات مع بعض: الكمية بتنقص، والدين بيتسجّل،
   * والبنود بتتكتب. لو اتفصلوا، يا بضاعة نقصت ومحدش مديون
   * بيها، يا دين على محل وبضاعة لسه في المخزون.
   */
  consign(input: {
    shopId: string;
    actorId: string;
    items: ConsignLine[];
    note: string | null;
    date: string | null;
  }): Promise<{ movementId: string; totalPiastres: number; newBalance: number }>;
  /**
   * سداد المحل — **بيمسّ الخزنة ذريًا**.
   *
   * ⚠ عكس سداد المورّد: الفلوس **بتدخل** الدرج مش بتطلع.
   */
  recordPayment(input: {
    shopId: string;
    actorId: string;
    treasuryId: string;
    amountPiastres: number;
    note: string | null;
    date: string | null;
  }): Promise<{ movementId: string; treasuryMovementId: string; newBalance: number }>;
}

// ═══════════════════ العملاء ═══════════════════

export interface CustomerRecord {
  id: string;
  tenantId: string;
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
  tenantId: string;
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
    tenantId: string;
    branchId: string | null;
    isMandatory: boolean;
    startsAt: Date;
    endsAt: Date | null;
    createdById: string;
  }): Promise<{ id: string }>;
}


// ═══════════════════════════════════════════════════════════
//  الضمان · شراء البضاعة · تقفيل اليومية
// ═══════════════════════════════════════════════════════════

// ═══════════════════ الضمان ═══════════════════

/**
 * حالة ضمان فاتورة.
 *
 * ⚠ `warrantyDays === null` معناها **مفيش ضمان**، مش "الافتراضي".
 * والفرق ده بيحكم الاسترجاع كله: الفاتورة اللي بلا ضمان كل مرتجع
 * عليها محتاج موافقة صاحب المحل.
 */
export interface WarrantyStatus {
  /** null = بلا ضمان */
  warrantyDays: number | null;
  /** تاريخ خروج البضاعة — الضمان بيبدأ منه مش من وقت التسجيل */
  startsOn: string;
  /** null لو مفيش ضمان */
  expiresOn: string | null;
  /** موجب = لسه فيه أيام. سالب = انتهى من كام يوم. null = مفيش ضمان */
  daysLeft: number | null;
  isCovered: boolean;
}

export interface WarrantyChangeResult {
  previousDays: number | null;
  newDays: number | null;
  expiresOn: string | null;
}

export interface WarrantyRepository {
  status(saleId: string): Promise<WarrantyStatus | null>;
  /**
   * تعديل الضمان بعد البيع.
   *
   * ⚠ الحراسة (صاحب المحل وحده + حاجز المحل) جوّه دالة قاعدة
   * البيانات. الفحص في حالة الاستخدام بيتكرّر معاها عن قصد.
   */
  setDays(
    saleId: string,
    actorId: string,
    warrantyDays: number | null,
  ): Promise<WarrantyChangeResult>;
}

// ═══════════════════ شراء البضاعة ═══════════════════

export interface CreatePurchaseInput {
  actorId: string;
  treasuryId: string;
  amountPiastres: number;
  itemName: string;
  quantity: number;
  supplierId: string | null;
  note: string | null;
}

export interface CreatePurchaseResult {
  purchaseId: string;
  movementId: string;
  /** PENDING لو المنفّذ مالوش صلاحية اعتماد */
  status: 'PENDING' | 'APPROVED';
}

export interface PurchaseRow {
  id: string;
  movementId: string;
  itemName: string;
  quantity: number;
  /** ⚠ مبلغ الحركة **هو** التكلفة. مفيش عمود تاني. */
  amountPiastres: number;
  supplierId: string | null;
  supplierName: string | null;
  status: string;
  note: string | null;
  occurredAt: Date;
  createdById: string;
  createdByName: string | null;
}

export interface PurchaseFilter {
  tenantId: string;
  branchId: string | null;
  from: string | null;
  to: string | null;
  limit: number;
}

export interface PurchaseRepository {
  /**
   * تسجيل شراء — حركة الخزنة والبيان مع بعض في معاملة واحدة.
   *
   * ⚠ الاعتماد بيتحدّد **جوّه القاعدة** من صلاحيات المنفّذ، مش
   * من الطلب. لو التطبيق هو اللي بيقول "دي معتمدة"، أي طلب
   * معدّل بإيد يقدر يعتمد مصروف لنفسه.
   */
  create(input: CreatePurchaseInput): Promise<CreatePurchaseResult>;
  list(filter: PurchaseFilter): Promise<PurchaseRow[]>;
  /**
   * أسماء الموردين بس — لملء القائمة المنسدلة.
   *
   * ⚠ ودي **مش** `SupplierRepository.listBalances`، والفرق مقصود:
   * الأرصدة والديون معلومة مالية مقفولة بـ`supplier.manage`،
   * لكن **الاسم** لازم يوصل لأي حد بيسجّل شرا.
   *
   * لو خلّينا المندوب يكتب الاسم بإيده، هنرجع لنفس بق
   * `products.source`: "أحمد للموبايلات" و"احمد للموبايلات"
   * تاجرين مختلفين والدين ما بيقفلش.
   */
  listSupplierNames(tenantId: string): Promise<{ id: string; name: string }[]>;
}

// ═══════════════════ تقفيل اليومية ═══════════════════

/** الأدوار اللي ينفع تتختار. صاحب المحل خارج القايمة — بيقفل دايمًا. */
export type ClosingRole = 'BRANCH_MANAGER' | 'STAFF';

export interface ClosingPreview {
  canClose: boolean;
  /** السبب لو `canClose` بـ false — بيتعرض قبل الضغط مش بعده */
  reason: string | null;
  periodFrom: Date;
  minutesOpen: number;
  /** الدقايق الفاضلة على حارس التلات ساعات. صفر = تقدر تقفل. */
  minutesLeft: number;
  salesCount: number;
  salesPiastres: number;
  returnsCount: number;
  movementsCount: number;
  closingRoles: ClosingRole[];
}

export interface ClosingSummary {
  id: string;
  branchId: string;
  branchName: string;
  periodFrom: Date;
  periodTo: Date;
  salesCount: number;
  salesPiastres: number;
  returnsCount: number;
  returnsPiastres: number;
  expensesPiastres: number;
  advancesPiastres: number;
  purchasesPiastres: number;
  cashInPiastres: number;
  cashOutPiastres: number;
  note: string | null;
  closedById: string;
  closedByName: string | null;
  closedAt: Date;
}

/**
 * سطر بيع جوّه اللقطة.
 *
 * ⚠ ده **نسخة مستقلة** مش رابط للفاتورة الحيّة. لو الفاتورة
 * اتعدّلت بكرة، السطر ده ما بيتغيّرش — وده الغرض كله.
 */
export interface ClosingSaleLine {
  id: string;
  at: string;
  exitDate: string;
  totalPiastres: number;
  customer: string | null;
  phone: string | null;
  staff: string | null;
  treasury: string | null;
  warrantyDays: number | null;
  items: {
    name: string;
    serial: string | null;
    quantity: number;
    unitPricePiastres: number;
  }[];
}

export interface ClosingMovementLine {
  id: string;
  at: string;
  occurredAt: string;
  type: string;
  direction: string;
  status: string;
  amountPiastres: number;
  reason: string | null;
  person: string | null;
  by: string | null;
  treasury: string | null;
  note: string | null;
}

export interface ClosingPurchaseLine {
  movementId: string;
  at: string;
  amountPiastres: number;
  status: string;
  /** ممكن تكون فاضية: حركة شرا قديمة اتسجّلت قبل ما البيان يبقى موجود */
  item: string | null;
  quantity: number | null;
  supplier: string | null;
  by: string | null;
  treasury: string | null;
  note: string | null;
}

/**
 * الظرف المقفول.
 *
 * ⚠ `undefined` هنا معناها **مالكش صلاحية** مش "مفيش بيانات".
 * الدالة في قاعدة البيانات ما بترجّعهاش أصلاً لمن مالوش
 * `profit.view_real` — فالرقم مش موجود في الرد الخام، مش مخفي
 * في الشاشة.
 */
export interface ClosingCostSnapshot {
  cogsPiastres: number;
  grossProfitPiastres: number;
  lines: {
    saleId: string;
    name: string;
    quantity: number;
    unitCostPiastres: number;
    unitPricePiastres: number;
  }[];
}

export interface ClosingDetail extends Omit<ClosingSummary, 'closedById'> {
  sales: ClosingSaleLine[];
  movements: ClosingMovementLine[];
  purchases: ClosingPurchaseLine[];
  /** موجودة لصاحب المحل بس */
  cost?: ClosingCostSnapshot;
}

export interface CloseDayResult {
  closingId: string;
  periodFrom: Date;
  periodTo: Date;
  salesCount: number;
  salesPiastres: number;
  returnsPiastres: number;
  expensesPiastres: number;
  purchasesPiastres: number;
  cashInPiastres: number;
  cashOutPiastres: number;
}

export interface ClosingRolesChange {
  previousRoles: ClosingRole[];
  newRoles: ClosingRole[];
}

export interface ClosingRepository {
  preview(branchId: string, actorId: string): Promise<ClosingPreview>;
  close(branchId: string, actorId: string, note: string | null): Promise<CloseDayResult>;
  list(scope: ListScope, limit: number): Promise<ClosingSummary[]>;
  /**
   * ⚠ `tenantId` معامل إلزامي مش سياق حواليه.
   * الجلب بالمعرّف المباشر مش محمي بأي فلتر قوايم — من غيره أي
   * حد يعرف رقم يومية يقراها من محل تاني.
   */
  detail(
    closingId: string,
    tenantId: string,
    includeCost: boolean,
  ): Promise<ClosingDetail | null>;
  setRoles(
    branchId: string,
    actorId: string,
    roles: ClosingRole[],
  ): Promise<ClosingRolesChange>;
}