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

/** الأنواع المدعومة حاليًا. التحويلات (TRANSFER_*) موجودة في
 *  قاعدة البيانات لكن لسه مش مفعّلة في التطبيق. */
export type MovementType = 'DEPOSIT' | 'WITHDRAWAL' | 'EXPENSE' | 'ADVANCE' | 'ADJUSTMENT';

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
