/**
 * إدارة المحلات — شغل مشغّل المنصّة
 *
 * ══ الحد الفاصل اللي بيحكم الملف كله ══
 * مشغّل المنصّة بيتحكّم في **الاشتراك**، مش في **الشغل**.
 *
 *   يقدر:  يفتح محل، يوقفه، يظبط عدد فروعه، يشوف حجم استخدامه
 *   ما يقدرش: يشوف مبيعاته، تكاليفه، أرباحه، عملاءه، ولا مخزونه
 *
 * ══ ليه الخط ده مهم تجاريًا مش أخلاقيًا بس؟ ══
 * المحلات دي ممكن تكون منافسة لبعض. أول ما واحد فيهم يفهم إن
 * مورّد النظام شايف هوامشه، مش هيدخّل بياناته الحقيقية — هيدخّل
 * أرقام مزوّقة، والنظام يبقى بلا قيمة عنده وعندك.
 *
 * الحياد مش تنازل. هو المنتج.
 *
 * ══ وفين الحراسة فعليًا؟ ══
 * في تلات طبقات:
 *   1) دور PLATFORM_ADMIN صلاحياته اتنين بس (permissions.ts)
 *   2) `scopeFor` في كل حالة استخدام بترمي لو الدور ده (products,
 *      sales, customers, treasury)
 *   3) الشاشات نفسها بتوجّهه بعيد عن بيانات المحلات
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  PasswordHasher,
  TenantOverview,
  TenantRepository,
} from '../ports';

export interface PlatformDeps {
  tenants: TenantRepository;
  hasher: PasswordHasher;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateTenantRequest {
  code: string;
  name: string;
  maxBranches: number;
  ownerUsername: string;
  ownerFullName: string;
  ownerPassword: string;
  branchCode: string;
  branchName: string;
}

/** كود المحل: حروف إنجليزية كبيرة وأرقام وشرطة، من 3 لـ 16 */
const TENANT_CODE_RE = /^[A-Z0-9-]{3,16}$/;
const BRANCH_CODE_RE = /^[A-Z0-9-]{2,16}$/;
const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;

/** حد أقصى احترازي — مفيش محل واقعي بمية فرع */
const MAX_ALLOWED_BRANCHES = 50;

function assertPlatform(actor: AuthenticatedUser, permission: string): void {
  if (!actor.permissions.includes(permission as never)) {
    throw Errors.forbidden(permission);
  }
}

// ─────────── القراءة ───────────

export async function listTenants(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
): Promise<TenantOverview[]> {
  assertPlatform(actor, PERMISSIONS.TENANT_VIEW);
  return deps.tenants.listOverview();
}

// ─────────── فتح محل ───────────

export async function createTenant(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  input: CreateTenantRequest,
): Promise<{ tenantId: string; code: string }> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  // نوحّد لحروف كبيرة قبل الفحص عشان "shop1" و"SHOP1" ما يبقوش
  // محلّين مختلفين — والكود ده الموظّف هيكتبه كل يوم في الدخول
  const code = input.code.trim().toUpperCase();
  const branchCode = input.branchCode.trim().toUpperCase();
  const name = input.name.trim();
  const branchName = input.branchName.trim();
  const ownerUsername = input.ownerUsername.trim().toLowerCase();
  const ownerFullName = input.ownerFullName.trim();

  if (!TENANT_CODE_RE.test(code)) {
    throw Errors.validation('كود المحل: حروف إنجليزية كبيرة وأرقام وشرطة، من 3 إلى 16 حرفًا.');
  }
  if (!BRANCH_CODE_RE.test(branchCode)) {
    throw Errors.validation('كود الفرع: حروف إنجليزية كبيرة وأرقام وشرطة، من حرفين إلى 16.');
  }
  if (name.length < 2 || name.length > 80) throw Errors.validation('اسم المحل غير صالح.');
  if (branchName.length < 2 || branchName.length > 80) {
    throw Errors.validation('اسم الفرع غير صالح.');
  }
  if (!USERNAME_RE.test(ownerUsername)) {
    throw Errors.validation('اسم مستخدم المالك: حروف إنجليزية صغيرة وأرقام، من 3 إلى 32 حرفًا.');
  }
  if (ownerFullName.length < 3 || ownerFullName.length > 80) {
    throw Errors.validation('اسم المالك الكامل غير صالح.');
  }
  if (input.ownerPassword.length < 12) {
    throw Errors.validation('كلمة مرور المالك 12 حرفًا على الأقل.');
  }
  if (input.ownerPassword.length > 1024) {
    throw Errors.validation('كلمة المرور أطول من الحد المسموح.');
  }

  const maxBranches = Number(input.maxBranches);
  if (!Number.isInteger(maxBranches) || maxBranches < 1 || maxBranches > MAX_ALLOWED_BRANCHES) {
    throw Errors.validation(`عدد الفروع من 1 إلى ${MAX_ALLOWED_BRANCHES}.`);
  }

  // فحص مبكر عشان رسالة عربية واضحة بدل خطأ قاعدة بيانات خام.
  // القيد الفريد في القاعدة هو الضمانة النهائية.
  const existing = await deps.tenants.findByCode(code);
  if (existing) throw Errors.validation('كود المحل ده مستخدم بالفعل.');

  const ownerPasswordHash = await deps.hasher.hash(input.ownerPassword);

  const created = await deps.tenants.create({
    code,
    name,
    maxBranches,
    ownerUsername,
    ownerFullName,
    ownerPasswordHash,
    branchCode,
    branchName,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'tenant.create',
    entity: 'Tenant',
    entityId: created.tenantId,
    // ⚠ مفيش كلمة مرور ولا هاش في السجل. السجل بيتقرا بصلاحية
    // تانية، وما ينفعش يبقى نسخة تانية من الأسرار.
    metadata: { code, name, maxBranches, ownerUsername, branchCode },
  });

  return { tenantId: created.tenantId, code };
}

// ─────────── إيقاف وتفعيل ───────────

/**
 * إيقاف اشتراك محل.
 *
 * ⚠ الإيقاف بيمنع الدخول ومش بيمسح ولا صف. لو دفع بكرة، كل حاجة
 * زي ما هي — بضاعته وفواتيره وخزينته وموظّفينه.
 *
 * والإيقاف **فوري** مش بعد انتهاء الجلسات: الحارس بيقرا حالة
 * المحل من قاعدة البيانات في كل طلب دخول.
 */
export async function setTenantActive(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  tenantId: string,
  isActive: boolean,
): Promise<void> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const tenant = await deps.tenants.findById(tenantId);
  if (!tenant) throw Errors.notFound('المحل');

  // ⚠ ما تقفلش على نفسك.
  // حساب مشغّل المنصّة عايش جوّه محل. لو أوقفناه، هتتقفل بره
  // النظام ومفيش طريق رجوع غير SQL يدوي.
  if (!isActive && tenantId === actor.tenantId) {
    throw Errors.validation('ما ينفعش توقف المحل اللي حسابك فيه.');
  }

  await deps.tenants.setActive(tenantId, isActive);

  await deps.audit.record({
    actorId: actor.id,
    action: isActive ? 'tenant.activate' : 'tenant.suspend',
    entity: 'Tenant',
    entityId: tenantId,
    metadata: { code: tenant.code, name: tenant.name },
  });
}

/** تغيير حد الفروع — الترقية أو التخفيض حسب الاشتراك */
export async function setTenantBranchLimit(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  tenantId: string,
  maxBranches: number,
): Promise<void> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const limit = Number(maxBranches);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ALLOWED_BRANCHES) {
    throw Errors.validation(`عدد الفروع من 1 إلى ${MAX_ALLOWED_BRANCHES}.`);
  }

  const tenant = await deps.tenants.findById(tenantId);
  if (!tenant) throw Errors.notFound('المحل');

  // ⚠ التخفيض تحت عدد الفروع الحالي مسموح عن قصد.
  //
  // الفروع الموجودة ما بتتقفلش — المحل بس ما يقدرش يفتح جديد لحد
  // ما ينزل تحت الحد. الشغل ما بيقفش عشان تخفيض اشتراك، والضغط
  // بيبقى على الجديد مش على القايم.
  await deps.tenants.setMaxBranches(tenantId, limit);

  await deps.audit.record({
    actorId: actor.id,
    action: 'tenant.limit.update',
    entity: 'Tenant',
    entityId: tenantId,
    metadata: { code: tenant.code, from: tenant.maxBranches, to: limit },
  });
}

// ─────────── التأسيس لمرّة واحدة ───────────

export interface BootstrapRequest {
  tenantId: string;
  username: string;
  fullName: string;
  password: string;
  passkey: string;
}

/**
 * إنشاء أول حساب مشغّل منصّة.
 *
 * ══ مشكلة البيضة والفرخة ══
 * عشان تفتح محل لازم تكون مشغّل منصّة. وعشان تبقى مشغّل منصّة
 * لازم حد يعملك حساب. ومفيش حد.
 *
 * الحل نفس حل الإعداد الأولي: سرّ في إعدادات كلاودفلير بيفتح
 * الباب مرة واحدة، وبعدين تمسحه فيتقفل للأبد.
 *
 * ⚠ الدالة دي **مالهاش فحص صلاحية** لأن مفيش حد عنده صلاحية بعد.
 * حراستها في المسار: السرّ + إن مفيش مشغّل منصّة أصلاً.
 */
export async function bootstrapPlatformAdmin(
  deps: PlatformDeps,
  input: BootstrapRequest,
): Promise<{ id: string }> {
  const username = input.username.trim().toLowerCase();
  const fullName = input.fullName.trim();

  if (!USERNAME_RE.test(username)) {
    throw Errors.validation('اسم المستخدم: حروف إنجليزية صغيرة وأرقام، من 3 إلى 32 حرفًا.');
  }
  if (fullName.length < 3 || fullName.length > 80) {
    throw Errors.validation('الاسم الكامل غير صالح.');
  }
  if (input.password.length < 12) throw Errors.validation('كلمة المرور 12 حرفًا على الأقل.');
  if (input.passkey.length < 16) {
    throw Errors.validation('المفتاح الثاني 16 حرفًا على الأقل.');
  }
  if (input.passkey === input.password) {
    // مفتاحين متطابقين = مفتاح واحد. القفل التاني بيبقى شكل بلا وظيفة.
    throw Errors.validation('المفتاح الثاني يجب أن يختلف عن كلمة المرور.');
  }

  if (await deps.tenants.platformAdminExists()) {
    throw Errors.validation('مشغّل المنصّة موجود بالفعل.');
  }

  const [passwordHash, passkeyHash] = await Promise.all([
    deps.hasher.hash(input.password),
    deps.hasher.hash(input.passkey),
  ]);

  const created = await deps.tenants.createPlatformAdmin({
    tenantId: input.tenantId,
    username,
    fullName,
    passwordHash,
    passkeyHash,
  });

  await deps.audit.record({
    actorId: created.id,
    action: 'platform.bootstrap',
    entity: 'User',
    entityId: created.id,
    metadata: { username, tenantId: input.tenantId },
  });

  return created;
}
