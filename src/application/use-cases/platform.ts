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
  AnnouncementAudience,
  AuditLogger,
  AuthenticatedUser,
  Clock,
  PasswordHasher,
  PlatformAnnouncementRow,
  TenantBranchOption,
  TenantCensus,
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
  /** فاضية = يتولّد واحدة عشوائية ويترجع في الملخّص */
  ownerPassword?: string;
  branches: Array<{ code: string; name: string }>;
  users: Array<{
    username: string;
    fullName: string;
    password?: string;
    role: 'BRANCH_MANAGER' | 'STAFF';
    branchCode: string;
  }>;
}

/**
 * ملخّص التسليم — بيتعرض مرة واحدة بعد الفتح وما بيتخزّنش.
 *
 * ⚠ كلمات المرور هنا **نصّ صريح**، وده الاستثناء الوحيد في
 * النظام كله. السبب إنك لازم تسلّمها للعميل، ومفيش طريقة تانية:
 * الهاش مالوش رجعة.
 *
 * ولذلك ما بتترجّعش تاني أبدًا. لو قفلت الشاشة قبل ما تنسخها،
 * الحل الوحيد إنك تغيّرها من حساب صاحب المحل.
 */
export interface ProvisionedAccount {
  username: string;
  fullName: string;
  role: 'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF';
  branchCode: string | null;
  password: string;
}

export interface CreateTenantResult {
  tenantId: string;
  code: string;
  branchCount: number;
  accounts: ProvisionedAccount[];
}

/** كود المحل: حروف إنجليزية كبيرة وأرقام وشرطة، من 3 لـ 16 */
const TENANT_CODE_RE = /^[A-Z0-9-]{3,16}$/;
const BRANCH_CODE_RE = /^[A-Z0-9-]{2,16}$/;
const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;

/** حد أقصى احترازي — مفيش محل واقعي بمية فرع */
const MAX_ALLOWED_BRANCHES = 50;
const MAX_USERS_AT_SETUP = 30;

/**
 * حروف كلمة المرور المولّدة.
 *
 * ⚠ لاحظ اللي **مش** موجود: صفر و O، واحد و l و I.
 *
 * إنت هتكتب الكلمة دي على ورقة وتسلّمها لموظّف هيكتبها على شاشة
 * موبايل. الحروف المتشابهة دي بتخلق مكالمة "مش راضي يفتح" كل مرة،
 * والمكالمة دي أغلى بكتير من حرفين ناقصين في مساحة الاحتمالات.
 */
const SAFE_CHARS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const GENERATED_LENGTH = 14;

/**
 * توليد كلمة مرور.
 *
 * `crypto.getRandomValues` مش `Math.random` — الفرق مش شكلي:
 * الأولى عشوائية تشفيريًا، والتانية متوقّعة لو حد عرف بذرتها.
 * ودي كلمات مرور محلات عملاء، مش أرقام لعبة.
 */
function generatePassword(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(GENERATED_LENGTH));
  let out = '';
  for (let i = 0; i < GENERATED_LENGTH; i++) {
    out += SAFE_CHARS[bytes[i] % SAFE_CHARS.length];
  }
  return out;
}

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
): Promise<CreateTenantResult> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  // نوحّد لحروف كبيرة قبل الفحص عشان "shop1" و"SHOP1" ما يبقوش
  // محلّين مختلفين — والكود ده الموظّف هيكتبه كل يوم في الدخول
  const code = input.code.trim().toUpperCase();
  const name = input.name.trim();
  const ownerUsername = input.ownerUsername.trim().toLowerCase();
  const ownerFullName = input.ownerFullName.trim();

  if (!TENANT_CODE_RE.test(code)) {
    throw Errors.validation('كود المحل: حروف إنجليزية كبيرة وأرقام وشرطة، من 3 إلى 16 حرفًا.');
  }
  if (name.length < 2 || name.length > 80) throw Errors.validation('اسم المحل غير صالح.');
  if (!USERNAME_RE.test(ownerUsername)) {
    throw Errors.validation('اسم مستخدم المالك: حروف إنجليزية صغيرة وأرقام، من 3 إلى 32 حرفًا.');
  }
  if (ownerFullName.length < 3 || ownerFullName.length > 80) {
    throw Errors.validation('اسم المالك الكامل غير صالح.');
  }

  const maxBranches = Number(input.maxBranches);
  if (!Number.isInteger(maxBranches) || maxBranches < 1 || maxBranches > MAX_ALLOWED_BRANCHES) {
    throw Errors.validation(`عدد الفروع من 1 إلى ${MAX_ALLOWED_BRANCHES}.`);
  }

  // ─── الفروع ───
  if (!Array.isArray(input.branches) || input.branches.length === 0) {
    throw Errors.validation('أضف فرعًا واحدًا على الأقل.');
  }
  if (input.branches.length > maxBranches) {
    throw Errors.validation(
      `عدد الفروع ${input.branches.length} أكبر من الحد المسموح ${maxBranches}. ارفع الحد أو احذف فرعًا.`,
    );
  }

  const branches = input.branches.map((b) => {
    const bCode = String(b.code ?? '').trim().toUpperCase();
    const bName = String(b.name ?? '').trim();
    if (!BRANCH_CODE_RE.test(bCode)) {
      throw Errors.validation(`كود الفرع "${bCode}" غير صالح: حروف كبيرة وأرقام وشرطة، من حرفين إلى 16.`);
    }
    if (bName.length < 2 || bName.length > 80) {
      throw Errors.validation('اسم الفرع غير صالح.');
    }
    return { code: bCode, name: bName };
  });

  // ⚠ فحص التكرار هنا قبل النداء. القيد الفريد في القاعدة هو
  // الضمانة النهائية، لكن الرسالة اللي بترجع منه غامضة — والفحص
  // ده بيقول للمستخدم أنهي كود بالظبط اتكرّر.
  const branchCodes = new Set<string>();
  for (const b of branches) {
    if (branchCodes.has(b.code)) throw Errors.validation(`كود الفرع "${b.code}" مكرّر.`);
    branchCodes.add(b.code);
  }

  // ─── الحسابات ───
  const rawUsers = Array.isArray(input.users) ? input.users : [];
  if (rawUsers.length > MAX_USERS_AT_SETUP) {
    throw Errors.validation(`الحد ${MAX_USERS_AT_SETUP} حسابًا عند التجهيز. الباقي يضيفه صاحب المحل.`);
  }

  const usernames = new Set<string>([ownerUsername]);
  const prepared = rawUsers.map((u) => {
    const username = String(u.username ?? '').trim().toLowerCase();
    const fullName = String(u.fullName ?? '').trim();
    const branchCode = String(u.branchCode ?? '').trim().toUpperCase();

    if (!USERNAME_RE.test(username)) {
      throw Errors.validation(`اسم المستخدم "${username}" غير صالح.`);
    }
    if (usernames.has(username)) {
      throw Errors.validation(`اسم المستخدم "${username}" مكرّر في النموذج.`);
    }
    usernames.add(username);

    if (fullName.length < 3 || fullName.length > 80) {
      throw Errors.validation(`الاسم الكامل لـ "${username}" غير صالح.`);
    }
    if (u.role !== 'BRANCH_MANAGER' && u.role !== 'STAFF') {
      throw Errors.validation('الدور المسموح: مدير فرع أو مندوب مبيعات.');
    }
    if (!branchCodes.has(branchCode)) {
      throw Errors.validation(`الفرع "${branchCode}" غير موجود في قائمة الفروع.`);
    }

    // فاضية = يتولّد. المولّدة أقوى من اللي بتتكتب على السريع،
    // وبتترجع في الملخّص عشان تسلّمها.
    const password = String(u.password ?? '').trim() || generatePassword();
    if (password.length < 12) {
      throw Errors.validation(`كلمة مرور "${username}" 12 حرفًا على الأقل.`);
    }
    if (password.length > 1024) throw Errors.validation('كلمة المرور أطول من الحد المسموح.');

    return { username, fullName, password, role: u.role, branchCode };
  });

  const ownerPassword = String(input.ownerPassword ?? '').trim() || generatePassword();
  if (ownerPassword.length < 12) {
    throw Errors.validation('كلمة مرور المالك 12 حرفًا على الأقل.');
  }
  if (ownerPassword.length > 1024) throw Errors.validation('كلمة المرور أطول من الحد المسموح.');

  const existing = await deps.tenants.findByCode(code);
  if (existing) throw Errors.validation('كود المحل ده مستخدم بالفعل.');

  // ─── التجزئة ───
  // كل الهاشات على التوازي: كل واحد بيلف مية ألف لفة عن قصد،
  // فالتسلسل هيخلّي عشر حسابات تاخد وقت ملحوظ قدّامك.
  const [ownerPasswordHash, ...userHashes] = await Promise.all([
    deps.hasher.hash(ownerPassword),
    ...prepared.map((u) => deps.hasher.hash(u.password)),
  ]);

  const created = await deps.tenants.create({
    code,
    name,
    maxBranches,
    ownerUsername,
    ownerFullName,
    ownerPasswordHash,
    branches,
    users: prepared.map((u, i) => ({
      username: u.username,
      fullName: u.fullName,
      passwordHash: userHashes[i],
      role: u.role,
      branchCode: u.branchCode,
    })),
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'tenant.create',
    entity: 'Tenant',
    entityId: created.tenantId,
    // ⚠ مفيش كلمة مرور ولا هاش في السجل. السجل بيتقرا بصلاحية
    // تانية، وما ينفعش يبقى نسخة تانية من الأسرار.
    metadata: {
      code,
      name,
      maxBranches,
      branchCount: created.branchCount,
      userCount: created.userCount,
      ownerUsername,
    },
  });

  return {
    tenantId: created.tenantId,
    code,
    branchCount: created.branchCount,
    accounts: [
      {
        username: ownerUsername,
        fullName: ownerFullName,
        role: 'SUPER_ADMIN',
        branchCode: null,
        password: ownerPassword,
      },
      ...prepared.map((u) => ({
        username: u.username,
        fullName: u.fullName,
        role: u.role,
        branchCode: u.branchCode,
        password: u.password,
      })),
    ],
  };
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

// ─────────── الجرد والمحو النهائي ───────────

/**
 * جرد المحل — بيتنادى قبل ما شاشة التأكيد تظهر.
 *
 * ⚠ ده الاستثناء الوحيد اللي بيشوف فيه مشغّل المنصّة رقم مالي.
 * وبيشوفه في لحظة واحدة بس: قبل ما يمسح.
 *
 * والاستثناء ده مقصود ومحدود: مش تقرير ولا قائمة، رقم إجمالي
 * واحد بيقول "المحل ده فيه شغل حقيقي ولا فاضي". من غيره، المحو
 * بيبقى دوسة في الضلمة — ومحل تجربة ومحل زبون بيبانوا زي بعض.
 */
export async function getTenantCensus(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  tenantId: string,
): Promise<TenantCensus> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const census = await deps.tenants.census(tenantId);
  if (!census) throw Errors.notFound('المحل');
  return census;
}

export interface PurgeTenantRequest {
  /** كود المحل مكتوب بإيد المستخدم — لازم يطابق */
  confirmCode: string;
}

export interface PurgeTenantResult {
  code: string;
  name: string;
  deletedUsers: number;
  deletedSales: number;
}

/**
 * محو المحل نهائيًا.
 *
 * ══ ⚠ مفيش تراجع ══
 * مفيش سلّة مهملات ولا نسخة احتياطية جوّه النظام.
 *
 * ══ الأقفال الأربعة ══
 *   1) مشغّل المنصّة بس        ← هنا
 *   2) المحل لازم يكون موقوف   ← جوّه دالة القاعدة
 *   3) مفيش مشغّل منصّة جوّاه   ← جوّه دالة القاعدة
 *   4) تكتب الكود بإيدك        ← هنا
 *
 * ══ ليه القفل الرابع هنا مش في الواجهة؟ ══
 * الواجهة ممكن تتخطّى بطلب من المتصفح مباشرةً. المقارنة لازم
 * تحصل في الخادم وإلا تبقى لافتة مش قفل.
 *
 * ══ ليه كتابة الكود مش "متأكد؟ أيوه"؟ ══
 * زرار "أيوه" بيتضغط بالعضلة مش بالعقل — إنت ضغطته ألف مرة
 * قبل كده على حاجات مش خطيرة. كتابة الكود بتجبرك تبصّ على
 * الصف اللي إنت واقف عليه فعلاً وتقراه.
 *
 * تشبيه: فرق بين ما تمضي على ورقة وبين ما تكتب المبلغ بالحروف.
 * التانية بتخلّيك تقراه.
 */
export async function purgeTenant(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  tenantId: string,
  input: PurgeTenantRequest,
): Promise<PurgeTenantResult> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const tenant = await deps.tenants.findById(tenantId);
  if (!tenant) throw Errors.notFound('المحل');

  const typed = String(input.confirmCode ?? '').trim().toUpperCase();
  if (!typed) throw Errors.validation('اكتب كود المحل للتأكيد.');
  if (typed !== tenant.code.toUpperCase()) {
    throw Errors.validation(`الكود مش مطابق. اكتب "${tenant.code}" بالظبط.`);
  }

  // ⚠ الجرد بيتاخد **قبل** المحو عشان يتسجّل في الملخّص. بعد
  // المحو مفيش حاجة نعدّها — والرقم اللي بيتقال بعد كده بيبقى
  // بلا مصدر.
  const census = await deps.tenants.census(tenantId);

  const result = await deps.tenants.purge(tenantId, actor.id);

  // ⚠ الشاهد الأساسي بيتكتب **جوّه المعاملة** في قاعدة البيانات،
  // مش هنا. السطر ده إضافي: لو الشبكة قطعت بعد المحو، السجل
  // اللي في القاعدة يكون اتكتب فعلاً. الاتنين مش تكرار — واحد
  // مضمون مع المسح والتاني بيشيل تفاصيل الجلسة.
  await deps.audit.record({
    actorId: actor.id,
    action: 'tenant.purge.confirmed',
    entity: 'Tenant',
    entityId: tenantId,
    metadata: {
      code: result.code,
      name: result.name,
      deletedUsers: result.deletedUsers,
      deletedSales: result.deletedSales,
      salesTotalPiastres: census?.salesTotalPiastres ?? null,
    },
  });

  return result;
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


// ═══════════════════════════════════════════════════════════
//  الإعلانات
//
//  ══ ⚠ ليه هنا مش في `announcements.ts`؟ ══
//  لأن ده بقى فعل **منصّة** مش فعل محل. ملف الإعلانات القديم
//  بيشتغل بمنطق "أنا جوّه محلي": بياخد المحل من جلسة الباثّ.
//  والبثّ دلوقتي بيعدّي الجدار ده عن قصد.
//
//  خلطهم كان هيخلّي ملف واحد فيه منطقين متعاكسين — وأول واحد
//  يعدّل فيه بكرة هيلخبطهم.
//
//  ══ ⚠ ومفيش صلاحية جديدة ══
//  الحارس بيفحص `tenant.manage` — الصلاحية اللي عند مشغّل
//  المنصّة أصلاً. وفحص الدور نفسه مكرّر جوّه دوال القاعدة.
//
//  السبب: الفحص الأمني الدوري بيفشل لو مشغّل المنصّة اتدّى أي
//  صلاحية غير `tenant.view` و`tenant.manage`. صلاحية جديدة كانت
//  هتخلّي الفحص يرنّ كل يوم الساعة ٣ الفجر.
// ═══════════════════════════════════════════════════════════

export interface BroadcastRequest {
  /** فاضي = كل المحلات المفعّلة */
  tenantId?: string | null;
  audience?: string;
  branchId?: string | null;
  title: string;
  body: string;
  severity?: string;
  isMandatory?: boolean;
  /** فاضي = بلا نهاية */
  endsAt?: string | null;
}

const AUDIENCES: AnnouncementAudience[] = [
  'ALL',
  'OWNERS_ONLY',
  'MANAGERS_ONLY',
  'STAFF_ONLY',
  'SINGLE_BRANCH',
];

const SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;

/** أسماء فروع محل — لملء القائمة عند التوجيه لفرع */
export async function listTenantBranches(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  tenantId: string,
): Promise<TenantBranchOption[]> {
  assertPlatform(actor, PERMISSIONS.TENANT_VIEW);

  const id = String(tenantId ?? '').trim();
  if (!id) throw Errors.validation('اختر المحل.');

  return deps.tenants.branchesOf(actor.id, id);
}

/**
 * بثّ إعلان.
 *
 * ══ ⚠ المحل الفاضي معناه "الكل" — وده قرار خطر بطبيعته ══
 * زرار واحد بيوصل لكل عملائك. عشان كده السجل بيكتب **عدد
 * المحلات اللي اتبعتلها فعلاً**، مش النيّة.
 *
 * لو بعتّ لـ٤٠ محل بالغلط، السجل هيقول ٤٠ — وتعرف حجم اللي
 * حصل من غير ما تعدّ بإيدك.
 */
export async function broadcast(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  input: BroadcastRequest,
): Promise<{ sentCount: number }> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const title = String(input.title ?? '').trim();
  const body = String(input.body ?? '').trim();

  if (title.length < 3) throw Errors.validation('عنوان الإعلان قصير جدًا.');
  if (title.length > 140) throw Errors.validation('العنوان يجب أن يكون 140 حرفًا أو أقل.');
  if (body.length < 3) throw Errors.validation('نص الإعلان قصير جدًا.');
  if (body.length > 4000) throw Errors.validation('النص طويل جدًا (الحد 4000 حرف).');

  const audience = String(input.audience ?? 'ALL').trim().toUpperCase() as AnnouncementAudience;
  if (!AUDIENCES.includes(audience)) throw Errors.validation('الجمهور غير معروف.');

  const severityRaw = String(input.severity ?? 'INFO').trim().toUpperCase();
  const severity = SEVERITIES.find((s) => s === severityRaw);
  if (!severity) throw Errors.validation('درجة الأهمية غير معروفة.');

  const tenantId = String(input.tenantId ?? '').trim() || null;
  const branchId = String(input.branchId ?? '').trim() || null;

  // ⚠ الفرع معناه محل واحد بالضرورة. "كل المحلات + فرع" جملة
  // بلا معنى — الفرع بتاع محل بعينه.
  if (audience === 'SINGLE_BRANCH') {
    if (!tenantId) throw Errors.validation('التوجيه لفرع يحتاج اختيار المحل.');
    if (!branchId) throw Errors.validation('اختر الفرع.');
  }

  let endsAt: Date | null = null;
  if (input.endsAt) {
    endsAt = new Date(input.endsAt);
    if (Number.isNaN(endsAt.getTime())) throw Errors.validation('تاريخ الانتهاء غير صالح.');
    if (endsAt <= deps.clock.now()) {
      throw Errors.validation('تاريخ الانتهاء يجب أن يكون في المستقبل.');
    }
  }

  const result = await deps.tenants.broadcast({
    // ⚠ من الجلسة مش من الطلب — والدالة في القاعدة بتفحص الدور
    // منه تاني قبل ما تكتب أي صف.
    actorId: actor.id,
    tenantId,
    audience,
    branchId: audience === 'SINGLE_BRANCH' ? branchId : null,
    title,
    body,
    severity,
    isMandatory: input.isMandatory !== false,
    endsAt,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'platform.broadcast',
    entity: 'Announcement',
    entityId: tenantId ?? 'ALL_TENANTS',
    metadata: {
      // العدد من رد القاعدة مش من حسابنا — الحقيقة مش النيّة
      sentCount: result.sentCount,
      scope: tenantId ? 'SINGLE_TENANT' : 'ALL_TENANTS',
      tenantId,
      audience,
      branchId,
      severity,
      isMandatory: input.isMandatory !== false,
      title,
    },
  });

  return result;
}

/**
 * سجل ما أُرسل.
 *
 * ⚠ فيه عمود "كام قراه من كام المفروض يشوفوه". إعلان إلزامي
 * من غير الرقم ده = بثّ في الفراغ: "٣ قروه" مالهاش معنى من
 * غير ما تعرف ٣ من كام.
 */
export async function listPlatformAnnouncements(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  limit = 50,
): Promise<PlatformAnnouncementRow[]> {
  assertPlatform(actor, PERMISSIONS.TENANT_VIEW);
  return deps.tenants.announcements(actor.id, Math.min(Math.max(limit, 1), 200));
}

/**
 * سحب إعلان اتبعت بالغلط.
 *
 * ⚠ حذف ناعم. بيختفي من الشاشات فورًا، والإقرارات اللي اتسجّلت
 * بتفضل — السجل ما بيتشالش.
 *
 * ولاحظ إن السحب **بيشيل صف واحد**. لو البثّ راح لأربعين محل،
 * دول أربعين صف، وكل واحد بيتسحب لوحده. مقصود: ممكن تسحب من
 * محل واحد وتسيبه عند الباقيين.
 */
export async function withdrawAnnouncement(
  deps: PlatformDeps,
  actor: AuthenticatedUser,
  announcementId: string,
): Promise<void> {
  assertPlatform(actor, PERMISSIONS.TENANT_MANAGE);

  const id = String(announcementId ?? '').trim();
  if (!id) throw Errors.validation('معرّف الإعلان مفقود.');

  await deps.tenants.withdrawAnnouncement(actor.id, id);

  await deps.audit.record({
    actorId: actor.id,
    action: 'platform.announcement.withdraw',
    entity: 'Announcement',
    entityId: id,
  });
}