/**
 * منطق المصادقة (Auth Use-Cases)
 *
 * ══ لاحظ حاجة مهمة ══
 * إحنا غيّرنا المنصّة كلها: من Node لكلاودفلير، من Prisma لسوبابيز،
 * من Argon2 لـ PBKDF2. والملف ده — اللي فيه أهم منطق في النظام —
 * اتغيّر فيه تلات سطور بس (لأن التشفير بقى async).
 *
 * ده مش صدفة. ده بالظبط سبب تقسيم المشروع بالشكل ده.
 * تشبيه: خطة المدرّب ما بتتغيرش لما النادي يغيّر ماركة الأجهزة.
 *
 * الملف ده مش بيعرف حاجة عن Hono ولا سوبابيز ولا كلاودفلير.
 * ولا سطر واحد.
 */

import { Errors } from '../../domain/errors';
import { LOGIN_POLICY, SESSION_POLICY, idleRuleFor } from '../../domain/config';
import type {
  RoleKey,
  AuditLogger,
  AuthenticatedUser,
  Clock,
  PasswordHasher,
  RateLimiter,
  SessionRecord,
  SessionRepository,
  TokenService,
  UserRecord,
  UserRepository,
} from '../ports';

export interface AuthDeps {
  users: UserRepository;
  sessions: SessionRepository;
  hasher: PasswordHasher;
  tokens: TokenService;
  clock: Clock;
  audit: AuditLogger;
  rateLimiter: RateLimiter;
  /** سرّ التوقيع — جاي من إعدادات كلاودفلير مع كل طلب */
  jwtSecret: string;
}

export interface RequestContext {
  ipAddress: string | null;
  userAgent: string | null;
}

export interface LoginInput {
  /** كود المحل — جزء من الهوية، مش سياق حواليها */
  tenantCode: string;
  username: string;
  password: string;
  /** المفتاح التاني — مطلوب من مشغّل المنصّة وحده */
  adminPasskey?: string;
}

export interface LoginResult {
  user: AuthenticatedUser;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

/**
 * الأدوار اللي بتدخل من الباب السرّي بالمفتاح التاني.
 *
 * ══ ⚠ ليه صاحب المحل مش هنا؟ ══
 *
 * القاعدة دي اتكتبت لما كان فيه **مالك واحد في النظام كله**.
 * وقتها كان منطقي إن أعلى حساب يتخبّى ورا رابط سرّي ومفتاح تاني.
 *
 * مع نظام المحلات، بقى فيه صاحب محل لكل عميل. ولو خلّيناهم كلهم
 * على الباب السرّي، هيبقى عشرين واحد بيشتركوا في نفس الرابط —
 * وده مش قفل، ده مفتاح واحد متوزّع على كل الناس.
 *
 * والأسوأ: `fn_create_tenant` ما بتعملش مفتاح تاني للمالك الجديد،
 * فكان بيتقفل بره النظام من البابين — العام لأنه صاحب صلاحية،
 * والسرّي لأنه بلا مفتاح.
 *
 * دلوقتي:
 *   PLATFORM_ADMIN  الباب السرّي + المفتاح التاني. إنت لوحدك.
 *   SUPER_ADMIN     صفحة الدخول العادية، بكود محله.
 *                   هو أعلى حساب **في محله**، مش في النظام.
 *
 * وكود المحل نفسه بيشتغل كعامل تمييز إضافي: الاسم لوحده مش كافي.
 */
const PRIVILEGED_ROLES: RoleKey[] = ['PLATFORM_ADMIN'];

/**
 * تسجيل الدخول.
 * ترتيب الفحوصات مقصود: الأرخص الأول (حدّ المحاولات) قبل الأغلى
 * (فحص كلمة المرور، وهو بطيء عمداً).
 */
export async function login(
  deps: AuthDeps,
  input: LoginInput,
  ctx: RequestContext,
): Promise<LoginResult> {
  const { users, sessions, hasher, tokens, clock, audit, rateLimiter } = deps;
  const now = clock.now();

  // 1) حدّ المحاولات لكل IP — بيمنع رشّ كلمات المرور على مئات الحسابات
  // ⚠ كود المحل جزء من مفتاح الحدّ.
  // من غيره، محل مزحوم عليه محاولات دخول كتير يقفل الباب على
  // كل المحلات التانية اللي جايّة من نفس شبكة المحمول.
  const tenantKey = input.tenantCode.trim().toLowerCase();
  const rateKey = `login:${tenantKey}:${ctx.ipAddress}`;
  const limit = LOGIN_POLICY.IP_RATE_LIMIT;
  const windowSec = LOGIN_POLICY.IP_RATE_WINDOW_SECONDS;

  const retryAfter = await rateLimiter.check(rateKey, limit, windowSec);
  if (retryAfter !== null) {
    await audit.record({
      action: 'auth.login.rate_limited',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: {
        tenantCode: input.tenantCode,
        username: input.username,
      },
    });
    throw Errors.rateLimited(retryAfter);
  }

  const user = await users.findByTenantAndUsername(
    input.tenantCode.trim(),
    input.username.trim().toLowerCase(),
  );

  // 2) مستخدم مش موجود
  // بننفّذ فحص وهمي بنفس التكلفة الزمنية عشان المهاجم ما يعرفش
  // من فرق زمن الرد إن الحساب موجود أصلاً (timing attack).
  if (!user || user.deletedAt) {
    await hasher.verify(DUMMY_HASH, input.password).catch(() => false);
    await audit.record({
      action: 'auth.login.unknown_user',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { tenantCode: input.tenantCode, username: input.username },
    });
    // ⚠ نفس الرسالة سواء المحل غلط أو الاسم غلط أو الاتنين.
    // لو فرّقنا، حد يقدر يعرف أنهي أكواد محلات موجودة عندنا.
    throw Errors.invalidCredentials('user not found');
  }

  // ══ الاشتراك موقوف ══
  //
  // ⚠ الفحص ده بعد ما نتأكد إن البيانات صح عن قصد.
  //
  // لو رفضنا قبل فحص كلمة المرور، أي حد يقدر يعرف أنهي محلات
  // موقوفة عندنا بمجرد تجربة الأكواد. والمعلومة دي مش من حقه.
  //
  // ورسالة الرفض مختلفة عن "بيانات غلط": صاحب المحل لازم يعرف
  // إن مشكلته في الاشتراك مش في كلمة المرور، وإلا هيقعد يجرّب
  // ويعيّط في الموظفين.
  if (!user.tenantActive) {
    await audit.record({
      actorId: user.id,
      action: 'auth.login.tenant_suspended',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { tenantCode: user.tenantCode },
    });
    throw Errors.accountInactive();
  }

  // 3) موقوف مؤقتاً
  if (user.lockedUntil && user.lockedUntil > now) throw Errors.accountLocked(user.lockedUntil);

  // 4) معطّل
  if (!user.isActive) {
    await audit.record({ actorId: user.id, action: 'auth.login.inactive', ipAddress: ctx.ipAddress });
    throw Errors.accountInactive();
  }

  // ══ 5) البوّابة السرّية اتلغت ══
  //
  // كان فيه فصل: المالك من رابط سرّي، والموظّف من الصفحة العامة.
  //
  // ده كان منطقي لما كان فيه مالك واحد في النظام كله. مع نظام
  // المحلات بقى فيه صاحب محل لكل عميل، وما ينفعش عشرين واحد
  // يشتركوا في نفس الرابط — ده مش قفل، ده مفتاح واحد متوزّع.
  //
  // والأسوأ إن `fn_create_tenant` ما بتعملش مفتاح تاني للمالك
  // الجديد، فكان بيتقفل بره النظام من البابين: العام لأنه صاحب
  // صلاحية، والسرّي لأنه بلا مفتاح.
  //
  // دلوقتي: باب واحد للكل، وكود المحل هو اللي بيفرّق.

  // 6) كلمة المرور
  if (!(await hasher.verify(user.passwordHash, input.password))) {
    await handleFailedAttempt(deps, user, now, ctx);
    throw Errors.invalidCredentials('bad password');
  }

  // ══ 7) المفتاح التاني — لمشغّل المنصّة وحده ══
  //
  // ⚠ الحساب ده بيتحكّم في اشتراكات كل المحلات: يفتح، يوقف،
  // ويغيّر حدودها. سرقته معناها إن كل عملائك يقفوا في نفس اللحظة.
  //
  // كلمة مرور واحدة مش كفاية لحساب بالحجم ده. والتكلفة عليك
  // بقت شبه صفر: الجلسة بتعيش 30 يوم، فالمفتاح بيتكتب مرة في
  // الشهر مش كل يوم.
  //
  // وصاحب المحل **مالوش** مفتاح تاني: هو أعلى حساب في محله، مش
  // في النظام. لو طلبناه منه، هيبقى سرّ زيادة على كل عميل يحفظه
  // ويضيّعه ويكلّمك عشانه.
  if (user.roleKey === 'PLATFORM_ADMIN') {
    if (!user.adminPasskeyHash) {
      throw Errors.internal('platform admin has no passkey configured');
    }

    const passkeyOk = input.adminPasskey
      ? await hasher.verify(user.adminPasskeyHash, input.adminPasskey)
      : false;

    if (!passkeyOk) {
      await handleFailedAttempt(deps, user, now, ctx);
      throw Errors.invalidCredentials('bad platform passkey');
    }
  }

  // 8) نجاح — صفّر العدّاد وافتح جلسة
  await users.clearLoginFailures(user.id, now);
  await rateLimiter.reset(rateKey);

  // ترقية صامتة للهاش لو رفعنا عدد اللفّات من إعدادات كلاودفلير
  if (hasher.needsRehash(user.passwordHash)) {
    await users.updatePasswordHash(user.id, await hasher.hash(input.password));
  }

  const refreshExpiresAt = new Date(now.getTime() + SESSION_POLICY.ABSOLUTE_SESSION_SECONDS * 1000);
  const { raw: refreshToken, digest } = await tokens.createRefreshToken();

  const session = await sessions.create({
    userId: user.id,
    refreshTokenHash: digest,
    expiresAt: refreshExpiresAt,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  const authUser = toAuthenticatedUser(user);
  const accessToken = await tokens.signAccessToken(
    {
      sub: user.id,
      sid: session.id,
      role: user.roleKey,
      branchId: user.branchId,
      perms: authUser.permissions,
      ver: 1,
    },
    SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS,
    deps.jwtSecret,
  );

  await audit.record({
    actorId: user.id,
    action: 'auth.login.success',
    entity: 'Session',
    entityId: session.id,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { tenantCode: user.tenantCode, roleKey: user.roleKey },
  });

  return {
    user: authUser,
    accessToken,
    refreshToken,
    accessTokenExpiresAt: new Date(now.getTime() + SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS * 1000),
    refreshTokenExpiresAt: refreshExpiresAt,
  };
}

/**
 * تجديد بطاقة الدخول.
 *
 * هنا بيتطبّق أهم شرط: الخروج بعد 10 دقايق خمول.
 * المرجع هو last_seen_at في قاعدة البيانات — مش مؤقّت في المتصفح.
 * تشبيه محاسبي: العبرة بالقيد في الدفتر، مش بكلام العميل.
 *
 * وكمان بنعمل "تدوير للتوكن": كل تجديد بيلغي القديم. لو توكن قديم
 * اتستخدم تاني، دي إشارة سرقة.
 */
export async function refreshSession(
  deps: AuthDeps,
  rawRefreshToken: string,
  ctx: RequestContext,
): Promise<LoginResult> {
  const { users, sessions, tokens, clock, audit } = deps;
  const now = clock.now();

  const digest = await tokens.digestRefreshToken(rawRefreshToken);
  const session = await sessions.findActiveByDigest(digest);

  if (!session) {
    await audit.record({
      action: 'auth.refresh.invalid_token',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    throw Errors.sessionExpired();
  }

  if (session.expiresAt <= now) {
    await sessions.revoke(session.id, 'absolute_expiry', now);
    throw Errors.sessionExpired();
  }

  // ترتيب مقصود: بنجيب المستخدم **قبل** تقييم الخمول، لأن القاعدة
  // نفسها بتعتمد على دوره (10 دقايق للمدير، 30 وقفل للموظف).
  const user = await users.findById(session.userId);
  if (!user || !user.isActive || user.deletedAt) {
    await sessions.revoke(session.id, 'user_disabled', now);
    throw Errors.sessionExpired();
  }

  await enforceIdlePolicy(deps, session, user.roleKey, now);

  const { raw: newRefresh, digest: newDigest } = await tokens.createRefreshToken();
  await sessions.rotate(session.id, newDigest, now);

  const authUser = toAuthenticatedUser(user);
  const accessToken = await tokens.signAccessToken(
    {
      sub: user.id,
      sid: session.id,
      role: user.roleKey,
      branchId: user.branchId,
      perms: authUser.permissions,
      ver: 1,
    },
    SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS,
    deps.jwtSecret,
  );

  return {
    user: authUser,
    accessToken,
    refreshToken: newRefresh,
    accessTokenExpiresAt: new Date(now.getTime() + SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS * 1000),
    refreshTokenExpiresAt: session.expiresAt,
  };
}

/** فحص الجلسة + تسجيل النشاط */
export async function checkSession(
  deps: AuthDeps,
  sessionId: string,
  userId: string,
  touch = true,
): Promise<AuthenticatedUser> {
  const { users, sessions, clock } = deps;
  const now = clock.now();

  const session = await sessions.findActiveById(sessionId);
  if (!session || session.userId !== userId) throw Errors.sessionExpired();

  if (session.expiresAt <= now) {
    await sessions.revoke(session.id, 'absolute_expiry', now);
    throw Errors.sessionExpired();
  }

  const user = await users.findById(userId);
  if (!user || !user.isActive || user.deletedAt) {
    await sessions.revoke(session.id, 'user_disabled', now);
    throw Errors.sessionExpired();
  }

  // ⚠ اشتراك المحل بيتفحص هنا، في **كل طلب**.
  //
  // من غير السطر ده، إيقاف اشتراك محل ما كانش هيبان غير بعد ما
  // جلسات موظفينه تنتهي — 30 يوم كاملة يشتغلوا فيها بعد ما
  // توقفهم. دلوقتي الإيقاف فوري.
  //
  // وده هو اللي بيعوّض إلغاء مهلة الخمول: الجلسة طويلة، لكن
  // صلاحيتها بتتراجع من الدفتر مع كل حركة.
  if (!user.tenantActive) {
    await sessions.revoke(session.id, 'tenant_suspended', now);
    throw Errors.accountInactive();
  }

  await enforceIdlePolicy(deps, session, user.roleKey, now);

  if (touch) await sessions.touch(session.id, now);

  return toAuthenticatedUser(user);
}

/**
 * قفل الشاشة يدويًا.
 * بينادها المتصفح لما مؤقّت الخمول يوصل للحد عند الموظّف، عشان
 * الخادم يعرف بالقفل فورًا مش يستنى الطلب الجاي.
 */
export async function lockSession(deps: AuthDeps, sessionId: string): Promise<void> {
  const now = deps.clock.now();
  const session = await deps.sessions.findActiveById(sessionId);
  if (!session) throw Errors.sessionExpired();
  if (session.lockedAt) return; // مقفولة أصلاً — عملية متسامحة

  await deps.sessions.lock(session.id, now);
  await deps.audit.record({
    actorId: session.userId,
    action: 'auth.session.locked_manual',
    entity: 'Session',
    entityId: session.id,
  });
}

/**
 * فكّ القفل بكلمة المرور.
 *
 * ══ ليه بيشتغل بتوكن التحديث مش ببطاقة الدخول؟ ══
 * بطاقة الدخول عمرها 5 دقايق. الشاشة ممكن تفضل مقفولة نص ساعة.
 * فالبطاقة أكيد منتهية وقت فكّ القفل. توكن التحديث (12 ساعة)
 * هو اللي لسه صالح، وهو المرسل تلقائيًا لمسارات /api/auth.
 *
 * بننفّذ حدّ محاولات هنا كمان — من غيره الشاشة المقفولة بتبقى
 * لوحة تخمين مفتوحة لأي حد ماسك الجهاز.
 */
export async function unlockSession(
  deps: AuthDeps,
  rawRefreshToken: string,
  password: string,
  ctx: RequestContext,
): Promise<LoginResult> {
  const { users, sessions, hasher, tokens, clock, audit, rateLimiter } = deps;
  const now = clock.now();

  const digest = await tokens.digestRefreshToken(rawRefreshToken);
  const session = await sessions.findActiveByDigest(digest);
  if (!session) throw Errors.sessionExpired();

  if (session.expiresAt <= now) {
    await sessions.revoke(session.id, 'absolute_expiry', now);
    throw Errors.sessionExpired();
  }

  const rateKey = `unlock:${session.id}`;
  const retryAfter = await rateLimiter.check(rateKey, 5, 5 * 60);
  if (retryAfter !== null) throw Errors.rateLimited(retryAfter);

  const user = await users.findById(session.userId);
  if (!user || !user.isActive || user.deletedAt) {
    await sessions.revoke(session.id, 'user_disabled', now);
    throw Errors.sessionExpired();
  }

  if (!(await hasher.verify(user.passwordHash, password))) {
    await audit.record({
      actorId: user.id,
      action: 'auth.unlock.failed',
      entity: 'Session',
      entityId: session.id,
      ipAddress: ctx.ipAddress,
    });
    throw Errors.invalidCredentials('bad unlock password');
  }

  // فك القفل + تصفير عدّاد الخمول في عملية واحدة
  await sessions.unlock(session.id, now);
  await rateLimiter.reset(rateKey);

  const { raw: newRefresh, digest: newDigest } = await tokens.createRefreshToken();
  await sessions.rotate(session.id, newDigest, now);

  const authUser = toAuthenticatedUser(user);
  const accessToken = await tokens.signAccessToken(
    {
      sub: user.id,
      sid: session.id,
      role: user.roleKey,
      branchId: user.branchId,
      perms: authUser.permissions,
      ver: 1,
    },
    SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS,
    deps.jwtSecret,
  );

  await audit.record({
    actorId: user.id,
    action: 'auth.unlock.success',
    entity: 'Session',
    entityId: session.id,
    ipAddress: ctx.ipAddress,
  });

  return {
    user: authUser,
    accessToken,
    refreshToken: newRefresh,
    accessTokenExpiresAt: new Date(now.getTime() + SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS * 1000),
    refreshTokenExpiresAt: session.expiresAt,
  };
}

/** الخروج عملية متسامحة: ما بتفشلش أبداً من وجهة نظر المستخدم */
export async function logout(
  deps: AuthDeps,
  sessionId: string | null,
  ctx: RequestContext,
): Promise<void> {
  if (!sessionId) return;

  const now = deps.clock.now();
  await deps.sessions.revoke(sessionId, 'user_logout', now);
  await deps.audit.record({
    action: 'auth.logout',
    entity: 'Session',
    entityId: sessionId,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
}

// ─────────── مساعدات داخلية ───────────

/**
 * تقييم الخمول حسب دور المستخدم.
 *
 * الدالة دي هي **المكان الوحيد** اللي بيقرر إيه اللي يحصل لجلسة
 * خاملة. refreshSession و checkSession الاتنين بينادوها، فمستحيل
 * يختلفوا في السلوك — وده بالظبط نوع الاختلاف اللي بيعمل ثغرات.
 *
 * بترمي الخطأ المناسب وبتنفّذ الأثر (إلغاء أو قفل)، أو بترجع بهدوء
 * لو الجلسة سليمة.
 */
async function enforceIdlePolicy(
  deps: AuthDeps,
  session: SessionRecord,
  roleKey: string,
  now: Date,
): Promise<void> {
  // الجلسة مقفولة من قبل؟ ما نلمسش حاجة — نقول مقفولة وخلاص.
  // مهم: **مش** بنلغيها، عشان فكّ القفل يفضل ممكن.
  if (session.lockedAt) throw Errors.sessionLocked();

  const rule = idleRuleFor(roleKey);

  // ⚠ صفر = المهلة معطّلة لهذا الدور. الآلية كلها تحت لسه شغّالة،
  // بس ما بتتنفّذش. رقم واحد في config.ts بيرجّعها.
  if (rule.seconds <= 0) return;

  const idleSeconds = (now.getTime() - session.lastSeenAt.getTime()) / 1000;
  if (idleSeconds <= rule.seconds) return;

  if (rule.action === 'LOCK') {
    await deps.sessions.lock(session.id, now);
    await deps.audit.record({
      actorId: session.userId,
      action: 'auth.session.locked',
      entity: 'Session',
      entityId: session.id,
      metadata: { idleSeconds: Math.round(idleSeconds), roleKey },
    });
    throw Errors.sessionLocked();
  }

  await deps.sessions.revoke(session.id, 'idle_timeout', now);
  await deps.audit.record({
    actorId: session.userId,
    action: 'auth.session.idle_timeout',
    entity: 'Session',
    entityId: session.id,
    metadata: { idleSeconds: Math.round(idleSeconds), roleKey },
  });
  throw Errors.idleTimeout();
}

/** هاش وهمي بنفس تكلفة الهاش الحقيقي — لتثبيت زمن الرد */
const DUMMY_HASH =
  'pbkdf2-sha256$100000$ZHVtbXlzYWx0MTIzNDU2$0mL3xQ9vK2nR7tY4wZ8aB5cD1eF6gH0iJ3kL9mN2oPQ';

async function handleFailedAttempt(
  deps: AuthDeps,
  user: UserRecord,
  now: Date,
  ctx: RequestContext,
): Promise<void> {
  const nextCount = user.failedLoginCount + 1;
  const shouldLock = nextCount >= LOGIN_POLICY.MAX_FAILED_ATTEMPTS;
  const lockUntil = shouldLock
    ? new Date(now.getTime() + LOGIN_POLICY.LOCK_DURATION_SECONDS * 1000)
    : null;

  await deps.users.registerFailedLogin(user.id, lockUntil);
  await deps.audit.record({
    actorId: user.id,
    action: shouldLock ? 'auth.login.locked' : 'auth.login.failed',
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { attempt: nextCount },
  });
}

function toAuthenticatedUser(user: UserRecord): AuthenticatedUser {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    roleKey: user.roleKey,
    branchId: user.branchId,
    tenantId: user.tenantId,
    tenantCode: user.tenantCode,
    tenantName: user.tenantName,
    permissions: user.permissions,
    mustChangePassword: user.mustChangePassword,
  };
}
