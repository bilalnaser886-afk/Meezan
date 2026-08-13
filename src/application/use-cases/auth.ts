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
import { LOGIN_POLICY, SESSION_POLICY } from '../../domain/config';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  PasswordHasher,
  RateLimiter,
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
  username: string;
  password: string;
  /** المفتاح التاني — مطلوب بس من بوّابة المالك */
  adminPasskey?: string;
  /** true لما الطلب جاي من المسار السرّي */
  viaAdminGate: boolean;
}

export interface LoginResult {
  user: AuthenticatedUser;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

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
  const rateKey = input.viaAdminGate ? `login:admin:${ctx.ipAddress}` : `login:${ctx.ipAddress}`;
  const limit = input.viaAdminGate ? LOGIN_POLICY.ADMIN_IP_RATE_LIMIT : LOGIN_POLICY.IP_RATE_LIMIT;
  const windowSec = input.viaAdminGate
    ? LOGIN_POLICY.ADMIN_IP_RATE_WINDOW_SECONDS
    : LOGIN_POLICY.IP_RATE_WINDOW_SECONDS;

  const retryAfter = await rateLimiter.check(rateKey, limit, windowSec);
  if (retryAfter !== null) {
    await audit.record({
      action: 'auth.login.rate_limited',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { username: input.username, viaAdminGate: input.viaAdminGate },
    });
    throw Errors.rateLimited(retryAfter);
  }

  const user = await users.findByUsername(input.username.trim().toLowerCase());

  // 2) مستخدم مش موجود
  // بننفّذ فحص وهمي بنفس التكلفة الزمنية عشان المهاجم ما يعرفش
  // من فرق زمن الرد إن الحساب موجود أصلاً (timing attack).
  if (!user || user.deletedAt) {
    await hasher.verify(DUMMY_HASH, input.password).catch(() => false);
    await audit.record({
      action: 'auth.login.unknown_user',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      metadata: { username: input.username },
    });
    throw Errors.invalidCredentials('user not found');
  }

  // 3) موقوف مؤقتاً
  if (user.lockedUntil && user.lockedUntil > now) throw Errors.accountLocked(user.lockedUntil);

  // 4) معطّل
  if (!user.isActive) {
    await audit.record({ actorId: user.id, action: 'auth.login.inactive', ipAddress: ctx.ipAddress });
    throw Errors.accountInactive();
  }

  // 5) البوّابة الصح للدور الصح
  //    المالك ما بيدخلش من باب الموظفين، والموظف ما بيدخلش من الباب السرّي.
  if (input.viaAdminGate && user.roleKey !== 'SUPER_ADMIN') {
    await audit.record({
      actorId: user.id,
      action: 'auth.login.wrong_gate',
      ipAddress: ctx.ipAddress,
      metadata: { attemptedGate: 'admin', actualRole: user.roleKey },
    });
    throw Errors.invalidCredentials('non-admin at admin gate');
  }
  if (!input.viaAdminGate && user.roleKey === 'SUPER_ADMIN') {
    throw Errors.invalidCredentials('admin at public gate');
  }

  // 6) كلمة المرور
  if (!(await hasher.verify(user.passwordHash, input.password))) {
    await handleFailedAttempt(deps, user, now, ctx);
    throw Errors.invalidCredentials('bad password');
  }

  // 7) المفتاح التاني للمالك
  if (input.viaAdminGate) {
    if (!user.adminPasskeyHash) throw Errors.internal('super admin has no passkey configured');

    const passkeyOk = input.adminPasskey
      ? await hasher.verify(user.adminPasskeyHash, input.adminPasskey)
      : false;

    if (!passkeyOk) {
      await handleFailedAttempt(deps, user, now, ctx);
      throw Errors.invalidCredentials('bad admin passkey');
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
    metadata: { viaAdminGate: input.viaAdminGate },
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

  const idleSeconds = (now.getTime() - session.lastSeenAt.getTime()) / 1000;
  if (idleSeconds > SESSION_POLICY.IDLE_TIMEOUT_SECONDS) {
    await sessions.revoke(session.id, 'idle_timeout', now);
    await audit.record({
      actorId: session.userId,
      action: 'auth.session.idle_timeout',
      entity: 'Session',
      entityId: session.id,
      metadata: { idleSeconds: Math.round(idleSeconds) },
    });
    throw Errors.idleTimeout();
  }

  const user = await users.findById(session.userId);
  if (!user || !user.isActive || user.deletedAt) {
    await sessions.revoke(session.id, 'user_disabled', now);
    throw Errors.sessionExpired();
  }

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

  const idleSeconds = (now.getTime() - session.lastSeenAt.getTime()) / 1000;
  if (idleSeconds > SESSION_POLICY.IDLE_TIMEOUT_SECONDS) {
    await sessions.revoke(session.id, 'idle_timeout', now);
    throw Errors.idleTimeout();
  }

  const user = await users.findById(userId);
  if (!user || !user.isActive || user.deletedAt) {
    await sessions.revoke(session.id, 'user_disabled', now);
    throw Errors.sessionExpired();
  }

  if (touch) await sessions.touch(session.id, now);

  return toAuthenticatedUser(user);
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
    permissions: user.permissions,
    mustChangePassword: user.mustChangePassword,
  };
}
