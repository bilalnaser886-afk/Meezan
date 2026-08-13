/**
 * التوصيلات (Runtime Wiring)
 *
 * الملف ده فيه حاجتين بيشتغلوا مع بعض:
 *
 *  1) نقطة التجميع — بتوصّل العقود بالأدوات الحقيقية
 *     تشبيه: غرفة المعدّات. المدرّب طلب "جهاز قياس نبض"،
 *     وهنا بنحطّ الجهاز الفعلي في إيده.
 *
 *  2) أدوات HTTP — الكوكيز، سياق الطلب، وتوحيد الأخطاء
 *     تشبيه: مكتب الاستقبال. بيستلم ويسلّم ويكتب الأوراق.
 */

import type { Context } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import type { AuthDeps } from '../application/use-cases/auth';
import type { AnnouncementDeps } from '../application/use-cases/announcements';
import type { UserDeps } from '../application/use-cases/users';
import type { BranchRepository } from '../application/ports';
import { AppError, Errors } from '../domain/errors';
import { COOKIES, SESSION_POLICY, type Env } from '../domain/config';
import type { RequestContext } from '../application/use-cases/auth';
import { createHasher, createTokenService } from '../infrastructure/crypto';
import {
  createAnnouncementRepository,
  createAuditLogger,
  createBranchRepository,
  createDb,
  createRateLimiter,
  createSessionRepository,
  createUserRepository,
} from '../infrastructure/database';

// ═══════════════ 1) نقطة التجميع ═══════════════
const systemClock = { now: () => new Date() };

export interface Container {
  auth: AuthDeps;
  announcements: AnnouncementDeps;
  users: UserDeps;
  branches: BranchRepository;
  db: ReturnType<typeof createDb>;
}

export function buildContainer(env: Env): Container {
  const db = createDb(env);
  const audit = createAuditLogger(db);
  const iterations = Number.parseInt(env.PBKDF2_ITERATIONS ?? '100000', 10);
  const hasher = createHasher(Number.isFinite(iterations) ? iterations : 100_000);
  const userRepo = createUserRepository(db);
  const branchRepo = createBranchRepository(db);

  return {
    db,
    auth: {
      users: userRepo,
      sessions: createSessionRepository(db),
      hasher,
      tokens: createTokenService(env.REFRESH_TOKEN_PEPPER),
      clock: systemClock,
      audit,
      rateLimiter: createRateLimiter(db),
      jwtSecret: env.JWT_SECRET,
    },
    announcements: {
      announcements: createAnnouncementRepository(db),
      clock: systemClock,
      audit,
    },
    users: {
      users: userRepo,
      branches: branchRepo,
      hasher,
      clock: systemClock,
      audit,
    },
    branches: branchRepo,
  };
}


// ═══════════════ 2) أدوات HTTP ═══════════════
/** كلاودفلير بتحطّ IP الحقيقي في الهيدر ده ومش ممكن يتزوّر */
export function getRequestContext(c: Context): RequestContext {
  return {
    ipAddress:
      c.req.header('CF-Connecting-IP') ??
      c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ??
      null,
    userAgent: c.req.header('user-agent') ?? null,
  };
}

export function setAuthCookies(
  c: Context,
  tokens: { accessToken: string; refreshToken: string },
): void {
  const isLocal = new URL(c.req.url).hostname === 'localhost';

  setCookie(c, COOKIES.ACCESS, tokens.accessToken, {
    httpOnly: true,        // ← JavaScript مش قادرة توصله خالص
    secure: !isLocal,      // HTTPS بس (كلاودفلير بتديك HTTPS تلقائي)
    sameSite: 'Lax',       // بيمنع إرسال الكوكي مع طلبات مواقع تانية
    path: '/',
    maxAge: SESSION_POLICY.ACCESS_TOKEN_TTL_SECONDS,
  });

  // توكن التحديث بيتبعت لمسار التجديد بس — تقليل مساحة التعرّض
  setCookie(c, COOKIES.REFRESH, tokens.refreshToken, {
    httpOnly: true,
    secure: !isLocal,
    sameSite: 'Lax',
    path: '/api/auth',
    maxAge: SESSION_POLICY.ABSOLUTE_SESSION_SECONDS,
  });
}

export function clearAuthCookies(c: Context): void {
  deleteCookie(c, COOKIES.ACCESS, { path: '/' });
  deleteCookie(c, COOKIES.REFRESH, { path: '/api/auth' });
}

/**
 * تحويل أي خطأ لرد JSON موحّد.
 *
 * القاعدة: المستخدم بيشوف رسالة عربية واضحة وكود ثابت.
 * التفاصيل الداخلية (اسم جدول، نص استعلام) بتروح للوق بس.
 * تسريبها بيدّي المهاجم خريطة نظامك.
 */
export function errorResponse(c: Context, error: unknown): Response {
  if (error instanceof AppError) {
    if (error.httpStatus >= 500) console.error('[error]', error.code, error.internalDetail);

    if (error.code === 'SESSION_EXPIRED' || error.code === 'SESSION_IDLE_TIMEOUT') {
      clearAuthCookies(c);
    }
    if (error.code === 'RATE_LIMITED' && typeof error.meta?.retryAfterSec === 'number') {
      c.header('Retry-After', String(error.meta.retryAfterSec));
    }

    return c.json(
      { ok: false, error: { code: error.code, message: error.userMessage, ...error.meta } },
      error.httpStatus as 400,
    );
  }

  console.error('[error] خطأ غير متوقّع:', error);
  const fallback = Errors.internal();
  return c.json(
    { ok: false, error: { code: fallback.code, message: fallback.userMessage } },
    500,
  );
}

/** قراءة JSON بأمان — طلب فاضي أو تالف ما يصحّش يوقّع الخادم */
export async function readJson<T>(c: Context): Promise<T> {
  try {
    const body = await c.req.json();
    if (!body || typeof body !== 'object') throw new Error('not an object');
    return body as T;
  } catch {
    throw Errors.validation('صيغة الطلب غير صحيحة.');
  }
}
