/**
 * التشفير — بـ Web Crypto فقط
 *
 * ══ ليه اتغيّر عن Argon2؟ ══
 * Argon2 مكتبة C++ أصلية. كلاودفلير بتشغّل V8 بس، من غير مكتبات أصلية.
 * تشبيه: جهاز ٢٢٠ فولت في مقبس ١١٠. الجهاز سليم، المكان مش بيشغّله.
 *
 * البديل: PBKDF2 — موجود **جوّه** كلاودفلير أصلاً، صفر مكتبات،
 * ومستحيل يفشل في البناء. معتمد من OWASP لتخزين كلمات المرور.
 *
 * ══ نفس الفكرة برضه ══
 * مفرمة اللحم: تُدخل قطعة فتخرج مفرومة، ومفيش زرّ يرجّعها.
 * والبطء متعمّد: إنت بتدفع الثمن مرة واحدة عند الدخول، أما اللي
 * عايز يجرّب مليار كلمة مرور فهيحتاج عمر.
 *
 * ══ ملاحظة مهمة عن حدّ المعالجة ══
 * الخطة المجانية في كلاودفلير بتدّي 10 مللي ثانية معالجة لكل طلب.
 * عدد اللفّات هنا مضبوط على 100,000 كتوازن. الخطة المدفوعة ($5/شهر)
 * بتدّي 30 ثانية، وساعتها ارفعه لـ 600,000 من wrangler.jsonc
 * من غير ما تلمس سطر كود واحد.
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { AccessTokenPayload, PasswordHasher, TokenService } from '../application/ports';
import { Errors } from '../domain/errors';

const encoder = new TextEncoder();
const ALGO_TAG = 'pbkdf2-sha256';
const KEY_BITS = 256;
const SALT_BYTES = 16;
const DEFAULT_ITERATIONS = 100_000;

// ─────────── تحويلات base64url ───────────

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// ─────────── مقارنة بزمن ثابت ───────────

/**
 * ليه مش بنستخدم === عادي؟
 * المقارنة العادية بتقف عند أول حرف مختلف، فوقت التنفيذ بيفضح
 * كام حرف كان صح. المقارنة دي بتفحص كل البايتات دايماً.
 *
 * كلاودفلير بتوفّر نسخة جاهزة، وبنرجع لنسخة يدوية لو مش موجودة.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (x: ArrayBufferView, y: ArrayBufferView) => boolean;
  };
  if (typeof subtle.timingSafeEqual === 'function') {
    return subtle.timingSafeEqual(a, b);
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ─────────── اشتقاق المفتاح ───────────

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    KEY_BITS,
  );

  return new Uint8Array(bits);
}

/**
 * صيغة التخزين:  pbkdf2-sha256$100000$<الملح>$<الناتج>
 *
 * ليه بنخزّن عدد اللفّات جوّه النص؟ عشان لو رفعناه بكرة تفضل
 * كلمات المرور القديمة شغّالة، والنظام يرقّيها بهدوء عند أول دخول.
 */
export function createHasher(iterations = DEFAULT_ITERATIONS): PasswordHasher {
  return {
    async hash(plain: string): Promise<string> {
      if (plain.length < 10) throw new Error('[crypto] كلمة المرور أقصر من 10 أحرف');
      if (plain.length > 1024) throw new Error('[crypto] كلمة المرور أطول من 1024 حرف');

      const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
      const derived = await derive(plain, salt, iterations);

      return `${ALGO_TAG}$${iterations}$${toBase64Url(salt)}$${toBase64Url(derived)}`;
    },

    async verify(stored: string, plain: string): Promise<boolean> {
      try {
        const [tag, iterText, saltText, hashText] = stored.split('$');
        if (tag !== ALGO_TAG) return false;

        const storedIterations = Number.parseInt(iterText, 10);
        if (!Number.isFinite(storedIterations) || storedIterations < 1000) return false;

        const salt = fromBase64Url(saltText);
        const expected = fromBase64Url(hashText);
        const actual = await derive(plain, salt, storedIterations);

        return constantTimeEqual(actual, expected);
      } catch {
        // هاش تالف أو بصيغة مش معروفة — نتعامل معاه كفشل عادي
        return false;
      }
    },

    needsRehash(stored: string): boolean {
      const [tag, iterText] = stored.split('$');
      if (tag !== ALGO_TAG) return true;
      return Number.parseInt(iterText, 10) < iterations;
    },
  };
}

// ─────────── توكن التحديث ───────────

/**
 * التوكن ده عشوائي بالكامل (256 بت) ومستحيل يتخمّن، فمش محتاج بطء
 * متعمّد — محتاج سرعة، لأننا بندوّر بيه في قاعدة البيانات كل تجديد.
 * فبنستخدم HMAC-SHA256 بدل PBKDF2.
 *
 * الـ pepper سرّ عايش في إعدادات كلاودفلير. لو قاعدة البيانات
 * اتسربت لوحدها، البصمات المخزّنة فيها تبقى بلا فايدة.
 */
export function createTokenService(pepper: string): TokenService {
  if (!pepper || pepper.length < 32) {
    throw new Error('[crypto] REFRESH_TOKEN_PEPPER مفقود أو أقصر من 32 حرف');
  }

  let hmacKey: CryptoKey | null = null;

  async function getKey(): Promise<CryptoKey> {
    if (hmacKey) return hmacKey;
    hmacKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(pepper),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    return hmacKey;
  }

  async function digestRefreshToken(raw: string): Promise<string> {
    const signature = await crypto.subtle.sign('HMAC', await getKey(), encoder.encode(raw));
    return toBase64Url(new Uint8Array(signature));
  }

  return {
    signAccessToken,
    verifyAccessToken,
    digestRefreshToken,

    async createRefreshToken() {
      const raw = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
      return { raw, digest: await digestRefreshToken(raw) };
    },
  };
}

/** معرّف عشوائي — بديل cuid()، مبني على المتاح في كلاودفلير */
export function newId(): string {
  return crypto.randomUUID();
}


// ═══════════════════════════════════════════════════════════
//  بطاقة الدخول (JWT)
//
//  تشبيه: بطاقة الحصة اليومية. مكتوب عليها اسمك وحزامك وساعة
//  انتهائها، وعليها ختم محدش يقدر يقلّده. الحارس بيقرأها ويفحص
//  الختم فوراً من غير ما يتصل بالإدارة.
//
//  ⚠ البطاقة مقروءة للكل (موقّعة، مش مشفّرة). متحطّش فيها أي سرّ.
// ═══════════════════════════════════════════════════════════

const ISSUER = 'pos-system';
const AUDIENCE = 'pos-client';
const encoder = new TextEncoder();

export async function signAccessToken(
  payload: AccessTokenPayload,
  ttlSeconds: number,
  secret: string,
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);

  return new SignJWT({ ...payload } as unknown as JWTPayload)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(nowSec)
    .setNotBefore(nowSec)
    .setExpirationTime(nowSec + ttlSeconds)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .sign(encoder.encode(secret));
}

export async function verifyAccessToken(
  token: string,
  secret: string,
): Promise<AccessTokenPayload> {
  try {
    const { payload } = await jwtVerify(token, encoder.encode(secret), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'], // تثبيت الخوارزمية بيمنع هجوم "alg: none"
      clockTolerance: 5,
    });

    const { sub, sid, role, branchId, perms, ver } = payload as unknown as AccessTokenPayload;
    if (!sub || !sid || !role || !Array.isArray(perms)) throw Errors.unauthenticated();

    return { sub, sid, role, branchId: branchId ?? null, perms, ver: ver ?? 1 };
  } catch {
    // مش بنفرّق بين "منتهية" و"مزوّرة" في الرسالة الظاهرة
    throw Errors.sessionExpired();
  }
}
