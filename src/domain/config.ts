/**
 * إعدادات النظام
 *
 * تشبيه: لافتة الشروط على حيطة النادي — مدة الجولة، عدد الإنذارات
 * قبل الإيقاف، وقت الراحة. مكان واحد الكل بيقرأ منه.
 */

export const SESSION_POLICY = {
  /**
   * المهلة الافتراضية — تُستخدم كحد أقصى وكقيمة احتياطية.
   * القيمة الفعلية لكل دور في IDLE_POLICY تحت.
   */
  IDLE_TIMEOUT_SECONDS: 10 * 60,
  /** عمر بطاقة الدخول قصير عمداً: لو اتسرقت، بتموت بسرعة */
  ACCESS_TOKEN_TTL_SECONDS: 5 * 60,
  /** السقف المطلق للجلسة مهما كان المستخدم نشط */
  ABSOLUTE_SESSION_SECONDS: 12 * 60 * 60,
  /** تحذير المستخدم قبل انتهاء المهلة بالمدة دي */
  IDLE_WARNING_SECONDS: 60,
} as const;

/**
 * سياسة الخمول حسب الدور.
 *
 * ══ ليه مش رقم واحد للكل؟ ══
 * العشر دقايق ممتازة للوحة المالك — بيانات حسّاسة وشاشة ممكن
 * تتساب مفتوحة في مكتب.
 *
 * لكنها مؤلمة على الكاشير: موظّف بيخدم زبون بيختار بين تلات موديلات
 * وبيسأل ويقلّب، ممكن يعدّي عشر دقايق من غير ما يلمس الشاشة —
 * وفجأة يلاقي نفسه اتطرد والسلة ضاعت قدّام الزبون.
 *
 * ══ الفرق بين LOGOUT و LOCK ══
 *   LOGOUT = الجلسة بتموت. لازم دخول كامل من الأول.
 *   LOCK   = الجلسة بتفضل حيّة في الخادم، الشاشة بس بتتغطّي.
 *            بيفكّها بكلمة المرور، والصفحة بحالتها زي ما هي.
 *
 * تشبيه: الأول زي ما الحكم يوقف النزال ويطلّعك بره الحلبة.
 * التاني زي وقت مستقطع — إنت لسه في الحلبة، بس واقف.
 */
export type IdleAction = 'LOGOUT' | 'LOCK';

export interface IdleRule {
  seconds: number;
  action: IdleAction;
}

export const IDLE_POLICY: Record<'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF', IdleRule> = {
  SUPER_ADMIN: { seconds: 10 * 60, action: 'LOGOUT' },
  BRANCH_MANAGER: { seconds: 10 * 60, action: 'LOGOUT' },
  STAFF: { seconds: 30 * 60, action: 'LOCK' },
};

/** قاعدة الخمول لدور معيّن — بترجع الأصرم لو الدور مش معروف */
export function idleRuleFor(roleKey: string): IdleRule {
  return (
    IDLE_POLICY[roleKey as keyof typeof IDLE_POLICY] ?? {
      seconds: SESSION_POLICY.IDLE_TIMEOUT_SECONDS,
      action: 'LOGOUT' as const,
    }
  );
}

export const LOGIN_POLICY = {
  MAX_FAILED_ATTEMPTS: 5,
  LOCK_DURATION_SECONDS: 15 * 60,
  IP_RATE_LIMIT: 20,
  IP_RATE_WINDOW_SECONDS: 5 * 60,
  /** بوّابة المالك أضيق بكتير */
  ADMIN_IP_RATE_LIMIT: 5,
  ADMIN_IP_RATE_WINDOW_SECONDS: 15 * 60,
} as const;

export const COOKIES = {
  ACCESS: 'pos_at',
  REFRESH: 'pos_rt',
} as const;

/** متغيّرات كلاودفلير — بتتضبط من لوحة التحكم مش من الكود */
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_KEY: string;
  JWT_SECRET: string;
  REFRESH_TOKEN_PEPPER: string;
  SUPER_ADMIN_PATH: string;
  SUPER_ADMIN_ALLOWED_IPS?: string;
  SETUP_SECRET?: string;
  PBKDF2_ITERATIONS?: string;
}

/**
 * التحقّق من المتغيّرات عند أول طلب.
 * الهدف: رسالة خطأ واضحة بدل انهيار غامض وسط يوم شغل.
 */
export function assertEnv(env: Env): void {
  const missing: string[] = [];

  if (!env.SUPABASE_URL) missing.push('SUPABASE_URL');
  if (!env.SUPABASE_SERVICE_KEY) missing.push('SUPABASE_SERVICE_KEY');
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) missing.push('JWT_SECRET (32 حرف على الأقل)');
  if (!env.REFRESH_TOKEN_PEPPER || env.REFRESH_TOKEN_PEPPER.length < 32) {
    missing.push('REFRESH_TOKEN_PEPPER (32 حرف على الأقل)');
  }
  if (!env.SUPER_ADMIN_PATH || env.SUPER_ADMIN_PATH.length < 8) {
    missing.push('SUPER_ADMIN_PATH (8 أحرف على الأقل)');
  }

  if (missing.length > 0) {
    throw new Error(
      `متغيّرات ناقصة في إعدادات كلاودفلير:\n  ${missing.join('\n  ')}\n` +
        `اضبطها من: Cloudflare ← مشروعك ← Settings ← Variables and Secrets`,
    );
  }

  // الغلطة الأشهر: حطّ مفتاح anon مكان service_role.
  // بيبان زي بعض بالظبط (الاتنين JWT طويل)، والفرق جوّه بس.
  // من غير الفحص ده هتقضّي ساعات في أخطاء "permission denied" غامضة.
  const role = jwtRole(env.SUPABASE_SERVICE_KEY);
  if (role && role !== 'service_role') {
    throw new Error(
      `SUPABASE_SERVICE_KEY فيه مفتاح "${role}" مش "service_role".\n` +
        `المفتاح ده مش هيقدر يقرأ حاجة لأن كل الجداول مقفولة بـ RLS.\n` +
        `هاته من: Supabase ← Settings ← API ← service_role`,
    );
  }
}

/**
 * قراءة الدور من جوّه مفتاح سوبابيز.
 *
 * المفتاح ده JWT — يعني **مقروء للكل**، موقّع مش مشفّر.
 * إحنا بنقرأ منه بس، ما بنتحقّقش من ختمه (سوبابيز هي اللي بتعمل كده).
 */
export function jwtRole(token: string): string | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;

    const padded = part.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const payload = JSON.parse(json) as { role?: string };

    return payload.role ?? null;
  } catch {
    // مفاتيح سوبابيز الجديدة (sb_secret_...) مش JWT — مفيش دور نقراه
    return null;
  }
}

export function superAdminPath(env: Env): string {
  return env.SUPER_ADMIN_PATH.replace(/^\/+/, '');
}
