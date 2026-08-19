/**
 * إعدادات النظام
 *
 * تشبيه: لافتة الشروط على حيطة النادي — مدة الجولة، عدد الإنذارات
 * قبل الإيقاف، وقت الراحة. مكان واحد الكل بيقرأ منه.
 */

export const SESSION_POLICY = {
  /**
   * مهلة الخمول. **صفر = معطّلة**.
   *
   * ══ ⚠ قرار اتاخد بوعي، والمقايضة مكتوبة هنا عشان تفضل مقروءة ══
   *
   * كانت 10 دقايق. المشكلة إن النظام بيتفتح من موبايل، والموظّف
   * بيسيب الصفحة ويرجع كل شوية — فكان بيلاقي شاشة دخول كل مرة،
   * وده بيخلّيه يكتب كلمة مروره عشرين مرة في اليوم قدّام الزبائن.
   * وكلمة السر اللي بتتكتب عشرين مرة قدّام الناس بتبقى معروفة.
   *
   * ══ اللي ضاع بالقرار ده ══
   * موبايل مفتوح ومتساب على الكاشير = وصول كامل لأي حد يمسكه.
   * قفل الجهاز نفسه بقى هو الحاجز الوحيد.
   *
   * ══ اللي فضل شغّال ══
   *   • تعطيل حساب بيقطع جلساته **فورًا**، مش بعد انتهاء المهلة
   *   • إيقاف اشتراك محل بيقطع جلسات موظفينه فورًا
   *   • كل طلب بيتفحص في قاعدة البيانات، مش في البطاقة
   *
   * ══ لو حبيت ترجّعها ══
   * غيّر الرقم في IDLE_POLICY تحت للدور اللي عايزه. سطر واحد،
   * والآلية كلها لسه موجودة وشغّالة — مش متشالة.
   */
  IDLE_TIMEOUT_SECONDS: 0,

  /**
   * عمر بطاقة الدخول.
   *
   * ══ ليه بقى طويل؟ ══
   * كان 5 دقايق، والفكرة كانت: لو البطاقة اتسرقت، تموت بسرعة.
   *
   * لكن ده كان بيعمل مشكلة أكبر من اللي بيحلّها: الكوكي نفسه كان
   * بيختفي من المتصفح بعد 5 دقايق، فأي رجوع للصفحة بعد الوقت ده
   * = شاشة دخول. حتى من غير أي مهلة خمول.
   *
   * ⚠ والقِصر ما كانش بيحمي كتير أصلاً: **كل طلب** بيروح لقاعدة
   * البيانات ويتأكد إن الجلسة لسه حيّة والمستخدم لسه مفعّل والمحل
   * لسه مشترك. فالبطاقة مش مصدر الصلاحية — هي بطاقة تعريف بس،
   * والدفتر هو الحَكَم.
   *
   * يعني بطاقة مسروقة بتموت لحظة ما تعطّل الحساب، مش بعد 5 دقايق.
   */
  ACCESS_TOKEN_TTL_SECONDS: 30 * 24 * 60 * 60,

  /** السقف المطلق للجلسة. بعده لازم دخول من الأول. */
  ABSOLUTE_SESSION_SECONDS: 30 * 24 * 60 * 60,

  /** تحذير المستخدم قبل انتهاء المهلة بالمدة دي (لو المهلة مفعّلة) */
  IDLE_WARNING_SECONDS: 60,
} as const;

/**
 * سياسة الخمول حسب الدور.
 *
 * ══ الفرق بين LOGOUT و LOCK ══
 *   LOGOUT = الجلسة بتموت. لازم دخول كامل من الأول.
 *   LOCK   = الجلسة بتفضل حيّة في الخادم، الشاشة بس بتتغطّي.
 *            بيفكّها بكلمة المرور، والصفحة بحالتها زي ما هي.
 *
 * تشبيه: الأول زي ما الحكم يوقف النزال ويطلّعك بره الحلبة.
 * التاني زي وقت مستقطع — إنت لسه في الحلبة، بس واقف.
 *
 * ⚠ كلهم صفر دلوقتي = مفيش قفل ولا خروج تلقائي.
 * الآلية موجودة وشغّالة؛ لو حطّيت رقم لأي دور، بتشتغل عنده على
 * طول من غير أي تعديل تاني.
 *
 * ولو رجّعتها لدور واحد، خلّيه STAFF بـ LOCK: الكاشير هو اللي
 * جهازه بيتساب على الترابيزة، والقفل بيحافظ على السلة اللي في
 * إيده بدل ما تضيع قدّام الزبون.
 */
export type IdleAction = 'LOGOUT' | 'LOCK';

export interface IdleRule {
  /** صفر = معطّلة لهذا الدور */
  seconds: number;
  action: IdleAction;
}

export const IDLE_POLICY: Record<
  'PLATFORM_ADMIN' | 'SUPER_ADMIN' | 'BRANCH_MANAGER' | 'STAFF',
  IdleRule
> = {
  PLATFORM_ADMIN: { seconds: 0, action: 'LOCK' },
  SUPER_ADMIN: { seconds: 0, action: 'LOCK' },
  BRANCH_MANAGER: { seconds: 0, action: 'LOCK' },
  STAFF: { seconds: 0, action: 'LOCK' },
};

/** قاعدة الخمول لدور معيّن — بترجع الأصرم لو الدور مش معروف */
export function idleRuleFor(roleKey: string): IdleRule {
  return (
    IDLE_POLICY[roleKey as keyof typeof IDLE_POLICY] ?? {
      seconds: SESSION_POLICY.IDLE_TIMEOUT_SECONDS,
      action: 'LOCK' as const,
    }
  );
}

export const LOGIN_POLICY = {
  MAX_FAILED_ATTEMPTS: 5,
  LOCK_DURATION_SECONDS: 15 * 60,
  IP_RATE_LIMIT: 20,
  IP_RATE_WINDOW_SECONDS: 5 * 60,
} as const;

export const COOKIES = {
  ACCESS: 'pos_at',
  REFRESH: 'pos_rt',
} as const;

/**
 * متغيّرات كلاودفلير — بتتضبط من لوحة التحكم مش من الكود.
 *
 * ⚠ SUPER_ADMIN_PATH و SUPER_ADMIN_ALLOWED_IPS اتشالوا.
 * كانوا للبوّابة السرّية، والبوّابة دي اتلغت: مع نظام المحلات بقى
 * فيه صاحب محل لكل عميل، وما ينفعش كلهم يشتركوا في نفس الرابط
 * السرّي — ده مش قفل، ده مفتاح واحد متوزّع على كل الناس.
 *
 * تقدر تمسحهم من إعدادات كلاودفلير؛ النظام مش بيقراهم.
 */
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_KEY: string;
  JWT_SECRET: string;
  REFRESH_TOKEN_PEPPER: string;
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
