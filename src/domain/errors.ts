/**
 * أخطاء المجال (Domain Errors)
 *
 * تشبيه: بدل أن يصرخ الحكم "خطأ!" بشكل غامض، عنده قائمة مخالفات
 * مرقّمة ومعروفة مسبقاً. كل خطأ هنا له كود ثابت + رسالة عربية آمنة
 * للعرض للمستخدم + كود HTTP مناسب.
 *
 * قاعدة أمنية مهمة: رسالة الخطأ للمستخدم لا تكشف أسراراً.
 * "اسم المستخدم غير موجود" تخبر المهاجم أنه اقترب. لذلك نقول دائماً
 * "بيانات الدخول غير صحيحة" مهما كان السبب الحقيقي.
 */

export type ErrorCode =
  | 'INVALID_CREDENTIALS'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_INACTIVE'
  | 'SESSION_EXPIRED'
  | 'SESSION_IDLE_TIMEOUT'
  | 'SESSION_LOCKED'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'RATE_LIMITED'
  | 'VALIDATION_ERROR'
  | 'NOT_FOUND'
  | 'INTERNAL_ERROR';

export class AppError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly httpStatus: number,
    /** رسالة آمنة للعرض للمستخدم النهائي */
    public readonly userMessage: string,
    /** تفاصيل داخلية للـ logs فقط — لا تُرسل للمتصفح أبداً */
    public readonly internalDetail?: string,
    public readonly meta?: Record<string, unknown>,
  ) {
    super(`${code}: ${internalDetail ?? userMessage}`);
    this.name = 'AppError';
  }
}

export const Errors = {
  invalidCredentials: (detail?: string) =>
    new AppError('INVALID_CREDENTIALS', 401, 'بيانات الدخول غير صحيحة.', detail),

  accountLocked: (until: Date) =>
    new AppError(
      'ACCOUNT_LOCKED',
      423,
      'الحساب موقوف مؤقتاً بسبب محاولات دخول متكرّرة. حاول لاحقاً.',
      `locked until ${until.toISOString()}`,
      { until: until.toISOString() },
    ),

  accountInactive: () =>
    new AppError('ACCOUNT_INACTIVE', 403, 'هذا الحساب غير مفعّل. راجع الإدارة.'),

  sessionExpired: () =>
    new AppError('SESSION_EXPIRED', 401, 'انتهت الجلسة. سجّل الدخول من جديد.'),

  idleTimeout: () =>
    new AppError('SESSION_IDLE_TIMEOUT', 401, 'تم إنهاء الجلسة لعدم النشاط. سجّل الدخول من جديد.'),

  /**
   * الشاشة مقفولة — الجلسة **لسه حيّة**.
   * كود 423 مش 401 عشان الواجهة تفرّق: 401 يعني روح لصفحة الدخول،
   * 423 يعني اعرض شاشة فكّ القفل والحالة محفوظة.
   *
   * ⚠ مهم: الكوكيز **ما بتتمسحش** مع الخطأ ده — من غيرها مفيش
   * طريقة نفكّ القفل أصلاً.
   */
  sessionLocked: () =>
    new AppError('SESSION_LOCKED', 423, 'الشاشة مقفولة. اكتب كلمة المرور للمتابعة.'),

  unauthenticated: () =>
    new AppError('UNAUTHENTICATED', 401, 'يجب تسجيل الدخول أولاً.'),

  forbidden: (missing?: string) =>
    new AppError('FORBIDDEN', 403, 'لا تملك صلاحية تنفيذ هذا الإجراء.', `missing permission: ${missing}`),

  rateLimited: (retryAfterSec: number) =>
    new AppError('RATE_LIMITED', 429, 'محاولات كثيرة جداً. انتظر قليلاً ثم أعد المحاولة.', undefined, {
      retryAfterSec,
    }),

  validation: (userMessage: string, detail?: string) =>
    new AppError('VALIDATION_ERROR', 422, userMessage, detail),

  notFound: (what = 'العنصر') => new AppError('NOT_FOUND', 404, `${what} غير موجود.`),

  internal: (detail?: string) =>
    new AppError('INTERNAL_ERROR', 500, 'حدث خطأ غير متوقّع. حاول مرة أخرى.', detail),
};
