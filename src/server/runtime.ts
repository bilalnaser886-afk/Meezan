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
import type { BranchDeps } from '../application/use-cases/branches';
import type { TreasuryDeps } from '../application/use-cases/treasury';
import type { ProductDeps } from '../application/use-cases/products';
import type { SaleDeps } from '../application/use-cases/sales';
import type { ReturnDeps } from '../application/use-cases/returns';
import type { ReportDeps } from '../application/use-cases/reports';
import type { AlertDeps } from '../application/use-cases/alerts';
import type { TransferDeps } from '../application/use-cases/transfers';
import type { SupplierDeps } from '../application/use-cases/suppliers';
import type { ShopDeps } from '../application/use-cases/shops';
import type { MaintenanceDeps } from '../application/use-cases/maintenance';
import type { CustomerDeps } from '../application/use-cases/customers';
import type { PlatformDeps } from '../application/use-cases/platform';
import type { PurchaseDeps } from '../application/use-cases/purchases';
import type { ClosingDeps } from '../application/use-cases/closings';
import type { BranchRepository } from '../application/ports';
import { AppError, Errors } from '../domain/errors';
import { COOKIES, SESSION_POLICY, type Env } from '../domain/config';
import type { RequestContext } from '../application/use-cases/auth';
import { createHasher, createTokenService } from '../infrastructure/crypto';
import {
  createAnnouncementRepository,
  createAuditLogger,
  createBranchRepository,
  createCategoryRepository,
  createColorRepository,
  createModelRepository,
  createCustomerRepository,
  createDb,
  createExpenseReasonRepository,
  createMovementRepository,
  createProductRepository,
  createRateLimiter,
  createAlertRepository,
  createClosingRepository,
  createMaintenanceRepository,
  createPurchaseRepository,
  createWarrantyRepository,
  createShopRepository,
  createSupplierRepository,
  createTransferRepository,
  createReportRepository,
  createReturnRepository,
  createSaleRepository,
  createSessionRepository,
  createTenantRepository,
  createTreasuryRepository,
  createUserRepository,
} from '../infrastructure/database';

// ═══════════════ 1) نقطة التجميع ═══════════════
const systemClock = { now: () => new Date() };

export interface Container {
  auth: AuthDeps;
  announcements: AnnouncementDeps;
  users: UserDeps;
  branchOps: BranchDeps;
  treasury: TreasuryDeps;
  products: ProductDeps;
  sales: SaleDeps;
  returns: ReturnDeps;
  reports: ReportDeps;
  alerts: AlertDeps;
  transfers: TransferDeps;
  suppliers: SupplierDeps;
  shops: ShopDeps;
  maintenance: MaintenanceDeps;
  customers: CustomerDeps;
  platform: PlatformDeps;
  purchases: PurchaseDeps;
  closings: ClosingDeps;
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
  const sessionRepo = createSessionRepository(db);
  const treasuryRepo = createTreasuryRepository(db);
  const tenantRepo = createTenantRepository(db);
  // ⚠ مستودع المبيعات بيتشارك بين البيع والمرتجع.
  // نسخة واحدة عشان الاتنين يقروا من نفس المكان — لو عملنا
  // نسختين، أي تعديل مستقبلي في واحدة بيسيب التانية وراه.
  const saleRepo = createSaleRepository(db);
  // ⚠ ونفس السبب بالظبط في الضمان: البيع بيكتبه، والمرتجع
  // بيقراه ويحكم بيه. نسختين معناهم إن قاعدة "امتى الضمان
  // انتهى" ممكن تختلف بين الشاشتين — وده أسوأ من غيابها.
  const warrantyRepo = createWarrantyRepository(db);

  return {
    db,
    auth: {
      users: userRepo,
      sessions: sessionRepo,
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
      sessions: sessionRepo,
      hasher,
      clock: systemClock,
      audit,
    },
    branchOps: {
      branches: branchRepo,
      tenants: tenantRepo,
      clock: systemClock,
      audit,
    },
    treasury: {
      treasuries: treasuryRepo,
      movements: createMovementRepository(db),
      expenseReasons: createExpenseReasonRepository(db),
      users: userRepo,
      clock: systemClock,
      audit,
    },
    // ⚠ الأدراج مستودع منفصل عن البضاعة عن قصد.
    //
    // المنتج بيتقرا ويتكتب في كل شاشة تقريبًا؛ والأدراج بتتقرا
    // في شاشة البضاعة وبس. دمجهم كان هيخلّي أي شاشة بتلمس
    // البضاعة تشيل معاها كود تنظيم مالهاش دعوة بيه.
    products: {
      products: createProductRepository(db),
      categories: createCategoryRepository(db),
      models: createModelRepository(db),
      colors: createColorRepository(db),
      branches: branchRepo,
      users: userRepo,
      clock: systemClock,
      audit,
    },
    sales: {
      sales: saleRepo,
      treasuries: treasuryRepo,
      users: userRepo,
      warranty: warrantyRepo,
      clock: systemClock,
      audit,
    },
    returns: {
      returns: createReturnRepository(db),
      sales: saleRepo,
      treasuries: treasuryRepo,
      warranty: warrantyRepo,
      clock: systemClock,
      audit,
    },
    reports: {
      reports: createReportRepository(db),
      clock: systemClock,
      audit,
    },
    alerts: {
      alerts: createAlertRepository(db),
      // ⚠ **نفس النسخة** اللي شاشة الخزينة بتستخدمها، مش واحدة
      // جديدة. `treasuryRepo` متعرّفة فوق ومستخدمة في كذا مكان،
      // وإنشاء نسخة تانية هنا كان هيبقى مسار قراءة موازي —
      // ينفع يختلف يوم ما من غير ما حد ياخد باله.
      treasuries: treasuryRepo,
      clock: systemClock,
    },
    transfers: {
      transfers: createTransferRepository(db),
      clock: systemClock,
      audit,
    },
    // ⚠ الصيانة بقت تاخد الخزنة مع دفتر الورش.
    //
    // السبب إن سداد الورشة **بيطلّع فلوس من الدرج**، زي سداد
    // المورّد بالظبط. والفحص في حالة الاستخدام بيتأكد إن
    // الخزنة جوّه محلك وفي فرعك قبل ما نروح للقاعدة.
    //
    // ⚠ ومن غيره كان مدير فرع يقدر يسدّد من درج فرع تاني
    // والدفتر يقول "تم" — والخزنة التانية ناقصة فلوس مش
    // بتاعتها ومفيش رقم بيقول كده. نفس عطل تسجيل الحركة
    // اللي عدّى علينا قبل كده بالحرف.
    //
    // ⚠ وما بتاخدش الموردين: دفتر الورش مستقل تمامًا عن دفتر
    // الموردين. دمجهم كان هيخلّي كيانين مختلفين في رصيد واحد،
    // والورشة اللي بتبيعلك قطع غيار كمان بتبقى صف في الاتنين.
    maintenance: {
      maintenance: createMaintenanceRepository(db),
      branches: branchRepo,
      treasuries: treasuryRepo,
      clock: systemClock,
      audit,
    },
    suppliers: {
      suppliers: createSupplierRepository(db),
      treasuries: treasuryRepo,
      clock: systemClock,
      audit,
    },
    // ⚠ حساب المحلات بياخد الخزنة زي الموردين بالظبط.
    //
    // السبب إن السداد **بيدخّل فلوس الدرج** — عكس سداد المورّد
    // اللي بيطلّعها. والعمليتين لازم يمسّوا الدفتر والخزنة مع
    // بعض، وإلا رصيدك على الورق بيختلف عن اللي في الدرج.
    //
    // ⚠ وما بياخدش البضاعة: خصم الكمية بيحصل جوّه
    // `fn_shop_consign` في نفس معاملة الدين. لو خصمناها من هنا،
    // بينهم رحلة شبكة — وأي فشل بيسيب بضاعة نقصت ومحدش مديون
    // بيها، أو دين على محل وبضاعة لسه في المخزون.
    shops: {
      shops: createShopRepository(db),
      treasuries: treasuryRepo,
      clock: systemClock,
      audit,
    },
    customers: {
      customers: createCustomerRepository(db),
      branches: branchRepo,
      clock: systemClock,
      audit,
    },
    platform: {
      tenants: tenantRepo,
      hasher,
      clock: systemClock,
      audit,
    },
    // ⚠ شرا البضاعة بياخد الخزنة، مش الموردين.
    // السبب إن العملية **مالية** في جوهرها: فلوس بتطلع من الدرج
    // وبيان بيتكتب جنبها. المورّد اسم على البيان مش طرف في
    // المعاملة — الدين بيتسجّل في وحدة الموردين لوحدها.
    purchases: {
      purchases: createPurchaseRepository(db),
      treasuries: treasuryRepo,
      clock: systemClock,
      audit,
    },
    // ⚠ واليومية بتاخد الفروع عشان صاحب المحل يختار،
    // وما بتاخدش المبيعات ولا الخزنة: اللقطة كلها بتتبني جوّه
    // قاعدة البيانات في نداء واحد. لو بنيناها هنا، كنا هنقرا
    // المبيعات في رحلة والحركات في رحلة تانية — وأي بيعة
    // بتتسجّل بينهم بتقع في الشق.
    closings: {
      closings: createClosingRepository(db),
      branches: branchRepo,
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
  // ══ ⚠ قناة تشخيص بمفتاح — مقفولة افتراضيًا ══
  //
  // لما عطل يحصل على موبايل في المحل، مفيش لوق ومفيش أدوات
  // مطوّر. والرسالة الموحّدة ("حدث خطأ غير متوقّع") بتحمي
  // النظام وبتخلّيك أعمى في نفس الوقت.
  //
  // المفتاح ده بيخلّي التفاصيل تنزل **في الرد نفسه**، فتقراها
  // من الموبايل مباشرةً.
  //
  // ⚠⚠ وهو مقفول إلا لو حطّيت DEBUG_ERRORS=1 في إعدادات
  // كلاودفلير. حطّه في بيئة **المعاينة** بس، واقفله بعد ما
  // تلاقي السبب.
  //
  // ⚠ لو سبته مفتوح في الإنتاج، أي زائر يقدر يشوف أسماء جداولك
  // ونصوص استعلاماتك — وده بيدّي المهاجم خريطة نظامك.
  const debug = (c.env as Env | undefined)?.DEBUG_ERRORS === '1';

  if (error instanceof AppError) {
    if (error.httpStatus >= 500) console.error('[error]', error.code, error.internalDetail);

    // ⚠ لاحظ إن SESSION_LOCKED **مش** في القائمة دي، وده مقصود.
    // القفل معناه إن الجلسة لسه حيّة — لو مسحنا الكوكيز، هيضيع
    // توكن التحديث اللي هو الطريق الوحيد لفكّ القفل، والموظّف
    // هيتطرد بدل ما يتقفل. ما تضيفهوش هنا.
    if (error.code === 'SESSION_EXPIRED' || error.code === 'SESSION_IDLE_TIMEOUT') {
      clearAuthCookies(c);
    }
    if (error.code === 'RATE_LIMITED' && typeof error.meta?.retryAfterSec === 'number') {
      c.header('Retry-After', String(error.meta.retryAfterSec));
    }

    return c.json(
      {
        ok: false,
        error: {
          code: error.code,
          message: error.userMessage,
          ...error.meta,
          ...(debug && error.internalDetail ? { detail: error.internalDetail } : {}),
        },
      },
      error.httpStatus as 400,
    );
  }

  console.error('[error] خطأ غير متوقّع:', error);
  const fallback = Errors.internal();
  return c.json(
    {
      ok: false,
      error: {
        code: fallback.code,
        message: fallback.userMessage,
        // ⚠ الرسالة الأصلية بالإنجليزي زي ما هي — مش مترجمة.
        // ترجمتها كانت هتخفي نص الخطأ اللي بندوّر عليه.
        ...(debug
          ? { detail: error instanceof Error ? error.message : String(error) }
          : {}),
      },
    },
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
