/**
 * التطبيق
 *
 * الملف ده بيبني التطبيق بس، وما بيصدّرش نقطة دخول.
 * نقطة الدخول في `functions/[[path]].ts` — لأن Cloudflare Pages
 * بتدوّر على مجلد `functions` مش على ملف واحد.
 *
 * تشبيه: ده تصميم الصالة. الباب اللي الناس بتدخل منه في ملف تاني.
 */

import { Hono } from 'hono';
import { secureHeaders } from 'hono/secure-headers';
import { SESSION_POLICY, assertEnv, idleRuleFor, type Env } from './domain/config';
import { todayInCairo } from './domain/dates';
import { AppError, Errors } from './domain/errors';
import { PERMISSIONS } from './domain/permissions';
import {
  announcementRoutes,
  authRoutes,
  branchRoutes,
  customerRoutes,
  platformRoutes,
  productRoutes,
  purchaseRoutes,
  closingRoutes,
  reportRoutes,
  maintenanceRoutes,
  shopRoutes,
  supplierRoutes,
  transferRoutes,
  returnRoutes,
  saleRoutes,
  setupRoutes,
  treasuryRoutes,
  userRoutes,
} from './server/routes';
import { listBranchesForActor, listTeam } from './application/use-cases/users';
import { listRepairShops } from './application/use-cases/maintenance';
import { listBranches } from './application/use-cases/branches';
import {
  getFinancialSummary,
  listBalances,
  listExpenseReasons,
  listMovements,
  listTransfers,
} from './application/use-cases/treasury';
import { listCategories, listColors, listModels, listProducts, listSellableProducts } from './application/use-cases/products';
import { listSupplierNames } from './application/use-cases/purchases';
import { listShopAccounts } from './application/use-cases/shops';
import { DEFAULT_WARRANTY_DAYS, listSales } from './application/use-cases/sales';
import { listCustomers } from './application/use-cases/customers';
import { listTenants } from './application/use-cases/platform';
import type { AuthenticatedUser } from './application/ports';
import { requireAuth, type AppBindings } from './server/guard';
import { buildContainer, errorResponse, getRequestContext } from './server/runtime';
import { APP_ICONS, APP_MANIFEST, SERVICE_WORKER, iconBytes } from './ui/icons';
import {
  dashboardPage,
  lockedPage,
  loginPage,
  customersPage,
  passwordPage,
  platformPage,
  platformSetupPage,
  posPage,
  productsPage,
  closingsPage,
  reportPage,
  maintenancePage,
  shopsPage,
  suppliersPage,
  setupPage,
  treasuryPage,
} from './ui/pages';

export const app = new Hono<AppBindings>();

// ─────────── هيدرات أمنية على كل رد ───────────
app.use(
  '*',
  secureHeaders({
    xFrameOptions: 'DENY', // يمنع وضع الموقع جوّه إطار (clickjacking)
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'strict-origin-when-cross-origin',
    strictTransportSecurity: 'max-age=63072000; includeSubDomains',
  }),
);

// ─────────── فحص الإعدادات ───────────
// أول حاجة بتحصل: نتأكد إن المتغيّرات موجودة وصح.
// الهدف رسالة واضحة بدل انهيار غامض وسط يوم شغل.
app.use('*', async (c, next) => {
  try {
    assertEnv(c.env);
  } catch (error) {
    console.error('[config]', error);
    return c.text(
      'النظام مش مضبوط بعد.\n\n' +
        (error instanceof Error ? error.message : '') +
        '\n\nروح: Cloudflare ← مشروعك ← Settings ← Variables and Secrets',
      503,
    );
  }
  await next();
});

// ─────────── مُوحِّد الأخطاء ───────────
app.onError((error, c) => {
  const wantsHtml = c.req.header('accept')?.includes('text/html');

  if (error instanceof AppError && wantsHtml && error.httpStatus === 401) {
    return c.redirect('/login?expired=1');
  }
  return errorResponse(c, error);
});

app.notFound((c) => c.json({ ok: false, error: { code: 'NOT_FOUND', message: 'غير موجود.' } }, 404));

// ═══════════════════ مسارات الـ API ═══════════════════

app.route('/api/auth', authRoutes);
app.route('/api/announcements', announcementRoutes);
app.route('/api/users', userRoutes);
app.route('/api/branches', branchRoutes);
app.route('/api/treasury', treasuryRoutes);
app.route('/api/products', productRoutes);
app.route('/api/sales', saleRoutes);
app.route('/api/returns', returnRoutes);
app.route('/api/reports', reportRoutes);
app.route('/api/transfers', transferRoutes);
app.route('/api/suppliers', supplierRoutes);
// ⚠ دفتر مستقل عن الموردين: دين **ليك** مش عليك.
app.route('/api/shops', shopRoutes);
app.route('/api/maintenance', maintenanceRoutes);
app.route('/api/customers', customerRoutes);
app.route('/api/purchases', purchaseRoutes);
app.route('/api/closings', closingRoutes);
app.route('/api/platform', platformRoutes);
app.route('/', setupRoutes);

// ═══════════════════ الصفحات ═══════════════════

// ═══════════════════ أصول التطبيق المثبَّت ═══════════════════
//
// ⚠ لازم تتسجّل **قبل** المسار الملتقط /:maybeSecret في آخر الملف،
// وإلا هيبتلعها ويرجّع 404.
//
// الأصول دي مفتوحة بلا تسجيل دخول عن قصد: المتصفح بيطلب البيان
// والأيقونة قبل ما المستخدم يدخل أصلاً. مفيهاش أي بيانات.

const ASSET_CACHE = 'public, max-age=86400';

app.get('/manifest.webmanifest', (c) => {
  c.header('Content-Type', 'application/manifest+json; charset=utf-8');
  c.header('Cache-Control', ASSET_CACHE);
  return c.body(APP_MANIFEST);
});

app.get('/sw.js', (c) => {
  c.header('Content-Type', 'application/javascript; charset=utf-8');
  // ⚠ مفيش تخزين للملف ده نفسه: لو خزّناه، أي تعديل عليه بعدين
  // هيفضل المتصفح شغّال بالقديم لمدة مش معروفة.
  c.header('Cache-Control', 'no-cache');
  c.header('Service-Worker-Allowed', '/');
  return c.body(SERVICE_WORKER);
});

// ⚠ الأيقونات متسجّلة بأسمائها واحدة واحدة مش بنمط regex.
//
// النمط كان بيحتاج شرطة مائلة مهرَّبة، وأي زيادة أو نقصان فيها
// بيخلّي المسار ما يطابقش حاجة — والنتيجة 404 صامت على كل
// الأيقونات، والتطبيق يفضل بلا صورة من غير أي رسالة خطأ.
//
// القائمة صريحة ومصدرها واحد (APP_ICONS)، فمفيش اسم ممكن يفوت.
for (const file of Object.keys(APP_ICONS)) {
  app.get(`/${file}`, (c) => {
    const bytes = iconBytes(file);
    if (!bytes) return c.notFound();

    c.header('Content-Type', 'image/png');
    c.header('Cache-Control', ASSET_CACHE);
    return c.body(bytes);
  });
}

app.get('/', (c) => c.redirect('/login'));

// ملاحظة: مسار /health اتشال في المرحلة صفر.
// كان أداة تشخيص وقت الإعداد الأول، وبعد ما النظام استقر بقى
// بيكشف معلومات عن البنية لأي زائر بدون فايدة.

app.get('/login', (c) => c.html(loginPage({ expired: c.req.query('expired') === '1' })));

/**
 * شاشة فك القفل.
 *
 * ⚠ مش محمية بـ requireAuth عن قصد — الجلسة المقفولة بترمي 423،
 * فلو حميناها هتعمل حلقة إعادة توجيه لا نهائية. الصفحة نفسها
 * ما بتعرضش أي بيانات؛ التحقق الحقيقي في /api/auth/unlock.
 */
app.get('/locked', (c) => c.html(lockedPage()));

/**
 * صفحة الإعداد لمرّة واحدة.
 * بتختفي تماماً (404) لو SETUP_SECRET مش مضبوط — يعني بعد ما
 * تمسحه من كلاودفلير، الصفحة مش موجودة أصلاً.
 */
app.get('/setup', (c) => {
  if (!c.env.SETUP_SECRET || c.env.SETUP_SECRET.length < 16) return c.notFound();
  return c.html(setupPage());
});

/**
 * تأسيس مشغّل المنصّة — لمرّة واحدة.
 * بتختفي (404) لو SETUP_SECRET مش مضبوط، زي صفحة الإعداد الأولي.
 */
app.get('/platform-setup', (c) => {
  if (!c.env.SETUP_SECRET || c.env.SETUP_SECRET.length < 16) return c.notFound();
  return c.html(platformSetupPage());
});

/**
 * شاشة إدارة المحلات.
 *
 * ⚠ الشاشة دي مالهاش أي وصول لبيانات المحلات. الحارس بيفحص
 * `tenant.view` اللي مالكوش غير مشغّل المنصّة، وحالات الاستخدام
 * بترمي لو الدور ده حاول يقرا بضاعة أو مبيعات.
 */
app.get('/platform', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.TENANT_VIEW)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);
  const tenants = await listTenants(container.platform, user);

  return c.html(
    platformPage({
      fullName: user.fullName,
      username: user.username,
      currentTenantId: user.tenantId,
      tenants: tenants.map((t) => ({
        id: t.id,
        code: t.code,
        name: t.name,
        isActive: t.isActive,
        maxBranches: t.maxBranches,
        branchCount: t.branchCount,
        userCount: t.userCount,
        ownerName: t.ownerName,
      })),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

const ROLE_LABELS: Record<string, string> = {
  PLATFORM_ADMIN: 'مشغّل المنصّة — إدارة الاشتراكات',
  SUPER_ADMIN: 'صاحب المحل — صلاحية كاملة داخل محلّه',
  BRANCH_MANAGER: 'مدير فرع — نطاق فرعك',
  STAFF: 'مندوب مبيعات — البيع وتسجيل العملاء',
};

/**
 * اسم الفرع للعرض.
 *
 * ⚠ الموظّف مالوش صلاحية branch.view، فالنداء بيرمي خطأ عنده.
 * بنمسكه ونرجّع null، والواجهة بتخفي السطر بدل ما تعرض شرطة.
 */
async function branchLabelFor(
  container: ReturnType<typeof buildContainer>,
  user: AuthenticatedUser,
): Promise<string | null> {
  if (user.roleKey === 'SUPER_ADMIN') return 'كل الفروع';
  const branches = await listBranches(container.branchOps, user).catch(() => []);
  return branches[0]?.name ?? null;
}

app.get('/app', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  // ⚠ مشغّل المنصّة مالوش لوحة محل — مالوش محل يديره أصلاً.
  // لو سيبناه يكمّل، كل استدعاء تحت هيرمي لأن نطاقه ممنوع.
  if (user.roleKey === 'PLATFORM_ADMIN') {
    return c.redirect('/platform');
  }

  const container = buildContainer(c.env);

  const canViewUsers = user.permissions.includes(PERMISSIONS.USER_VIEW);
  const canCreateUsers = user.permissions.includes(PERMISSIONS.USER_CREATE);
  const canEditUsers = user.permissions.includes(PERMISSIONS.USER_EDIT);
  const canManageBranches = user.permissions.includes(PERMISSIONS.BRANCH_MANAGE);
  const idleRule = idleRuleFor(user.roleKey);

  // نجيبهم هنا على الخادم بدل fetch من المتصفح: أسرع (رحلة واحدة
  // بدل تلاتة) وأبسط للقوائم اللي محتاجة تتعرض فوراً
  const canApproveExpenses = user.permissions.includes(PERMISSIONS.EXPENSE_APPROVE);

  const [team, branchOptions, tenantBranches, pending] = await Promise.all([
    canViewUsers ? listTeam(container.users, user) : Promise.resolve([]),
    canCreateUsers ? listBranchesForActor(container.users, user) : Promise.resolve([]),
    canManageBranches ? listBranches(container.branchOps, user) : Promise.resolve([]),
    canApproveExpenses
      ? listMovements(container.treasury, user, 'PENDING')
      : Promise.resolve([]),
  ]);

  const branchLabel = await branchLabelFor(container, user);

  return c.html(
    dashboardPage({
      currentUserId: user.id,
      fullName: user.fullName,
      username: user.username,
      branchLabel,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      roleLabel: ROLE_LABELS[user.roleKey] ?? user.roleKey,
      permissions: user.permissions,
      pendingApprovals: pending.length,
      canApproveExpenses,
      // ⚠ الاتنين دول مختلفين: الأولانية بتفتح الشاشة، والتانية
      // بتحدّد شكلها. مدير الفرع بيفتح ومش بيشوف التكلفة.
      canViewReport: user.permissions.includes(PERMISSIONS.REPORT_VIEW_BRANCH),
      // ⚠ صلاحية مختلفة عن التقرير عن قصد: المندوب بيشوف
      // اليومية (عشان يقفلها لو المالك اختاره) وما بيشوفش
      // قائمة الدخل. لو استخدمنا نفس العلم، الزرار كان
      // هيختفي عن اللي المفروض يضغطه.
      canViewClosings: user.permissions.includes(PERMISSIONS.SALES_VIEW_BRANCH),
      canSeeCost: user.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL),
      canManageSuppliers: user.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE),
      canViewMaintenance: user.permissions.includes(PERMISSIONS.MAINTENANCE_VIEW),
      canBroadcast: user.permissions.includes(PERMISSIONS.ANNOUNCEMENT_BROADCAST),
      canViewUsers,
      canCreateUsers,
      canEditUsers,
      canManageBranches,
      team,
      branches: branchOptions,
      tenantBranches,
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * شاشة الكاشير.
 *
 * كل البيانات بتتجاب على الخادم في رحلة واحدة متوازية — أسرع
 * بكتير من أربع نداءات من المتصفح على شبكة موبايل، والموظّف
 * بيفتح الشاشة دي أول ما يبدأ ورديته.
 */
app.get('/pos', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.SALES_CREATE)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);

  const canConsign = user.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE);

  const [products, balances, recent, branchLabel, posBranches, shopAccounts] =
    await Promise.all([
    listSellableProducts(container.products, user),
    listBalances(container.treasury, user),
    // ⚠ الخطأ ما يصحّش يتبلع في صمت. لو الاستعلام فشل، القائمة
    // بتفضل فاضية — وشكلها زي "مفيش فواتير" بالظبط. الفرق بين
    // الاتنين بيظهر في اللوق بس، فلازم يتكتب.
    listSales(container.sales, user, 10).catch((err) => {
      console.error('[pos] تعذّر جلب آخر الفواتير:', err);
      return [];
    }),
    branchLabelFor(container, user),
    // ⚠ لصاحب المحل وحده. غيره مقفول على فرعه أصلاً، فقائمة
    // فروع عنده بتبقى خانة باختيار واحد — أثاث بلا وظيفة.
    user.roleKey === 'SUPER_ADMIN'
      ? container.branches.listActive(user.tenantId).catch(() => [])
      : Promise.resolve([]),
    // ⚠ حسابات المحلات — للخروج أجل. بتتجاب لمن يملك الصلاحية
    // بس، وفاضية لغيره فالقسم كله بيختفي.
    canConsign
      ? listShopAccounts(container.shops, user).catch(() => [])
      : Promise.resolve([]),
  ]);

  return c.html(
    posPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      // ⚠ مدير الفرع والمالك بس. المندوب بيبيع وما بيرجّعش —
      // اللي بياخد الفلوس مش هو اللي بيردّها.
      canRefund: user.permissions.includes(PERMISSIONS.SALES_REFUND),
      // ⚠ الخزن اللي مالهاش فرع (مستوى الشركة) مستبعدة: البيع
      // لازم يتسجّل على فرع، والدالة في قاعدة البيانات بترفضها.
      // إخفاؤها هنا بيمنع الموظّف يختار حاجة هتترفض بعد الضغط.
      //
      // ⚠ و`branchId` بيتمرّر دلوقتي عشان الشاشة تفلتر بيه.
      // الفلتر ده **راحة مش حماية** — الحارس الحقيقي في دالة
      // القاعدة، وهو اللي بيرفض خزنة فرع مع منتج فرع تاني.
      treasuries: balances
        .filter((b) => b.isActive && b.branchId !== null)
        .map((b) => ({
          treasuryId: b.treasuryId,
          name: b.name,
          type: b.type,
          branchId: b.branchId as string,
        })),
      // ⚠ فاضية لغير صاحب المحل — والشاشة بتخفي الخانة ساعتها.
      branches: posBranches.map((b: { id: string; name: string }) => ({ id: b.id, name: b.name })),
      products: products.map((p) => ({
        id: p.id,
        name: p.name,
        productType: p.productType,
        serialNumber: p.serialNumber,
        pricePiastres: p.pricePiastres,
        quantityOnHand: p.quantityOnHand,
        branchId: p.branchId,
      })),
      recentSales: recent.map((s) => ({
        id: s.id,
        totalPiastres: s.totalPiastres,
        customerName: s.customerName,
        staffName: s.staffName,
        createdAt: s.createdAt,
        exitDate: s.exitDate,
        // ⚠ بيتحسب هنا على الخادم مش في المتصفح.
        // إخفاء الزرار راحة؛ الحراسة الحقيقية في حالة الاستخدام.
        canEditExit: s.staffId === user.id || user.roleKey === 'SUPER_ADMIN',
      })),
      today: todayInCairo(),
      // ⚠ الرقم جاي من حالة الاستخدام مش مكتوب في الواجهة —
      // مصدر واحد. لو اتكتب في المكانين، هييجي يوم يتغيّر في
      // واحد ويفضل القديم في التاني: الفاتورة تقول حاجة
      // والشاشة تقول حاجة.
      // ⚠ الاسم والمعرّف بس. الشاشة دي بتخرّج بضاعة مش بتعرض
      // ديون، والرصيد معلومة مالية مالهاش لزوم هنا.
      shopAccounts: shopAccounts.map((sh) => ({ id: sh.shopId, name: sh.name })),
      canConsign,
      defaultWarrantyDays: DEFAULT_WARRANTY_DAYS,
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * شاشة البضاعة.
 *
 * ⚠ التكلفة مش بتتفلتر هنا. الحقل بيوصل أو ما بيوصلش من طبقة
 * قاعدة البيانات حسب صلاحية profit.view_real، والصفحة بتعرض
 * اللي وصلها. مكان واحد للحقيقة.
 */
app.get('/products', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);
  const canEdit = user.permissions.includes(PERMISSIONS.INVENTORY_ADJUST);

  const [
    products, branches, allBranches, branchLabel,
    categories, models, colors, suppliers, treasuryList,
  ] = await Promise.all([
    // ⚠ الفشل هنا بيسمّي نفسه بدل ما يطلع "خطأ غير متوقّع".
    //
    // الرسالة الموحّدة بتحمي النظام، بس لما الصفحة كلها تقع
    // بيها إنت مش عارف وقعت من فين: البضاعة؟ الفروع؟ الأدراج؟
    //
    // ⚠ ومش بنبلع الخطأ ونرجّع قايمة فاضية — القايمة الفاضية
    // شكلها زي "مفيش بضاعة" بالظبط، وده أوحش من رسالة خطأ.
    listProducts(container.products, user).catch((err) => {
      console.error('[products] تعذّر جلب البضاعة:', err);
      throw Errors.internal(
        `listProducts: ${err instanceof Error ? err.message : String(err)}`,
      );
    }),
    // قائمة الفروع للإضافة — للمالك بس، غيره مقفول على فرعه
    // والاختيار مالوش معنى عنده
    user.roleKey === 'SUPER_ADMIN' && canEdit
      ? listBranchesForActor(container.users, user).catch(() => [])
      : Promise.resolve([]),
    // ⚠ قائمة منفصلة للتحويل. دي بتتجاب **لكل الأدوار** لأن
    // المندوب كمان بيحوّل، ومحتاج يشوف أسماء فروع محله.
    // أسماء الفروع مش بيانات حسّاسة — دي فروعه هو.
    canEdit
      ? container.branches.listActive(user.tenantId).catch(() => [])
      : Promise.resolve([]),
    branchLabelFor(container, user).catch((err) => {
      console.error('[products] تعذّر جلب اسم الفرع:', err);
      throw Errors.internal(
        `branchLabel: ${err instanceof Error ? err.message : String(err)}`,
      );
    }),
    // ⚠ الأدراج بتتجاب لكل من يشوف المخزون، مش للمعدّل بس.
    // الأدراج تنظيم عرض — واللي بيشوف قايمة مسطّحة والباقي
    // شايفين أدراج مش بيشوف نفس المحل.
    listCategories(container.products, user).catch(() => []),
    // ⚠ نفس السبب: سجل الموديلات بيتجاب لكل من يشوف المخزون.
    // الشاشة بتفلتر بيه، واللي شايف قايمة بلا فلتر مش بيشوف
    // نفس المحل.
    listModels(container.products, user).catch(() => []),
    listColors(container.products, user).catch(() => []),
    // ⚠ أسماء الموردين بس — لقايمة مصدر الشراء في نموذج الإضافة.
    // بلا أي رقم مالي، فالمندوب بيختار من غير ما يشوف الديون.
    listSupplierNames(container.purchases, user).catch(() => []),
    // ⚠ خزن نطاق المستخدم — لسداد التكلفة وقت الإضافة.
    // نفس نطاق شاشة الموردين: المالك كل الخزن، وغيره فرعه.
    container.treasury.treasuries
      .listBalances(user.tenantId, user.roleKey === 'SUPER_ADMIN' ? null : user.branchId)
      .catch(() => []),
  ]);

  // ورش الصيانة — لقائمة "تحويل للصيانة" في كارت المنتج
  const repairShops = user.permissions.includes(PERMISSIONS.MAINTENANCE_MANAGE)
    ? await listRepairShops(container.maintenance, user)
        .then((list) => list.map((sh) => ({ id: sh.id, name: sh.name })))
        .catch(() => [])
    : [];

  return c.html(
    productsPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canEdit,
      canSeeCost: user.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL),
      // ⚠ صلاحية منفصلة عن inventory.adjust: تعديل الكمية
      // عملية يومية، وتحديد الحد قرار سياسة.
      canSetReorder: user.permissions.includes(PERMISSIONS.INVENTORY_REORDER_POINT),
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      categories,
      models,
      colors,
      suppliers,
      canManageSuppliers: user.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE),
      // ⚠ الاسم والمعرّف بس — الرصيد معلومة مالية والمندوب
      // مش محتاجها عشان يقول "دفعت من الدرج".
      treasuries: treasuryList.map((t) => ({ id: t.treasuryId, name: t.name })),
      branches,
      // ⚠ فروع التحويل غير قائمة الإضافة: هنا بنستبعد فرع
      // المستخدم نفسه — تحويل لفرعك مالوش معنى، والقاعدة
      // بترفضه أصلاً بقيد صريح.
      // فرع المستخدم مستبعد — تحويل لفرعك مالوش معنى، والقاعدة
      // بترفضه بقيد صريح أصلاً
      transferTargets: allBranches
        .filter((b) => b.id !== user.branchId)
        .map((b) => ({ id: b.id, name: b.name })),
      // ⚠ الإرسال للورشة بيخصم من المخزون، فهو قرار إداري
      canSendToRepair: user.permissions.includes(PERMISSIONS.MAINTENANCE_MANAGE),
      repairShops,
      products,
      today: todayInCairo(),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * تغيير كلمة المرور — متاح لكل من دخل، أيًا كان دوره.
 *
 * ⚠ مفيش فحص صلاحية هنا عن قصد: تغيير كلمة مرورك حق مش امتياز.
 * الحراسة الوحيدة إنك مسجّل دخول، والفحص الحقيقي (كلمة المرور
 * الحالية) في حالة الاستخدام.
 */
app.get('/password', requireAuth({ redirectOnFail: true }), (c) => {
  const user = c.get('user');
  return c.html(
    passwordPage({
      fullName: user.fullName,
      username: user.username,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      branchLabel: null,
    }),
  );
});

/**
 * صفحة العملاء.
 *
 * بتتفتح من قائمة التلات نقط مش من الشريط السفلي: الشريط لليومي
 * المتكرر (بيع، بضاعة، خزنة)، والقائمة للي بتفتحه لما تحتاجه.
 */
app.get('/customers', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.CUSTOMER_VIEW)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);
  const canAdd = user.permissions.includes(PERMISSIONS.CUSTOMER_CREATE);

  const [customers, branches, branchLabel] = await Promise.all([
    listCustomers(container.customers, user),
    user.roleKey === 'SUPER_ADMIN' && canAdd
      ? listBranchesForActor(container.users, user).catch(() => [])
      : Promise.resolve([]),
    branchLabelFor(container, user),
  ]);

  return c.html(
    customersPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canAdd,
      canEdit: user.permissions.includes(PERMISSIONS.CUSTOMER_EDIT),
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      branches,
      customers: customers.map((cst) => ({
        id: cst.id,
        name: cst.name,
        phone: cst.phone,
        notes: cst.notes,
        deviceCount: cst.deviceCount,
        purchaseCount: cst.purchaseCount,
        totalPiastres: cst.totalPiastres,
      })),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة الصيانة.
 *
 * ⚠ كل البيانات بتتجاب بالجافاسكربت — الشاشة فيها بحث وفلترة
 * بتتغيّر كتير، وتحميلها مع الصفحة كان معناه إعادة تحميل كاملة
 * مع كل بحث.
 */
app.get('/maintenance', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.MAINTENANCE_VIEW)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);

  // ⚠ للمالك بس: هو مالوش فرع، فلازم يختار. غيره مقفول على
  // فرعه والاختيار مالوش معنى عنده.
  const branches =
    user.roleKey === 'SUPER_ADMIN'
      ? await container.branches.listActive(user.tenantId).catch(() => [])
      : [];

  return c.html(
    maintenancePage({
      fullName: user.fullName,
      username: user.username,
      branchLabel: await branchLabelFor(container, user),
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      canManage: user.permissions.includes(PERMISSIONS.MAINTENANCE_MANAGE),
      branches: branches.map((b) => ({ id: b.id, name: b.name })),
      today: todayInCairo(),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة الموردين والديون.
 *
 * ⚠ الأرصدة بتتجاب بالجافاسكربت مش هنا — بتتغيّر مع كل حركة
 * في نفس الشاشة، وإعادة تحميل الصفحة مع كل تسجيل مرهقة.
 *
 * اللي بيتبعت مع الصفحة: الخزن (لقائمة السداد) بس.
 */
app.get('/suppliers', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);

  // مدير الفرع بيدفع من خزنة فرعه. صاحب المحل من أي خزنة.
  const treasuries = await container.treasury.treasuries
    .listBalances(user.tenantId, user.roleKey === 'SUPER_ADMIN' ? null : user.branchId)
    .catch(() => []);

  return c.html(
    suppliersPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel: await branchLabelFor(container, user),
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      treasuries: treasuries.map((t) => ({ treasuryId: t.treasuryId, name: t.name })),
      today: todayInCairo(),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة حساب المحلات — المرآة المقلوبة للموردين.
 *
 * ⚠ نفس الصلاحية (`supplier.manage`). ده دفتر ديون، والديون
 * معلومة مالية سواء كانت عليك أو ليك.
 */
app.get('/shops', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.SUPPLIER_MANAGE)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);

  // ⚠ نفس نطاق شاشة الموردين: مدير الفرع بيحصّل في خزنة فرعه،
  // وصاحب المحل في أي خزنة.
  const treasuries = await container.treasury.treasuries
    .listBalances(user.tenantId, user.roleKey === 'SUPER_ADMIN' ? null : user.branchId)
    .catch(() => []);

  return c.html(
    shopsPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel: await branchLabelFor(container, user),
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      treasuries: treasuries.map((t) => ({ treasuryId: t.treasuryId, name: t.name })),
      today: todayInCairo(),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة قائمة الدخل.
 *
 * ⚠ التقرير نفسه بيتجاب بالجافاسكربت من `/api/reports/income`،
 * مش هنا. السبب: تغيير الفترة ما يعملش تحميل كامل للصفحة.
 *
 * الصفحة دي بتبعت الإطار والصلاحيات بس.
 */
app.get('/report', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.REPORT_VIEW_BRANCH)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);
  const today = todayInCairo();

  return c.html(
    reportPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel: await branchLabelFor(container, user),
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      canSeeCost: user.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL),
      // الافتراضي: من أول الشهر لحد النهاردة، بتوقيت القاهرة
      from: `${today.slice(0, 7)}-01`,
      to: today,
      today,
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});


/**
 * سجل اليوميات.
 *
 * ══ ليه الصلاحية `sales.view_branch` مش `report.view_branch`؟ ══
 * التقرير فيه هوامش وتكاليف، فمقفول على المدير وفوق. أما سجل
 * اليوميات فبيوصف **حركة الوردية**: باع كام، صرف كام، رجّع كام.
 *
 * والمندوب عنده الصلاحية دي أصلاً. لو حصرناها في المدير، المندوب
 * اللي صاحب المحل اختاره يقفل مش هيقدر يشوف اللي بيقفله — وده
 * زرار بيقفل على المجهول.
 *
 * ⚠ ولاحظ إن **مين يقدر يقفل** مش محسوب هنا خالص. ده إعداد على
 * الفرع بيتقرا من قاعدة البيانات وقت المعاينة، مش صلاحية على
 * المستخدم. الصفحة بتفتح للكل، والزرار بيظهر لمن يستحق.
 */
app.get('/closings', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.SALES_VIEW_BRANCH)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const idleRule = idleRuleFor(user.roleKey);
  const isOwner = user.roleKey === 'SUPER_ADMIN';

  // صاحب المحل مالوش فرع، فلازم يختار. غيره فرعه مقفول عليه
  // من جلسته ومفيش قائمة أصلاً.
  const branches = isOwner
    ? await listBranches(container.branchOps, user).catch(() => [])
    : [];

  return c.html(
    closingsPage({
      fullName: user.fullName,
      username: user.username,
      branchLabel: await branchLabelFor(container, user),
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      canUseTreasury: user.permissions.includes(PERMISSIONS.EXPENSE_CREATE),
      canSeeCost: user.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL),
      isOwner,
      branches: branches.map((b) => ({ id: b.id, name: b.name })),
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة الخزنة.
 * الأرصدة والحركات وقوائم الاختيار بتتجاب على الخادم في رحلة
 * واحدة متوازية — أسرع من أربع نداءات من المتصفح على شبكة موبايل.
 */
app.get('/treasury', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');

  if (!user.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    return c.redirect('/app');
  }

  const container = buildContainer(c.env);
  const canApprove = user.permissions.includes(PERMISSIONS.EXPENSE_APPROVE);

  const branchName = await branchLabelFor(container, user);

  const isOwner = user.roleKey === 'SUPER_ADMIN';

  const [balances, movements, reasons, team, pending, summary, transfers, branches] =
    await Promise.all([
      listBalances(container.treasury, user),
      listMovements(container.treasury, user),
      listExpenseReasons(container.treasury, user),
      user.permissions.includes(PERMISSIONS.USER_VIEW)
        ? listTeam(container.users, user)
        : Promise.resolve([]),
      canApprove ? listMovements(container.treasury, user, 'PENDING') : Promise.resolve([]),
      // ⚠ الملخّص نداء واحد بيرجّع الصفوف والمجاميع مع بعض —
      // متحسبين من نفس البيانات، فمستحيل يختلفوا.
      getFinancialSummary(container.treasury, user),
      // التحويلات بتظهر لكل من يشوف الخزنة، والتنفيذ لمن
      // يقدر يعتمد بس. الفرق بين "تشوف" و"تعمل".
      listTransfers(container.treasury, user).catch(() => []),
      // صاحب المحل مالوش فرع، فلازم يختار عند إضافة خزنة
      isOwner ? listBranches(container.branchOps, user).catch(() => []) : Promise.resolve([]),
    ]);

  return c.html(
    treasuryPage({
      currentUserId: user.id,
      fullName: user.fullName,
      username: user.username,
      branchLabel: branchName,
      tenantName: user.tenantName,
      roleKey: user.roleKey,
      canApprove,
      canSell: user.permissions.includes(PERMISSIONS.SALES_CREATE),
      canViewProducts: user.permissions.includes(PERMISSIONS.INVENTORY_VIEW),
      balances,
      movements,
      pending,
      reasons,
      team: team.filter((t) => t.isActive),
      summary,
      transfers,
      isOwner,
      canTransfer: canApprove,
      branches: branches.map((b) => ({ id: b.id, name: b.name })),
      idleTimeoutSeconds: idleRuleFor(user.roleKey).seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRuleFor(user.roleKey).action,
    }),
  );
});

// ⚠ البوّابة السرّية اتشالت.
//
// كانت رابط مخفي + مفتاح تاني لأعلى حساب، ومنطقها كان سليم لما
// كان فيه مالك واحد في النظام كله.
//
// مع محلات كتير، بقى فيه صاحب محل لكل عميل — وما ينفعش عشرين
// واحد يشتركوا في نفس الرابط. المسار المخفي كان "مطبّ سرعة مش
// قفل" من الأول، ومع الكتر بقى مطبّ بلا فايدة.
//
// دلوقتي الكل بيدخل من /login بكود محله. والقفل الحقيقي اللي
// فضل: كود المحل + كلمة المرور + مفتاح تاني لحساب المنصّة وحده.

export default app;
