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
import { SESSION_POLICY, assertEnv, idleRuleFor, superAdminPath, type Env } from './domain/config';
import { AppError } from './domain/errors';
import { PERMISSIONS } from './domain/permissions';
import {
  announcementRoutes,
  authRoutes,
  branchRoutes,
  setupRoutes,
  treasuryRoutes,
  userRoutes,
} from './server/routes';
import { listBranchesForActor, listTeam } from './application/use-cases/users';
import { listBranches } from './application/use-cases/branches';
import {
  listBalances,
  listExpenseReasons,
  listMovements,
} from './application/use-cases/treasury';
import { requireAuth, type AppBindings } from './server/guard';
import { buildContainer, errorResponse, getRequestContext } from './server/runtime';
import {
  dashboardPage,
  lockedPage,
  loginPage,
  setupPage,
  treasuryPage,
  vaultPage,
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
app.route('/', setupRoutes);

// ═══════════════════ الصفحات ═══════════════════

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

const ROLE_LABELS: Record<string, string> = {
  SUPER_ADMIN: 'المالك — صلاحية كاملة',
  BRANCH_MANAGER: 'مدير فرع — نطاق فرعك',
  STAFF: 'موظّف — البيع وتسجيل العملاء',
};

app.get('/app', requireAuth({ redirectOnFail: true }), async (c) => {
  const user = c.get('user');
  const container = buildContainer(c.env);

  const canViewUsers = user.permissions.includes(PERMISSIONS.USER_VIEW);
  const canCreateUsers = user.permissions.includes(PERMISSIONS.USER_CREATE);
  const canEditUsers = user.permissions.includes(PERMISSIONS.USER_EDIT);
  const canManageBranches = user.permissions.includes(PERMISSIONS.BRANCH_MANAGE);
  const idleRule = idleRuleFor(user.roleKey);

  // نجيبهم هنا على الخادم بدل fetch من المتصفح: أسرع (رحلة واحدة
  // بدل تلاتة) وأبسط للقوائم اللي محتاجة تتعرض فوراً
  const [team, branchOptions, allBranches] = await Promise.all([
    canViewUsers ? listTeam(container.users, user) : Promise.resolve([]),
    canCreateUsers ? listBranchesForActor(container.users, user) : Promise.resolve([]),
    canManageBranches ? listBranches(container.branchOps, user) : Promise.resolve([]),
  ]);

  return c.html(
    dashboardPage({
      currentUserId: user.id,
      fullName: user.fullName,
      roleKey: user.roleKey,
      roleLabel: ROLE_LABELS[user.roleKey] ?? user.roleKey,
      permissions: user.permissions,
      canBroadcast: user.permissions.includes(PERMISSIONS.ANNOUNCEMENT_BROADCAST),
      canViewUsers,
      canCreateUsers,
      canEditUsers,
      canManageBranches,
      team,
      branches: branchOptions,
      allBranches,
      idleTimeoutSeconds: idleRule.seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRule.action,
    }),
  );
});

/**
 * صفحة الخزينة.
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

  const [balances, movements, reasons, team, pending] = await Promise.all([
    listBalances(container.treasury, user),
    listMovements(container.treasury, user),
    listExpenseReasons(container.treasury, user),
    user.permissions.includes(PERMISSIONS.USER_VIEW)
      ? listTeam(container.users, user)
      : Promise.resolve([]),
    canApprove ? listMovements(container.treasury, user, 'PENDING') : Promise.resolve([]),
  ]);

  return c.html(
    treasuryPage({
      currentUserId: user.id,
      fullName: user.fullName,
      roleKey: user.roleKey,
      canApprove,
      balances,
      movements,
      pending,
      reasons,
      team: team.filter((t) => t.isActive),
      idleTimeoutSeconds: idleRuleFor(user.roleKey).seconds,
      idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
      idleAction: idleRuleFor(user.roleKey).action,
    }),
  );
});

// ═══════════════════ البوّابة السرّية ═══════════════════

/**
 * لازم تتسجّل **آخر حاجة**، عشان المسارات الثابتة فوق تاخد أولويتها.
 *
 * ══ كن صريح مع نفسك ══
 * المسار المخفي **مطبّ سرعة، مش قفل**. بيخبّي الباب عن الماسحات
 * الآلية، لكنه ما بيصمدش قدّام حد يعرف العنوان.
 *
 * الأقفال الحقيقية الأربعة، وكلها شغّالة:
 *   1) المفتاح التاني بعد كلمة المرور
 *   2) حدّ 5 محاولات لكل 15 دقيقة على البوّابة دي
 *   3) قائمة IP مسموحة
 *   4) فصل البوّابات (المالك ما يدخلش من باب الموظفين والعكس)
 */
app.get('/:maybeSecret', (c) => {
  const secret = superAdminPath(c.env);
  if (!secret || c.req.param('maybeSecret') !== secret) return c.notFound();

  const allowList = (c.env.SUPER_ADMIN_ALLOWED_IPS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowList.length > 0) {
    const ip = getRequestContext(c).ipAddress ?? '';
    // 404 مش 403: ما نأكّدش للمهاجم إنه لقى الباب الصح
    if (!allowList.includes(ip)) return c.notFound();
  }

  c.header('X-Robots-Tag', 'noindex, nofollow');
  return c.html(vaultPage());
});

export default app;
