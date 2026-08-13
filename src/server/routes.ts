/**
 * كل مسارات الـ API
 *
 * تلات مجموعات في ملف واحد: المصادقة، الإعلانات، الإعداد.
 *
 * لاحظ إن كل معالج هنا قصير جداً. دي علامة صحة معمارية:
 * المسار مجرد "موظف استقبال" — بيستلم الطلب، ينادي المدرّب
 * (use-case)، ويغلّف النتيجة. كل المنطق الحقيقي في مجلد application.
 */

import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import type { Context } from 'hono';
import { checkSession, login, logout, refreshSession } from '../application/use-cases/auth';
import {
  acknowledgeAnnouncement,
  broadcastAnnouncement,
  getPendingAnnouncements,
} from '../application/use-cases/announcements';
import {
  createUser,
  listBranchesForActor,
  listTeam,
  setUserActive,
  type CreatableRole,
} from '../application/use-cases/users';
import { createBranch, listBranches } from '../application/use-cases/branches';
import {
  buildContainer,
  clearAuthCookies,
  getRequestContext,
  readJson,
  setAuthCookies,
} from './runtime';
import { requireAuth, type AppBindings } from './guard';
import { COOKIES, SESSION_POLICY, superAdminPath } from '../domain/config';
import { PERMISSIONS } from '../domain/permissions';
import { Errors } from '../domain/errors';
import { createHasher, verifyAccessToken } from '../infrastructure/crypto';

// ═══════════════════ 1) المصادقة ═══════════════════

export const authRoutes = new Hono<AppBindings>();

interface LoginBody {
  username?: string;
  password?: string;
  adminPasskey?: string;
  gate?: 'staff' | 'admin';
}

authRoutes.post('/login', async (c) => {
  const body = await readJson<LoginBody>(c);

  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (!username || !password) throw Errors.validation('أدخل اسم المستخدم وكلمة المرور.');
  if (username.length > 64 || password.length > 1024) {
    throw Errors.validation('طول البيانات المدخلة غير مقبول.');
  }

  /**
   * نقطة أمنية جوهرية: مش بنصدّق حقل gate الجاي من المتصفح لوحده.
   * بنتأكد إن الطلب جاي فعلاً من الصفحة السرّية. لو اعتمدنا على
   * الجسم بس، أي مهاجم هيبعت gate:"admin" ببساطة.
   */
  const referer = c.req.header('referer') ?? '';
  const secret = superAdminPath(c.env);
  const viaAdminGate = body.gate === 'admin' && secret.length > 0 && referer.includes(`/${secret}`);

  const container = buildContainer(c.env);
  const result = await login(
    container.auth,
    { username, password, adminPasskey: body.adminPasskey, viaAdminGate },
    getRequestContext(c),
  );

  setAuthCookies(c, result);

  // التوكنات نفسها ما بتترسلش في الجسم خالص — في الكوكيز بس
  return c.json({
    ok: true,
    user: {
      id: result.user.id,
      fullName: result.user.fullName,
      roleKey: result.user.roleKey,
      branchId: result.user.branchId,
      permissions: result.user.permissions,
      mustChangePassword: result.user.mustChangePassword,
    },
    redirectTo: result.user.roleKey === 'SUPER_ADMIN' ? '/app' : '/app',
  });
});

authRoutes.post('/refresh', async (c) => {
  const raw = getCookie(c, COOKIES.REFRESH);
  if (!raw) throw Errors.sessionExpired();

  const container = buildContainer(c.env);
  const result = await refreshSession(container.auth, raw, getRequestContext(c));

  setAuthCookies(c, result);

  return c.json({
    ok: true,
    user: {
      id: result.user.id,
      fullName: result.user.fullName,
      roleKey: result.user.roleKey,
      permissions: result.user.permissions,
    },
  });
});

authRoutes.post('/logout', async (c) => {
  let sessionId: string | null = null;

  try {
    const token = getCookie(c, COOKIES.ACCESS);
    if (token) sessionId = (await verifyAccessToken(token, c.env.JWT_SECRET)).sid;
  } catch {
    // بطاقة تالفة أو منتهية — مش مهم، هنمسح الكوكيز على أي حال
  }

  try {
    await logout(buildContainer(c.env).auth, sessionId, getRequestContext(c));
  } catch (error) {
    console.error('[logout] فشل إلغاء الجلسة:', error);
  }

  clearAuthCookies(c);
  return c.json({ ok: true });
});

authRoutes.get('/session', requireAuth(), (c) => {
  const user = c.get('user');

  return c.json({
    ok: true,
    user: {
      id: user.id,
      fullName: user.fullName,
      roleKey: user.roleKey,
      branchId: user.branchId,
      permissions: user.permissions,
      mustChangePassword: user.mustChangePassword,
    },
    idleTimeoutSeconds: SESSION_POLICY.IDLE_TIMEOUT_SECONDS,
    idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
  });
});


// ═══════════════════ 2) الإعلانات ═══════════════════

export const announcementRoutes = new Hono<AppBindings>();

announcementRoutes.get(
  '/pending',
  requireAuth({
    requireAll: [PERMISSIONS.ANNOUNCEMENT_VIEW],
    // مش بنحدّث ختم النشاط هنا: ده نداء تلقائي بعد الدخول،
    // مش دليل إن الموظف لسه قدّام الجهاز.
    touchActivity: false,
  }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await getPendingAnnouncements(container.announcements, c.get('user'));
    return c.json({ ok: true, items });
  },
);

announcementRoutes.post(
  '/:id/ack',
  requireAuth({ requireAll: [PERMISSIONS.ANNOUNCEMENT_VIEW] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الإعلان مفقود.');

    const container = buildContainer(c.env);
    await acknowledgeAnnouncement(container.announcements, c.get('user'), id);
    return c.json({ ok: true });
  },
);

const SEVERITIES = ['INFO', 'WARNING', 'CRITICAL'] as const;
const AUDIENCES = ['ALL', 'MANAGERS_ONLY', 'STAFF_ONLY', 'SINGLE_BRANCH'] as const;

interface BroadcastBody {
  title?: string;
  body?: string;
  severity?: (typeof SEVERITIES)[number];
  audience?: (typeof AUDIENCES)[number];
  branchId?: string | null;
  isMandatory?: boolean;
  endsAt?: string | null;
}

announcementRoutes.post(
  '/',
  // الصلاحية متفحوصة هنا **وكمان** جوّه حالة الاستخدام.
  // التكرار مقصود: الخزنة مقفولة حتى جوّه الأوضة المقفولة.
  requireAuth({ requireAll: [PERMISSIONS.ANNOUNCEMENT_BROADCAST] }),
  async (c) => {
    const body = await readJson<BroadcastBody>(c);

    const severity = body.severity ?? 'INFO';
    const audience = body.audience ?? 'ALL';

    // ما تثقش أبداً في قيم جاية من المتصفح: افحصها مقابل قائمة مقفولة
    if (!SEVERITIES.includes(severity)) throw Errors.validation('درجة الأهمية غير معروفة.');
    if (!AUDIENCES.includes(audience)) throw Errors.validation('الجمهور المستهدف غير معروف.');

    let endsAt: Date | null = null;
    if (body.endsAt) {
      const parsed = new Date(body.endsAt);
      if (Number.isNaN(parsed.getTime())) throw Errors.validation('تاريخ الانتهاء غير صالح.');
      endsAt = parsed;
    }

    const container = buildContainer(c.env);
    const created = await broadcastAnnouncement(container.announcements, c.get('user'), {
      title: body.title ?? '',
      body: body.body ?? '',
      severity,
      audience,
      branchId: body.branchId ?? null,
      isMandatory: body.isMandatory ?? true,
      endsAt,
    });

    return c.json({ ok: true, id: created.id }, 201);
  },
);


// ═══════════════════ 3) الإعداد لمرّة واحدة ═══════════════════

export const setupRoutes = new Hono<AppBindings>();

/** مقارنة أسرار بزمن ثابت — عشان طول المقارنة ما يفضحش حاجة */
function secretsMatch(provided: string, expected: string): boolean {
  if (provided.length !== expected.length) return false;

  let diff = 0;
  for (let i = 0; i < provided.length; i++) {
    diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

setupRoutes.post('/api/setup', async (c) => {
  const expected = c.env.SETUP_SECRET;

  // القفل الأول: السرّ مش مضبوط = الباب مقفول تماماً
  if (!expected || expected.length < 16) {
    throw Errors.notFound('الصفحة');
  }

  const form = await c.req.parseBody();
  const setupSecret = String(form.setupSecret ?? '');
  const username = String(form.username ?? '').trim().toLowerCase();
  const fullName = String(form.fullName ?? '').trim();
  const password = String(form.password ?? '');
  const passkey = String(form.passkey ?? '');

  // القفل التاني: السرّ الصح
  if (!secretsMatch(setupSecret, expected)) {
    console.warn('[setup] محاولة بسرّ خاطئ من', getRequestContext(c).ipAddress);
    throw Errors.notFound('الصفحة'); // 404 مش 403: ما نأكّدش إن الباب موجود
  }

  const container = buildContainer(c.env);
  const db = container.db;

  // القفل التالت: فيه مالك أصلاً؟
  const { data: ownerExists, error: checkError } = await db.rpc('fn_owner_exists');
  if (checkError) throw Errors.internal(`fn_owner_exists: ${checkError.message}`);
  if (ownerExists === true) {
    throw Errors.forbidden('حساب المالك موجود بالفعل. امسح SETUP_SECRET من إعدادات كلاودفلير.');
  }

  // فحص المدخلات
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    throw Errors.validation('اسم المستخدم: حروف إنجليزية صغيرة وأرقام فقط، من 3 إلى 32 حرف.');
  }
  if (fullName.length < 3) throw Errors.validation('اكتب الاسم الكامل.');
  if (password.length < 12) throw Errors.validation('كلمة المرور 12 حرف على الأقل.');
  if (passkey.length < 16) throw Errors.validation('المفتاح السرّي 16 حرف على الأقل.');
  if (password === passkey) {
    throw Errors.validation('المفتاح السرّي لازم يكون مختلف عن كلمة المرور تماماً.');
  }

  const { data: role, error: roleError } = await db
    .from('roles')
    .select('id')
    .eq('key', 'SUPER_ADMIN')
    .single();

  if (roleError || !role) {
    throw Errors.internal('دور SUPER_ADMIN مش موجود — شغّل ملفات SQL الأول.');
  }

  const iterations = Number.parseInt(c.env.PBKDF2_ITERATIONS ?? '100000', 10);
  const hasher = createHasher(Number.isFinite(iterations) ? iterations : 100_000);

  const { error: insertError } = await db.from('users').insert({
    username,
    full_name: fullName,
    password_hash: await hasher.hash(password),
    admin_passkey_hash: await hasher.hash(passkey),
    role_id: role.id,
    branch_id: null, // المالك فوق الفروع، مش جوّه فرع
    is_active: true,
    must_change_password: false,
  });

  if (insertError) throw Errors.internal(`user insert: ${insertError.message}`);

  await container.auth.audit.record({
    action: 'setup.owner_created',
    entity: 'User',
    ipAddress: getRequestContext(c).ipAddress,
    metadata: { username },
  });

  return c.json({
    ok: true,
    message: 'تم إنشاء حساب المالك. امسح SETUP_SECRET من إعدادات كلاودفلير دلوقتي.',
  });
});


// ═══════════════════ 4) المستخدمون والفروع ═══════════════════
//
// تشبيه: كشف الأحزمة في النادي. المالك يمنح أي حزام لأي صالة.
// مدير الفرع يرقّي جوّه صالته هو بس — والقاعدة دي مفروضة في
// application/use-cases/users.ts، مش هنا. هنا مجرد استقبال وتسليم.

export const userRoutes = new Hono<AppBindings>();

/** قائمة الفريق — المالك يرى الجميع، مدير الفرع يرى فرعه فقط */
userRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.USER_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listTeam(container.users, c.get('user'));
    return c.json({ ok: true, items });
  },
);

interface CreateUserBody {
  username?: string;
  fullName?: string;
  password?: string;
  roleKey?: string;
  branchId?: string | null;
}

const CREATABLE_ROLES: CreatableRole[] = ['BRANCH_MANAGER', 'STAFF'];

userRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.USER_CREATE] }), async (c) => {
  const body = await readJson<CreateUserBody>(c);

  // لا نثق بقيمة roleKey القادمة من المتصفح إلا بعد مطابقتها
  // بقائمة مغلقة — هذا ما يمنع مرور "SUPER_ADMIN" في الطلب
  if (!CREATABLE_ROLES.includes(body.roleKey as CreatableRole)) {
    throw Errors.validation('الدور غير معروف.');
  }

  const container = buildContainer(c.env);
  const created = await createUser(container.users, c.get('user'), {
    username: body.username ?? '',
    fullName: body.fullName ?? '',
    password: body.password ?? '',
    roleKey: body.roleKey as CreatableRole,
    branchId: body.branchId ?? null,
  });

  return c.json({ ok: true, id: created.id }, 201);
});

export const branchRoutes = new Hono<AppBindings>();

/** قائمة الفروع النشطة — تُستخدم لملء القائمة المنسدلة عند إنشاء حساب */
branchRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.USER_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listBranchesForActor(container.users, c.get('user'));
    return c.json({ ok: true, items });
  },
);

/** إنشاء فرع — المالك فقط (`BRANCH_MANAGE` غائبة عن مدير الفرع عمدًا) */
branchRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.BRANCH_MANAGE] }), async (c) => {
  const body = await readJson<{
    code?: string;
    name?: string;
    address?: string | null;
    phone?: string | null;
  }>(c);

  const container = buildContainer(c.env);
  const created = await createBranch(container.branchOps, c.get('user'), {
    code: body.code ?? '',
    name: body.name ?? '',
    address: body.address ?? null,
    phone: body.phone ?? null,
  });

  return c.json({ ok: true, id: created.id }, 201);
});

/** تعطيل / إعادة تفعيل حساب */
userRoutes.post(
  '/:id/active',
  requireAuth({ requireAll: [PERMISSIONS.USER_EDIT] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الحساب مفقود.');

    const body = await readJson<{ isActive?: boolean }>(c);
    if (typeof body.isActive !== 'boolean') {
      throw Errors.validation('القيمة المطلوبة غير صحيحة.');
    }

    const container = buildContainer(c.env);
    await setUserActive(container.users, c.get('user'), id, body.isActive);

    return c.json({ ok: true });
  },
);
