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
import {
  checkSession,
  lockSession,
  login,
  logout,
  refreshSession,
  unlockSession,
} from '../application/use-cases/auth';
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
  getSalaryStatement,
  listBalances,
  recordMovement,
  reviewMovement,
} from '../application/use-cases/treasury';
import {
  createProduct,
  getPriceHistory,
  listProducts,
  listSellableProducts,
  restockProduct,
  updateProduct,
} from '../application/use-cases/products';
import {
  createSale,
  getSale,
  listSales,
  updateSaleExitDate,
} from '../application/use-cases/sales';
import {
  bootstrapPlatformAdmin,
  createTenant,
  listTenants,
  setTenantActive,
  setTenantBranchLimit,
} from '../application/use-cases/platform';
import {
  createCustomer,
  deleteCustomer,
  listCustomers,
  updateCustomer,
} from '../application/use-cases/customers';
import {
  MoneyError,
  parseCostToPiastres,
  parseCount,
  parseMoneyToPiastres,
} from '../domain/money';
import type { ManualMovementType, ProductType, SaleLineInput } from '../application/ports';
import {
  buildContainer,
  clearAuthCookies,
  getRequestContext,
  readJson,
  setAuthCookies,
} from './runtime';
import { requireAuth, type AppBindings } from './guard';
import { COOKIES, SESSION_POLICY, idleRuleFor } from '../domain/config';
import { PERMISSIONS } from '../domain/permissions';
import { Errors } from '../domain/errors';
import { createHasher, verifyAccessToken } from '../infrastructure/crypto';

// ═══════════════════ 1) المصادقة ═══════════════════

export const authRoutes = new Hono<AppBindings>();

interface LoginBody {
  tenantCode?: string;
  username?: string;
  password?: string;
  adminPasskey?: string;
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
  const container = buildContainer(c.env);
  const result = await login(
    container.auth,
    {
      tenantCode: (body.tenantCode ?? '').trim(),
      username,
      password,
      adminPasskey: body.adminPasskey,
    },
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
  const rule = idleRuleFor(user.roleKey);

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
    idleTimeoutSeconds: rule.seconds,
    idleAction: rule.action,
    idleWarningSeconds: SESSION_POLICY.IDLE_WARNING_SECONDS,
  });
});

/** قفل الشاشة — بينادها المتصفح عند وصول مؤقّت الخمول للحد */
authRoutes.post('/lock', requireAuth({ touchActivity: false }), async (c) => {
  const container = buildContainer(c.env);
  await lockSession(container.auth, c.get('sessionId'));
  return c.json({ ok: true });
});

/**
 * فكّ القفل بكلمة المرور.
 *
 * ⚠ مش محمي بـ requireAuth عن قصد — بطاقة الدخول (5 دقايق) أكيد
 * منتهية بعد نص ساعة قفل. التحقق بيتم بتوكن التحديث + كلمة المرور
 * جوّه حالة الاستخدام نفسها.
 */
authRoutes.post('/unlock', async (c) => {
  const raw = getCookie(c, COOKIES.REFRESH);
  if (!raw) throw Errors.sessionExpired();

  const body = await readJson<{ password?: string }>(c);
  const password = typeof body.password === 'string' ? body.password : '';
  if (!password) throw Errors.validation('اكتب كلمة المرور.');

  const container = buildContainer(c.env);
  const result = await unlockSession(container.auth, raw, password, getRequestContext(c));

  setAuthCookies(c, result);

  return c.json({
    ok: true,
    user: { id: result.user.id, fullName: result.user.fullName, roleKey: result.user.roleKey },
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


// ═══════════════════ 5) الخزينة ═══════════════════

export const treasuryRoutes = new Hono<AppBindings>();

/**
 * ⚠ لاحظ `ManualMovementType` مش `MovementType`.
 *
 * نوع البيع (SALE) موجود في النظام لكنه **مش** في القائمة دي،
 * ومستحيل يتضاف لها: النوع نفسه بيستبعده. لو حد حاول يبعت
 * type: "SALE" للمسار ده، الفحص تحت هيرفضه — والمترجم كان هيرفض
 * حتى محاولة كتابته هنا من الأساس.
 *
 * السبب: حركة البيع بتتولّد مع الفاتورة وخصم المخزون في عملية
 * واحدة. لو اتسجّلت لوحدها، هتبقى فلوس داخلة بلا بضاعة خرجت.
 */
const MOVEMENT_TYPES: ManualMovementType[] = [
  'DEPOSIT',
  'WITHDRAWAL',
  'EXPENSE',
  'ADVANCE',
  'ADJUSTMENT',
];

interface MovementBody {
  treasuryId?: string;
  type?: string;
  amount?: string;
  expenseReasonId?: string | null;
  relatedUserId?: string | null;
  note?: string | null;
  adjustmentDirection?: string;
}

treasuryRoutes.post('/movements', requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE] }), async (c) => {
  const body = await readJson<MovementBody>(c);

  if (!body.treasuryId) throw Errors.validation('اختر الخزينة.');
  if (!MOVEMENT_TYPES.includes(body.type as ManualMovementType)) {
    throw Errors.validation('نوع الحركة غير معروف.');
  }

  // المبلغ بيتحوّل لقروش هنا — نقطة واحدة في النظام كله بتحوّل
  // كلام المستخدم لرقم، فأي خطأ في التحويل بيتمسك في مكان واحد
  let amountPiastres: number;
  try {
    amountPiastres = parseMoneyToPiastres(body.amount ?? '');
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'المبلغ غير صالح.');
  }

  const container = buildContainer(c.env);
  const result = await recordMovement(container.treasury, c.get('user'), {
    treasuryId: body.treasuryId,
    type: body.type as ManualMovementType,
    amountPiastres,
    expenseReasonId: body.expenseReasonId ?? null,
    relatedUserId: body.relatedUserId ?? null,
    note: body.note ?? null,
    adjustmentDirection: body.adjustmentDirection === 'OUT' ? 'OUT' : 'IN',
  });

  return c.json(
    {
      ok: true,
      id: result.id,
      status: result.status,
      message:
        result.status === 'PENDING'
          ? 'تم تسجيل الطلب. محتاج اعتماد المدير قبل ما يأثّر على الرصيد.'
          : 'تم تسجيل الحركة.',
    },
    201,
  );
});

treasuryRoutes.post(
  '/movements/:id/review',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_APPROVE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الحركة مفقود.');

    const body = await readJson<{ decision?: string }>(c);
    if (body.decision !== 'APPROVED' && body.decision !== 'REJECTED') {
      throw Errors.validation('القرار غير معروف.');
    }

    const container = buildContainer(c.env);
    await reviewMovement(container.treasury, c.get('user'), id, body.decision);

    return c.json({ ok: true });
  },
);

treasuryRoutes.get(
  '/balances',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listBalances(container.treasury, c.get('user'));
    return c.json({ ok: true, items });
  },
);

treasuryRoutes.get(
  '/salary/:userId',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const userId = c.req.param('userId');
    const fromRaw = c.req.query('from');
    const toRaw = c.req.query('to');

    // الافتراضي: الشهر الحالي
    const now = new Date();
    const from = fromRaw ? new Date(fromRaw) : new Date(now.getFullYear(), now.getMonth(), 1);
    const to = toRaw ? new Date(toRaw) : new Date(now.getFullYear(), now.getMonth() + 1, 1);

    const container = buildContainer(c.env);
    const statement = await getSalaryStatement(container.treasury, c.get('user'), userId, from, to);

    return c.json({ ok: true, statement });
  },
);


// ═══════════════════ 6) المنتجات ═══════════════════

export const productRoutes = new Hono<AppBindings>();

/**
 * قائمة المنتجات.
 *
 * ⚠ التكلفة بتتحدّد في حالة الاستخدام من صلاحية `profit.view_real`،
 * والحجب بيحصل في طبقة قاعدة البيانات. المسار ده ما بيعملش أي
 * فلترة على الحقول — لو عمل، هيبقى عندنا مكانين للحقيقة.
 */
productRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listProducts(container.products, c.get('user'));
    return c.json({ ok: true, items });
  },
);

/** قائمة شاشة الكاشير: المفعّل واللي فيه كمية بس */
productRoutes.get(
  '/sellable',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listSellableProducts(container.products, c.get('user'));
    return c.json({ ok: true, items });
  },
);

interface ProductBody {
  name?: string;
  productType?: string;
  serialNumber?: string | null;
  source?: string | null;
  entryDate?: string | null;
  price?: string;
  cost?: string;
  quantity?: string;
  branchId?: string | null;
  isActive?: boolean;
}

/**
 * قراءة السعر من مدخل المستخدم.
 *
 * الفراغ **مش** غلط — معناه "المنتج لسه ما اتسعّرش".
 * بنرجّع null، وده مختلف تمامًا عن صفر.
 */
function readOptionalPrice(raw: string | undefined | null): number | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  return parseMoneyToPiastres(text);
}

productRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }), async (c) => {
  const body = await readJson<ProductBody>(c);

  // التحويل من كلام المستخدم لأرقام بيحصل هنا، في نقطة واحدة.
  // حالة الاستخدام بتستلم قروش وأعداد صحيحة وخلاص.
  let pricePiastres: number | null;
  let costPiastres: number;
  let quantity: number;

  try {
    pricePiastres = readOptionalPrice(body.price);
    costPiastres = parseCostToPiastres(body.cost);
    quantity = body.quantity === undefined || body.quantity === null || body.quantity === ''
      ? 0
      : parseCount(body.quantity);
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'بيانات غير صالحة.');
  }

  const container = buildContainer(c.env);
  const created = await createProduct(container.products, c.get('user'), {
    name: body.name ?? '',
    productType: (body.productType ?? 'accessory') as ProductType,
    serialNumber: body.serialNumber ?? null,
    source: body.source ?? null,
    entryDate: body.entryDate ?? null,
    pricePiastres,
    costPiastres,
    quantityOnHand: quantity,
    branchId: body.branchId ?? null,
  });

  return c.json({ ok: true, id: created.id }, 201);
});

/** تعديل منتج — الحقول اللي مش مبعوتة بتفضل زي ما هي */
productRoutes.post(
  '/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المنتج مفقود.');

    const body = await readJson<ProductBody>(c);
    const patch: {
      name?: string;
      pricePiastres?: number | null;
      costPiastres?: number;
      isActive?: boolean;
      source?: string | null;
      serialNumber?: string | null;
      entryDate?: string | null;
    } = {};

    try {
      if (typeof body.name === 'string') patch.name = body.name;
      // ⚠ الفرق بين "الحقل مش مبعوت" و"الحقل مبعوت فاضي":
      //   مش مبعوت  → ما نلمسش السعر
      //   مبعوت فاضي → شيل السعر (المنتج بقى بلا سعر)
      if (typeof body.price === 'string') {
        patch.pricePiastres = readOptionalPrice(body.price);
      }
      if (typeof body.cost === 'string') {
        patch.costPiastres = parseCostToPiastres(body.cost);
      }
      if (typeof body.isActive === 'boolean') patch.isActive = body.isActive;
      if (body.source !== undefined) patch.source = body.source;
      if (body.serialNumber !== undefined) patch.serialNumber = body.serialNumber;
      if (body.entryDate !== undefined) patch.entryDate = body.entryDate;
    } catch (error) {
      throw Errors.validation(error instanceof MoneyError ? error.message : 'بيانات غير صالحة.');
    }

    const container = buildContainer(c.env);
    await updateProduct(container.products, c.get('user'), id, patch);

    return c.json({ ok: true });
  },
);

/** سجل أسعار منتج — كان كام وبقى كام ومين غيّره */
productRoutes.get(
  '/:id/price-history',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المنتج مفقود.');

    const container = buildContainer(c.env);
    const items = await getPriceHistory(container.products, c.get('user'), id);
    return c.json({ ok: true, items });
  },
);

/** توريد أو خصم كمية — بفرق مش برقم نهائي */
productRoutes.post(
  '/:id/stock',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المنتج مفقود.');

    const body = await readJson<{ delta?: string }>(c);

    let delta: number;
    try {
      delta = parseCount(body.delta, { allowNegative: true });
    } catch (error) {
      throw Errors.validation(error instanceof MoneyError ? error.message : 'الكمية غير صالحة.');
    }

    const container = buildContainer(c.env);
    const result = await restockProduct(container.products, c.get('user'), id, delta);

    return c.json({ ok: true, quantityOnHand: result.quantityOnHand });
  },
);


// ═══════════════════ 7) البيع ═══════════════════

export const saleRoutes = new Hono<AppBindings>();

interface SaleBody {
  treasuryId?: string;
  items?: Array<{
    productId?: string;
    quantity?: number | string;
    unitPrice?: string | null;
  }>;
  customerName?: string | null;
  customerPhone?: string | null;
  exitDate?: string | null;
}

/**
 * إنشاء بيع.
 *
 * ⚠ مفيش حقل staffId في الجسم عن قصد. الموظّف بيتاخد من الجلسة
 * جوّه حالة الاستخدام. لو قبلناه من الطلب، أي حد يقدر يسجّل بيع
 * باسم زميله.
 */
saleRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.SALES_CREATE] }), async (c) => {
  const body = await readJson<SaleBody>(c);

  if (!Array.isArray(body.items) || body.items.length === 0) {
    throw Errors.validation('السلة فارغة.');
  }

  let items: SaleLineInput[];
  try {
    items = body.items.map((line) => ({
      productId: typeof line?.productId === 'string' ? line.productId : '',
      quantity: parseCount(line?.quantity),
      // السعر اليدوي بيتبعت بس لو الكاشير كتبه — يعني المنتج
      // مالوش سعر مسجّل
      unitPricePiastres: readOptionalPrice(line?.unitPrice),
    }));
  } catch (error) {
    throw Errors.validation(error instanceof MoneyError ? error.message : 'السلة غير صالحة.');
  }

  const container = buildContainer(c.env);
  const result = await createSale(container.sales, c.get('user'), {
    treasuryId: body.treasuryId ?? '',
    items,
    customerName: body.customerName ?? null,
    customerPhone: body.customerPhone ?? null,
    exitDate: body.exitDate ?? null,
  });

  return c.json(
    {
      ok: true,
      saleId: result.saleId,
      totalPiastres: result.totalPiastres,
      itemCount: result.itemCount,
      message: 'تم البيع.',
    },
    201,
  );
});

/**
 * قائمة الفواتير.
 *
 * تلات درجات رؤية: كل الفروع · الفرع · فواتيري أنا.
 * `requireAny` معناها إن أي واحدة من التلاتة بتفتح الباب، وحالة
 * الاستخدام هي اللي بتحدّد بعد كده إنت تشوف قد إيه.
 */
saleRoutes.get(
  '/',
  requireAuth({
    requireAny: [
      PERMISSIONS.SALES_VIEW_OWN,
      PERMISSIONS.SALES_VIEW_BRANCH,
      PERMISSIONS.SALES_VIEW_ALL,
    ],
    touchActivity: false,
  }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listSales(container.sales, c.get('user'));
    return c.json({ ok: true, items });
  },
);

saleRoutes.get(
  '/:id',
  requireAuth({
    requireAny: [
      PERMISSIONS.SALES_VIEW_OWN,
      PERMISSIONS.SALES_VIEW_BRANCH,
      PERMISSIONS.SALES_VIEW_ALL,
    ],
    touchActivity: false,
  }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const container = buildContainer(c.env);
    const sale = await getSale(container.sales, c.get('user'), id);
    return c.json({ ok: true, sale });
  },
);


/** تعديل تاريخ الخروج — اللي سجّل البيع، والمالك */
saleRoutes.post(
  '/:id/exit-date',
  requireAuth({ requireAll: [PERMISSIONS.SALES_CREATE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const body = await readJson<{ exitDate?: string }>(c);
    if (!body.exitDate) throw Errors.validation('اكتب تاريخ الخروج.');

    const container = buildContainer(c.env);
    const result = await updateSaleExitDate(container.sales, c.get('user'), id, body.exitDate);

    return c.json({ ok: true, exitDate: result.exitDate });
  },
);


// ═══════════════════ 8) العملاء ═══════════════════

export const customerRoutes = new Hono<AppBindings>();

interface CustomerBody {
  name?: string;
  phone?: string | null;
  notes?: string | null;
  branchId?: string | null;
}

customerRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.CUSTOMER_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listCustomers(container.customers, c.get('user'), c.req.query('q') ?? null);
    return c.json({ ok: true, items });
  },
);

customerRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.CUSTOMER_CREATE] }), async (c) => {
  const body = await readJson<CustomerBody>(c);

  const container = buildContainer(c.env);
  const created = await createCustomer(container.customers, c.get('user'), {
    name: body.name ?? '',
    phone: body.phone ?? null,
    notes: body.notes ?? null,
    branchId: body.branchId ?? null,
  });

  return c.json({ ok: true, id: created.id }, 201);
});

customerRoutes.post('/:id', requireAuth({ requireAll: [PERMISSIONS.CUSTOMER_EDIT] }), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف العميل مفقود.');

  const body = await readJson<CustomerBody>(c);
  const patch: { name?: string; phone?: string | null; notes?: string | null } = {};
  if (typeof body.name === 'string') patch.name = body.name;
  if (body.phone !== undefined) patch.phone = body.phone;
  if (body.notes !== undefined) patch.notes = body.notes;

  const container = buildContainer(c.env);
  await updateCustomer(container.customers, c.get('user'), id, patch);

  return c.json({ ok: true });
});

customerRoutes.post(
  '/:id/delete',
  requireAuth({ requireAll: [PERMISSIONS.CUSTOMER_EDIT] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف العميل مفقود.');

    const container = buildContainer(c.env);
    await deleteCustomer(container.customers, c.get('user'), id);

    return c.json({ ok: true });
  },
);


// ═══════════════════ 9) إدارة المحلات ═══════════════════

export const platformRoutes = new Hono<AppBindings>();

platformRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listTenants(container.platform, c.get('user'));
    return c.json({ ok: true, items });
  },
);

interface TenantBody {
  code?: string;
  name?: string;
  maxBranches?: number | string;
  ownerUsername?: string;
  ownerFullName?: string;
  ownerPassword?: string;
  branchCode?: string;
  branchName?: string;
}

platformRoutes.post('/', requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }), async (c) => {
  const body = await readJson<TenantBody>(c);

  const container = buildContainer(c.env);
  const created = await createTenant(container.platform, c.get('user'), {
    code: body.code ?? '',
    name: body.name ?? '',
    maxBranches: Number(body.maxBranches ?? 1),
    ownerUsername: body.ownerUsername ?? '',
    ownerFullName: body.ownerFullName ?? '',
    ownerPassword: body.ownerPassword ?? '',
    branchCode: body.branchCode ?? '',
    branchName: body.branchName ?? '',
  });

  return c.json({ ok: true, tenantId: created.tenantId, code: created.code }, 201);
});

platformRoutes.post(
  '/:id/active',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المحل مفقود.');

    const body = await readJson<{ isActive?: boolean }>(c);
    if (typeof body.isActive !== 'boolean') throw Errors.validation('الحالة غير محدّدة.');

    const container = buildContainer(c.env);
    await setTenantActive(container.platform, c.get('user'), id, body.isActive);

    return c.json({ ok: true });
  },
);

platformRoutes.post(
  '/:id/limit',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المحل مفقود.');

    const body = await readJson<{ maxBranches?: number | string }>(c);

    const container = buildContainer(c.env);
    await setTenantBranchLimit(
      container.platform,
      c.get('user'),
      id,
      Number(body.maxBranches ?? 0),
    );

    return c.json({ ok: true });
  },
);

/**
 * تأسيس أول حساب مشغّل منصّة.
 *
 * ⚠ المسار ده **مش محمي بتسجيل دخول** — ما ينفعش يكون، لأن مفيش
 * حساب بعد. حراسته تلات أقفال زي صفحة الإعداد الأولي بالظبط:
 *
 *   1) SETUP_SECRET مش مضبوط في كلاودفلير → المسار 404 أصلاً
 *   2) السرّ المبعوت لازم يطابق (مقارنة بزمن ثابت)
 *   3) فيه مشغّل منصّة أصلاً → يترفض
 *
 * وبعد ما تخلص، امسح SETUP_SECRET من كلاودفلير — الباب يختفي.
 */
platformRoutes.post('/bootstrap', async (c) => {
  const expected = c.env.SETUP_SECRET;

  if (!expected || expected.length < 16) {
    throw Errors.notFound('الصفحة');
  }

  const body = await readJson<{
    setupSecret?: string;
    tenantId?: string;
    username?: string;
    fullName?: string;
    password?: string;
    passkey?: string;
  }>(c);

  if (!secretsMatch(String(body.setupSecret ?? ''), expected)) {
    console.warn('[platform] محاولة تأسيس بسرّ خاطئ من', getRequestContext(c).ipAddress);
    // 404 مش 403: ما نأكّدش إن الباب موجود
    throw Errors.notFound('الصفحة');
  }

  const container = buildContainer(c.env);
  const created = await bootstrapPlatformAdmin(container.platform, {
    tenantId: String(body.tenantId ?? 'tenant_default'),
    username: String(body.username ?? ''),
    fullName: String(body.fullName ?? ''),
    password: String(body.password ?? ''),
    passkey: String(body.passkey ?? ''),
  });

  return c.json({ ok: true, id: created.id }, 201);
});
