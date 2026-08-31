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
import {
  consignToShop,
  createShopAccount,
  listShopAccounts,
  recordShopPayment,
  updateShopAccount,
} from '../application/use-cases/shops';
import { getCookie } from 'hono/cookie';
import type { Context } from 'hono';
import {
  checkSession,
  lockSession,
  changeOwnPassword,
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
  createExpenseReason,
  createTreasury,
  getFinancialSummary,
  getSalaryStatement,
  listBalances,
  listTransfers,
  recordMovement,
  reviewMovement,
  transferBetweenTreasuries,
  updateTreasury,
} from '../application/use-cases/treasury';
import {
  createCategory,
  createColor,
  createModel,
  createProduct,
  deleteCategory,
  deleteColor,
  deleteModel,
  getPriceHistory,
  listCategories,
  listColors,
  listModels,
  listProducts,
  listSellableProducts,
  renameCategory,
  restockProduct,
  updateColor,
  updateModel,
  updateProduct,
} from '../application/use-cases/products';
import {
  DEFAULT_WARRANTY_DAYS,
  createSale,
  getSale,
  getSaleWarranty,
  listSales,
  setSaleWarranty,
  updateSaleExitDate,
} from '../application/use-cases/sales';
import { getIncomeReport } from '../application/use-cases/reports';
import { listAlerts } from '../application/use-cases/alerts';
import {
  createRepairShop,
  createTicket,
  getProductMaintenance,
  getShopHistory,
  getTicketUnlock,
  listMaintenanceRecords,
  listRepairShops,
  listTickets,
  returnFromMaintenance,
  sendToMaintenance,
  updateTicket,
  updateTicketUnlock,
} from '../application/use-cases/maintenance';
import {
  createSupplier,
  listSuppliers,
  recordSupplierDebt,
  recordSupplierDiscount,
  recordSupplierPayment,
  updateSupplier,
} from '../application/use-cases/suppliers';
import {
  createTransfer,
  listPendingTransfers,
  resolveTransfer,
} from '../application/use-cases/transfers';
import {
  createReturn,
  getReturnContext,
  getReturnableLines,
  listQuarantine,
  reviewQuarantine,
} from '../application/use-cases/returns';
import {
  listPurchases,
  listSupplierNames,
  recordPurchase,
} from '../application/use-cases/purchases';
import {
  closeDay,
  getClosing,
  listClosings,
  previewClosing,
  setClosingRoles,
} from '../application/use-cases/closings';
import {
  bootstrapPlatformAdmin,
  broadcast,
  createTenant,
  getTenantCensus,
  listPlatformAnnouncements,
  listTenantBranches,
  listTenants,
  purgeTenant,
  setTenantActive,
  setTenantBranchLimit,
  withdrawAnnouncement,
} from '../application/use-cases/platform';
import {
  createCustomer,
  deleteCustomer,
  listCustomers,
  updateCustomer,
} from '../application/use-cases/customers';
import {
  MoneyError,
  normalizeDigits,
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


/** تغيير كلمة المرور — المستخدم لنفسه */
authRoutes.post('/password', requireAuth(), async (c) => {
  const body = await readJson<{ currentPassword?: string; newPassword?: string }>(c);

  if (!body.currentPassword) throw Errors.validation('اكتب كلمة المرور الحالية.');
  if (!body.newPassword) throw Errors.validation('اكتب كلمة المرور الجديدة.');

  const container = buildContainer(c.env);
  await changeOwnPassword(
    container.auth,
    c.get('user'),
    body.currentPassword,
    body.newPassword,
  );

  // كل الجلسات اتقفلت — الكوكيز بقت بلا قيمة، فبنمسحها
  clearAuthCookies(c);

  return c.json({ ok: true, message: 'تم تغيير كلمة المرور. سجّل الدخول من جديد.' });
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


// ═══════════════════ 5) الخزنة ═══════════════════

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

/**
 * سبب صرف جديد.
 *
 * ⚠ `expense.approve` مش `expense.create` — السبب بند في قائمة
 * الدخل مش بيان على الحركة. شوف التعليق في حالة الاستخدام.
 */
treasuryRoutes.post(
  '/expense-reasons',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_APPROVE] }),
  async (c) => {
    const body = await readJson<{ name?: string }>(c);
    const container = buildContainer(c.env);
    const created = await createExpenseReason(container.treasury, c.get('user'), body.name);
    return c.json({ ok: true, id: created.id }, 201);
  },
);

treasuryRoutes.post('/movements', requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE] }), async (c) => {
  const body = await readJson<MovementBody>(c);

  if (!body.treasuryId) throw Errors.validation('اختر الخزنة.');
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


/**
 * الملخّص المالي — فلوسك فين.
 *
 * ⚠ نداء واحد بيرجّع الصفوف والمجاميع مع بعض، لأنهم متحسبين
 * من **نفس** البيانات. لو الشاشة طلبت المجاميع في نداء تاني،
 * كان ممكن يوصلها إجمالي من لحظة وأجزاء من لحظة تانية.
 */
treasuryRoutes.get(
  '/summary',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const summary = await getFinancialSummary(container.treasury, c.get('user'));
    return c.json({ ok: true, ...summary });
  },
);

/**
 * إنشاء خزنة — صاحب المحل وحده.
 *
 * ⚠ الحارس هنا بـ`EXPENSE_CREATE` بس؛ فحص الدور جوّه حالة
 * الاستخدام وجوّه دالة القاعدة. مفيش صلاحية مخصّصة لإنشاء
 * الخزن، وعمل واحدة عشان فعل بيحصل مرة كل شهور كان هيزوّد
 * الكتالوج بلا فايدة.
 */
treasuryRoutes.post(
  '/treasuries',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE] }),
  async (c) => {
    const body = await readJson<{
      branchId?: string;
      name?: string;
      type?: string;
      provider?: string | null;
    }>(c);

    const container = buildContainer(c.env);
    const created = await createTreasury(container.treasury, c.get('user'), {
      branchId: String(body.branchId ?? ''),
      name: String(body.name ?? ''),
      type: String(body.type ?? ''),
      provider: body.provider ?? null,
    });

    return c.json({ ok: true, ...created, message: 'تمت إضافة الخزنة.' }, 201);
  },
);

/**
 * تعديل خزنة.
 *
 * ⚠ مفيش حقل للنوع هنا عن قصد. تحويل خزنة من نقدي لمحفظة بعد
 * ما اتسجّل عليها حركات معناه إن كل حركة قديمة بقت في مكان غير
 * اللي حصلت فيه — والدفتر بيكدب بأثر رجعي.
 */
treasuryRoutes.patch(
  '/treasuries/:id',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الخزنة مفقود.');

    const body = await readJson<{
      name?: string | null;
      provider?: string | null;
      isActive?: boolean | null;
    }>(c);

    const container = buildContainer(c.env);
    const result = await updateTreasury(container.treasury, c.get('user'), id, body);

    return c.json({ ok: true, ...result, message: 'تم حفظ التعديل.' });
  },
);

/**
 * تحويل بين خزنتين.
 *
 * ⚠ الطلب بياخد **طلع كام** و**وصل كام** — مفيش خانة للعمولة.
 * هي الفرق بينهم، بتتحسب في القاعدة وبيحرسها قيد.
 *
 * لو كانت خانة تالتة، كان ممكن تتبعت أرقام متناقضة (طلع ١٠٠٠،
 * وصل ٩٨٠، عمولة ٥٠) ومحدش يعرف مين الصح.
 */
treasuryRoutes.post(
  '/transfers',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_APPROVE] }),
  async (c) => {
    const body = await readJson<{
      fromTreasuryId?: string;
      toTreasuryId?: string;
      sent?: string;
      received?: string;
      note?: string | null;
      date?: string | null;
    }>(c);

    const container = buildContainer(c.env);
    const result = await transferBetweenTreasuries(container.treasury, c.get('user'), {
      fromTreasuryId: String(body.fromTreasuryId ?? ''),
      toTreasuryId: String(body.toTreasuryId ?? ''),
      sent: String(body.sent ?? ''),
      received: String(body.received ?? ''),
      note: body.note ?? null,
      date: body.date ?? null,
    });

    return c.json(
      {
        ok: true,
        ...result,
        message:
          result.feePiastres > 0
            ? `تم التحويل. العمولة ${(result.feePiastres / 100).toFixed(2)} ج.م`
            : 'تم التحويل بلا عمولة.',
      },
      201,
    );
  },
);

treasuryRoutes.get(
  '/transfers',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const transfers = await listTransfers(
      container.treasury,
      c.get('user'),
      c.req.query('from') ?? null,
      c.req.query('to') ?? null,
    );
    return c.json({ ok: true, transfers });
  },
);


// ═══════════════════ 6) البضاعة ═══════════════════

export const productRoutes = new Hono<AppBindings>();

/**
 * قائمة البضاعة.
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

// ═══════════════════ أدراج البضاعة ═══════════════════
//
// ⚠ المسارات دي تحت `/api/products/categories`، وترتيبها قبل
// `/:id` **مقصود**: هونو بيطابق أول مسار مناسب، فلو حطّيناها
// بعده كان `/categories` هيتقرا كمعرّف منتج اسمه "categories".

productRoutes.get(
  '/categories',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listCategories(container.products, c.get('user'));
    return c.json({ ok: true, items });
  },
);

productRoutes.post(
  '/categories',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ parentId?: string | null; name?: string }>(c);
    const container = buildContainer(c.env);
    const created = await createCategory(container.products, c.get('user'), {
      parentId: body.parentId ?? null,
      name: String(body.name ?? ''),
    });
    return c.json({ ok: true, id: created.id }, 201);
  },
);

productRoutes.patch(
  '/categories/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ name?: string }>(c);
    const container = buildContainer(c.env);
    await renameCategory(container.products, c.get('user'), c.req.param('id'), body.name);
    return c.json({ ok: true });
  },
);

productRoutes.delete(
  '/categories/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const container = buildContainer(c.env);
    await deleteCategory(container.products, c.get('user'), c.req.param('id'));
    return c.json({ ok: true });
  },
);

// ═══════════════════ موديلات الموبايل ═══════════════════
//
// ⚠ قبل `/:id` زي الأدراج بالظبط — هونو بيطابق أول مسار مناسب.

productRoutes.get(
  '/models',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listModels(container.products, c.get('user'));
    return c.json({ ok: true, items });
  },
);

productRoutes.post(
  '/models',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ name?: string; brand?: string | null; family?: unknown }>(c);
    const container = buildContainer(c.env);
    const created = await createModel(container.products, c.get('user'), {
      name: String(body.name ?? ''),
      brand: body.brand ?? null,
      // ⚠ بتتمرّر خام. الفحص في حالة الاستخدام مش هنا — عشان
      // أي مسار تاني يوصل لنفس الدالة يعدّي من نفس الحارس.
      family: body.family,
    });
    return c.json({ ok: true, id: created.id }, 201);
  },
);

productRoutes.patch(
  '/models/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ name?: string; brand?: string | null; family?: unknown }>(c);
    const container = buildContainer(c.env);
    await updateModel(container.products, c.get('user'), c.req.param('id'), body);
    return c.json({ ok: true });
  },
);

productRoutes.delete(
  '/models/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const container = buildContainer(c.env);
    await deleteModel(container.products, c.get('user'), c.req.param('id'));
    return c.json({ ok: true });
  },
);

// ═══════════════════ ألوان البضاعة ═══════════════════
//
// ⚠ قبل `/:id` زي الأدراج والموديلات.

productRoutes.get(
  '/colors',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const items = await listColors(container.products, c.get('user'));
    return c.json({ ok: true, items });
  },
);

productRoutes.post(
  '/colors',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ name?: string; hex?: string | null }>(c);
    const container = buildContainer(c.env);
    const created = await createColor(container.products, c.get('user'), {
      name: String(body.name ?? ''),
      hex: body.hex ?? null,
    });
    return c.json({ ok: true, id: created.id }, 201);
  },
);

productRoutes.patch(
  '/colors/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const body = await readJson<{ name?: string; hex?: string | null }>(c);
    const container = buildContainer(c.env);
    await updateColor(container.products, c.get('user'), c.req.param('id'), body);
    return c.json({ ok: true });
  },
);

productRoutes.delete(
  '/colors/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const container = buildContainer(c.env);
    await deleteColor(container.products, c.get('user'), c.req.param('id'));
    return c.json({ ok: true });
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
  serialUnavailable?: boolean;
  supplierId?: string | null;
  settle?: 'NONE' | 'PAID' | 'CREDIT';
  treasuryId?: string | null;
  source?: string | null;
  entryDate?: string | null;
  price?: string;
  cost?: string;
  quantity?: string;
  branchId?: string | null;
  isActive?: boolean;
  /**
   * ⚠ الأربعة دول كانت **ناقصة من النوع ده**، والواجهة بتبعتهم
   * من زمان. يعني الخادم كان بيرميهم في صمت ويرد "تم الحفظ" —
   * والصفحة بتتحدّث وتوري القيمة القديمة.
   *
   * أوحش نوع عطل: بيشتغل صح، وبيبان صح، وما بيحفظش.
   */
  reorderPoint?: number;
  customsCleared?: boolean;
  batteryHealth?: number | null;
  storageCapacity?: string | null;
  categoryId?: string | null;
  modelId?: string | null;
  colorId?: string | null;
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
    serialUnavailable: body.serialUnavailable === true,
    source: body.source ?? null,
    supplierId: body.supplierId ?? null,
    // ⚠ خام. الفحص في حالة الاستخدام مش هنا.
    settle: body.settle,
    treasuryId: body.treasuryId ?? null,
    entryDate: body.entryDate ?? null,
    pricePiastres,
    costPiastres,
    quantityOnHand: quantity,
    branchId: body.branchId ?? null,
    // ⚠ مواصفات الجهاز مع الإنشاء. حالة الاستخدام بتصفّرهم
    // للإكسسوار، فمفيش داعي نفحص النوع هنا كمان.
    customsCleared: body.customsCleared ?? false,
    batteryHealth: body.batteryHealth ?? null,
    storageCapacity: body.storageCapacity ?? null,
    categoryId: body.categoryId ?? null,
    modelId: body.modelId ?? null,
    colorId: body.colorId ?? null,
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
      serialUnavailable?: boolean;
      entryDate?: string | null;
      reorderPoint?: number | null;
      customsCleared?: boolean;
      batteryHealth?: number | null;
      storageCapacity?: string | null;
      categoryId?: string | null;
      modelId?: string | null;
      colorId?: string | null;
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
      if (body.serialUnavailable !== undefined) {
        patch.serialUnavailable = body.serialUnavailable === true;
      }
      if (body.entryDate !== undefined) patch.entryDate = body.entryDate;

      // ── مواصفات الجهاز والحد الأدنى ──
      //
      // ⚠ الأربعة دول كانوا **بيتقروش خالص**. الواجهة بتبعتهم،
      // والنوع مكانش فيه مكان ليهم، فكانوا بيتبخّروا هنا.
      //
      // ⚠ ونفس قاعدة السعر شغّالة عليهم: `undefined` معناها
      // "ما تلمسش"، والقيمة الفاضية معناها "امسح". من غير
      // التفريق ده مستحيل ترجّع صحة البطارية فاضية بعد ما
      // اتكتبت — وفاضي هنا معناه "ما اتقاسش" مش صفر.
      //
      // ⚠ والصلاحية على `reorderPoint` بتتفحص في حالة الاستخدام
      // مش هنا. المسار بيقرا، والحراسة جنب البيانات.
      if (body.reorderPoint !== undefined) patch.reorderPoint = body.reorderPoint;
      if (body.customsCleared !== undefined) patch.customsCleared = body.customsCleared;
      if (body.batteryHealth !== undefined) patch.batteryHealth = body.batteryHealth;
      if (body.storageCapacity !== undefined) patch.storageCapacity = body.storageCapacity;
      if (body.categoryId !== undefined) patch.categoryId = body.categoryId;
      if (body.modelId !== undefined) patch.modelId = body.modelId;
      if (body.colorId !== undefined) patch.colorId = body.colorId;
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
  note?: string | null;
  /**
   * ⚠ `undefined` (الحقل مش مبعوت) غير `null` (اتبعت فاضي).
   *
   * الأول معناه "الشاشة قديمة أو ما سألتش" فبيتطبّق الافتراضي.
   * التاني معناه "الموظّف فضّى الخانة" = بلا ضمان.
   *
   * عشان كده بنمرّر القيمة **زي ما هي** من غير `?? null` —
   * الـ`??` كانت هتلغي الفرق ده تمامًا.
   */
  warrantyDays?: number | string | null;
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
    warrantyDays: readWarrantyInput(body.warrantyDays),
    note: body.note ?? null,
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
 * الضمان الافتراضي — الشاشة بتبدأ بيه.
 *
 * ⚠ الرقم بيتقرا من حالة الاستخدام مش مكتوب في الواجهة.
 * لو اتكتب في المكانين، هييجي يوم يتغيّر في واحد ويفضل القديم
 * في التاني — والفاتورة تقول حاجة والشاشة تقول حاجة.
 */
saleRoutes.get(
  '/warranty/default',
  requireAuth({ requireAll: [PERMISSIONS.SALES_CREATE], touchActivity: false }),
  (c) => c.json({ ok: true, days: DEFAULT_WARRANTY_DAYS }),
);

/** حالة ضمان فاتورة */
saleRoutes.get(
  '/:id/warranty',
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
    const warranty = await getSaleWarranty(container.sales, c.get('user'), id);

    return c.json({ ok: true, warranty });
  },
);

/**
 * تعديل الضمان بعد البيع — صاحب المحل وحده.
 *
 * ⚠ مفيش صلاحية مخصّصة في الحارس عن قصد: الفحص على الدور جوّه
 * حالة الاستخدام وجوّه دالة القاعدة. الحارس هنا بيتأكد إنك
 * بتشوف الفواتير أصلاً، والباقي جوّه.
 */
saleRoutes.patch(
  '/:id/warranty',
  requireAuth({ requireAll: [PERMISSIONS.SALES_CREATE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const body = await readJson<{ warrantyDays?: number | string | null }>(c);

    const container = buildContainer(c.env);
    const change = await setSaleWarranty(
      container.sales,
      c.get('user'),
      id,
      readWarrantyInput(body.warrantyDays),
    );

    return c.json({ ok: true, ...change, message: 'تم تعديل الضمان.' });
  },
);

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


// ═══════════════════ 7.5) المرتجعات ورفّ المراجعة ═══════════════════

export const returnRoutes = new Hono<AppBindings>();

/**
 * البنود القابلة للاسترجاع في فاتورة.
 *
 * `touchActivity: false` — الشاشة بتنادي ده وهي بتفتح، ومش
 * المفروض يعتبر نشاط بشري.
 */
returnRoutes.get(
  '/sale/:id',
  requireAuth({ requireAll: [PERMISSIONS.SALES_REFUND], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const container = buildContainer(c.env);
    const lines = await getReturnableLines(container.returns, c.get('user'), id);

    return c.json({ ok: true, lines });
  },
);

/**
 * سياق شاشة الاسترجاع — البنود وحالة الضمان في رحلة واحدة.
 *
 * ⚠ ليه مسار جديد بدل ما نوسّع اللي فوق؟
 * عشان القديم لسه مستخدم في أماكن تانية، وتغيير شكل رده كان
 * هيكسرها بصمت. الجديد بيزيد ما بيستبدلش.
 *
 * والشاشة بتنادي ده عشان تعرف تعرض إيه **قبل** الضغط: زرار
 * استرجاع عادي، ولا تحذير ضمان منتهي وزرار تأكيد لصاحب المحل،
 * ولا رسالة رفض للمندوب.
 */
returnRoutes.get(
  '/context/:id',
  requireAuth({ requireAll: [PERMISSIONS.SALES_REFUND], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const container = buildContainer(c.env);
    const context = await getReturnContext(container.returns, c.get('user'), id);

    return c.json({ ok: true, ...context });
  },
);

/**
 * تنفيذ الاسترجاع.
 *
 * ⚠ صلاحية `sales.refund` مش عند المندوب. اللي بيبيع مش هو اللي
 * بيرجّع الفلوس — ودي فصل مهام مش تعقيد.
 */
returnRoutes.post(
  '/sale/:id',
  requireAuth({ requireAll: [PERMISSIONS.SALES_REFUND] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الفاتورة مفقود.');

    const body = await readJson<{
      treasuryId?: string;
      items?: Array<{ saleItemId?: string; quantity?: number; unitRefundPiastres?: number }>;
      reason?: string | null;
      returnDate?: string | null;
      overrideWarranty?: boolean;
    }>(c);

    const container = buildContainer(c.env);
    const result = await createReturn(container.returns, c.get('user'), id, {
      overrideWarranty: body.overrideWarranty === true,
      treasuryId: String(body.treasuryId ?? ''),
      items: (body.items ?? []).map((line) => ({
        saleItemId: String(line?.saleItemId ?? ''),
        quantity: Number(line?.quantity),
        unitRefundPiastres: Number(line?.unitRefundPiastres),
      })),
      reason: body.reason ?? null,
      returnDate: body.returnDate ?? null,
    });

    return c.json({ ok: true, ...result });
  },
);

/** رفّ المراجعة — المرتجعات المستنية قرار */
returnRoutes.get(
  '/quarantine',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const rows = await listQuarantine(container.returns, c.get('user'));

    return c.json({ ok: true, rows });
  },
);

/**
 * القرار: سليم (يرجع للبيع) أو تالف (يتشطب).
 *
 * ⚠ الصلاحية هنا `inventory.adjust` مش `sales.refund`.
 * دول فعلين مختلفين: الاسترجاع قرار مالي، والمراجعة قرار مخزني.
 */
returnRoutes.post(
  '/quarantine/:productId',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const productId = c.req.param('productId');
    if (!productId) throw Errors.validation('معرّف المنتج مفقود.');

    const body = await readJson<{ quantity?: number; decision?: string }>(c);
    const decision = String(body.decision ?? '');

    if (decision !== 'RELEASE' && decision !== 'SCRAP') {
      throw Errors.validation('القرار غير صحيح.');
    }

    const container = buildContainer(c.env);
    const result = await reviewQuarantine(
      container.returns,
      c.get('user'),
      productId,
      Number(body.quantity),
      decision,
    );

    return c.json({ ok: true, ...result });
  },
);


// ═══════════════════ 7.6) التقارير ═══════════════════

export const reportRoutes = new Hono<AppBindings>();

/**
 * قائمة الدخل.
 *
 * ⚠ `touchActivity: false` — التقرير بيتحدّث لما تغيّر الفترة،
 * ومش المفروض يعتبر نشاط بشري كل مرة.
 *
 * والصلاحية `report.view_branch`: صاحب المحل ومدير الفرع بس.
 * المندوب ما عندوش، فالمسار ده مقفول في وشه من الحارس.
 */
reportRoutes.get(
  '/income',
  requireAuth({ requireAll: [PERMISSIONS.REPORT_VIEW_BRANCH], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const report = await getIncomeReport(
      container.reports,
      c.get('user'),
      c.req.query('from') ?? null,
      c.req.query('to') ?? null,
    );

    return c.json({ ok: true, ...report });
  },
);


/**
 * التنبيهات الحالية.
 *
 * ⚠ `touchActivity: false` — الشاشة بتنادي ده وهي بتفتح، ومش
 * المفروض يعتبر نشاط بشري.
 */
reportRoutes.get(
  '/alerts',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const summary = await listAlerts(container.alerts, c.get('user'));
    return c.json({ ok: true, ...summary });
  },
);


// ═══════════════════ 7.7) التحويل بين الفروع ═══════════════════

export const transferRoutes = new Hono<AppBindings>();

/** التحويلات المعلّقة — الجاي والرايح */
transferRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const transfers = await listPendingTransfers(container.transfers, c.get('user'));
    return c.json({ ok: true, transfers });
  },
);

/** إنشاء تحويل — بيخصم الكمية من فرع المصدر فورًا */
transferRoutes.post(
  '/product/:id',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المنتج مفقود.');

    const body = await readJson<{ toBranchId?: string; quantity?: number; note?: string }>(c);

    const container = buildContainer(c.env);
    const result = await createTransfer(container.transfers, c.get('user'), id, {
      toBranchId: String(body.toBranchId ?? ''),
      quantity: Number(body.quantity),
      note: body.note ?? null,
    });

    return c.json({ ok: true, ...result });
  },
);

/**
 * استلام أو إلغاء.
 *
 * ⚠ الاستلام من الفرع المستقبِل والإلغاء من المُرسِل — الفحص
 * جوّه دالة القاعدة عشان يفضل شغّال من أي نداء.
 */
transferRoutes.post(
  '/:id/resolve',
  requireAuth({ requireAll: [PERMISSIONS.INVENTORY_ADJUST] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف التحويل مفقود.');

    const body = await readJson<{ decision?: string }>(c);
    const decision = String(body.decision ?? '');
    if (decision !== 'RECEIVE' && decision !== 'CANCEL') {
      throw Errors.validation('القرار غير صحيح.');
    }

    const container = buildContainer(c.env);
    const result = await resolveTransfer(container.transfers, c.get('user'), id, decision);

    return c.json({ ok: true, ...result });
  },
);


// ═══════════════════ 7.8) الموردين والديون ═══════════════════

export const supplierRoutes = new Hono<AppBindings>();

supplierRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.SUPPLIER_MANAGE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const suppliers = await listSuppliers(container.suppliers, c.get('user'));
    return c.json({ ok: true, suppliers });
  },
);

supplierRoutes.post(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.SUPPLIER_MANAGE] }),
  async (c) => {
    const body = await readJson<{ name?: string; phone?: string; notes?: string }>(c);
    const container = buildContainer(c.env);
    const created = await createSupplier(container.suppliers, c.get('user'), {
      name: String(body.name ?? ''),
      phone: body.phone ?? null,
      notes: body.notes ?? null,
    });
    return c.json({ ok: true, ...created });
  },
);

/**
 * حركة على حساب المورّد.
 *
 * ⚠ النوعين في مسار واحد عن قصد: الاتنين بيغيّروا نفس الرصيد،
 * والفرق بينهم إن السداد بيمسّ الخزنة كمان. فصلهم لمسارين كان
 * هيخلّي الواجهة تختار المسار — والاختيار ده منطق مالي مكانه
 * الخادم.
 */
supplierRoutes.post(
  '/:id/movement',
  requireAuth({ requireAll: [PERMISSIONS.SUPPLIER_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المورّد مفقود.');

    const body = await readJson<{
      kind?: string;
      amount?: string;
      note?: string;
      date?: string;
      treasuryId?: string;
    }>(c);

    const kind = String(body.kind ?? '');
    // ⚠ التلاتة في مسار واحد: كلهم بيغيّروا نفس الرصيد.
    // الفرق إن السداد بيمسّ الخزنة، والخصم لأ — والاختيار ده
    // منطق مالي مكانه الخادم مش الواجهة.
    if (kind !== 'DEBT' && kind !== 'PAYMENT' && kind !== 'DISCOUNT') {
      throw Errors.validation('نوع الحركة غير صحيح.');
    }

    const container = buildContainer(c.env);
    const input = {
      amount: String(body.amount ?? ''),
      note: body.note ?? null,
      date: body.date ?? null,
      treasuryId: body.treasuryId,
    };

    const result =
      kind === 'DEBT'
        ? await recordSupplierDebt(container.suppliers, c.get('user'), id, input)
        : kind === 'DISCOUNT'
          ? await recordSupplierDiscount(container.suppliers, c.get('user'), id, input)
          : await recordSupplierPayment(container.suppliers, c.get('user'), id, input);

    return c.json({ ok: true, ...result });
  },
);

/**
 * تعديل بيانات المورّد — الاسم والتليفون بس.
 *
 * ⚠ الرصيد مش هنا ولا في أي مسار. هو ناتج جمع الحركات، وأي
 * مسار يعدّله مباشرةً بيخلّي الدفتر يقول رقم والحركات تقول
 * رقم تاني. التعديل بيتم بحركة دين أو خصم بسبب مكتوب.
 */
supplierRoutes.patch(
  '/:id',
  requireAuth({ requireAll: [PERMISSIONS.SUPPLIER_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المورّد مفقود.');

    const body = await readJson<{
      name?: string;
      phone?: string | null;
      notes?: string | null;
    }>(c);

    const container = buildContainer(c.env);
    await updateSupplier(container.suppliers, c.get('user'), id, body);
    return c.json({ ok: true });
  },
);


// ═══════════════════ 7.85) حساب المحلات ═══════════════════
//
// ⚠ نفس صلاحية الموردين. ده دفتر ديون، والديون معلومة مالية
// سواء كانت عليك أو ليك.

export const shopRoutes = new Hono<AppBindings>();

const SHOP_GUARD = { requireAll: [PERMISSIONS.SUPPLIER_MANAGE] };

shopRoutes.get(
  '/',
  requireAuth({ ...SHOP_GUARD, touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const shops = await listShopAccounts(container.shops, c.get('user'));
    return c.json({ ok: true, shops });
  },
);

shopRoutes.post('/', requireAuth(SHOP_GUARD), async (c) => {
  const body = await readJson<{
    name?: string;
    contactName?: string | null;
    phone?: string | null;
    notes?: string | null;
  }>(c);

  const container = buildContainer(c.env);
  const created = await createShopAccount(container.shops, c.get('user'), {
    name: String(body.name ?? ''),
    contactName: body.contactName ?? null,
    phone: body.phone ?? null,
    notes: body.notes ?? null,
  });
  return c.json({ ok: true, ...created }, 201);
});

shopRoutes.patch('/:id', requireAuth(SHOP_GUARD), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف الحساب مفقود.');

  const body = await readJson<{
    name?: string;
    contactName?: string | null;
    phone?: string | null;
  }>(c);

  const container = buildContainer(c.env);
  await updateShopAccount(container.shops, c.get('user'), id, body);
  return c.json({ ok: true });
});

/**
 * خروج بضاعة أجل.
 *
 * ⚠ البنود بتتبعت خام. الفحص كله في حالة الاستخدام وقاعدة
 * البيانات — عشان أي مسار تاني يوصل لنفس الدالة يعدّي من نفس
 * الحارس.
 */
shopRoutes.post('/:id/consign', requireAuth(SHOP_GUARD), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف الحساب مفقود.');

  const body = await readJson<{
    items?: Array<{ productId?: string; quantity?: unknown; unitPrice?: string }>;
    note?: string | null;
    date?: string | null;
  }>(c);

  const container = buildContainer(c.env);
  const result = await consignToShop(container.shops, c.get('user'), id, {
    items: body.items ?? [],
    note: body.note ?? null,
    date: body.date ?? null,
  });
  return c.json({ ok: true, ...result });
});

shopRoutes.post('/:id/payment', requireAuth(SHOP_GUARD), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف الحساب مفقود.');

  const body = await readJson<{
    amount?: string;
    treasuryId?: string;
    note?: string | null;
    date?: string | null;
  }>(c);

  const container = buildContainer(c.env);
  const result = await recordShopPayment(container.shops, c.get('user'), id, {
    amount: String(body.amount ?? ''),
    treasuryId: body.treasuryId,
    note: body.note ?? null,
    date: body.date ?? null,
  });
  return c.json({ ok: true, ...result });
});


// ═══════════════════ 7.9) الصيانة ═══════════════════

export const maintenanceRoutes = new Hono<AppBindings>();

const VIEW = { requireAll: [PERMISSIONS.MAINTENANCE_VIEW], touchActivity: false };
const MANAGE = { requireAll: [PERMISSIONS.MAINTENANCE_MANAGE] };

/** كل بيانات الشاشة في رحلة واحدة */
maintenanceRoutes.get('/', requireAuth(VIEW), async (c) => {
  const container = buildContainer(c.env);
  const user = c.get('user');

  // ⚠ نطاق التذاكر ونطاق أجهزة المحل مختلفين في القيم المسموحة
  // (DELIVERED مقابل RETURNED)، فبنترجم مرة واحدة هنا.
  const scope = c.req.query('scope') ?? 'OPEN';
  const shared = {
    search: c.req.query('q') ?? null,
    from: c.req.query('from') ?? null,
    to: c.req.query('to') ?? null,
    shopId: c.req.query('shop') ?? null,
  };

  const [shops, records, tickets] = await Promise.all([
    listRepairShops(container.maintenance, user),
    listMaintenanceRecords(container.maintenance, user, {
      ...shared,
      scope: scope === 'DELIVERED' ? 'RETURNED' : scope,
    }),
    listTickets(container.maintenance, user, { ...shared, scope }),
  ]);

  return c.json({ ok: true, shops, records, tickets });
});

/** تاريخ صيانة منتج — بيتعرض في كارت المنتج */
maintenanceRoutes.get('/product/:id/history', requireAuth(VIEW), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف المنتج مفقود.');

  const container = buildContainer(c.env);
  const history = await getProductMaintenance(container.maintenance, c.get('user'), id);
  return c.json({ ok: true, history });
});

maintenanceRoutes.get('/shops/:id/history', requireAuth(VIEW), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف الورشة مفقود.');

  const container = buildContainer(c.env);
  const history = await getShopHistory(container.maintenance, c.get('user'), id);
  return c.json({ ok: true, history });
});

maintenanceRoutes.post('/shops', requireAuth(MANAGE), async (c) => {
  const body = await readJson<{ name?: string; phone?: string; notes?: string }>(c);
  const container = buildContainer(c.env);
  const created = await createRepairShop(container.maintenance, c.get('user'), {
    name: String(body.name ?? ''),
    phone: body.phone ?? null,
    notes: body.notes ?? null,
  });
  return c.json({ ok: true, ...created });
});

/** إرسال جهاز المحل — بيخصم من المخزون */
maintenanceRoutes.post('/product/:id', requireAuth(MANAGE), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف المنتج مفقود.');

  const body = await readJson<{ shopId?: string; fault?: string; cost?: string }>(c);
  const container = buildContainer(c.env);
  const result = await sendToMaintenance(container.maintenance, c.get('user'), id, {
    shopId: body.shopId ?? null,
    fault: String(body.fault ?? ''),
    cost: body.cost ?? null,
  });
  return c.json({ ok: true, ...result });
});

maintenanceRoutes.post('/record/:id/return', requireAuth(MANAGE), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف السجل مفقود.');

  const body = await readJson<{ status?: string; cost?: string; note?: string }>(c);
  const container = buildContainer(c.env);
  const result = await returnFromMaintenance(container.maintenance, c.get('user'), id, {
    status: String(body.status ?? ''),
    cost: body.cost ?? null,
    note: body.note ?? null,
  });
  return c.json({ ok: true, ...result });
});

/**
 * استلام جهاز عميل.
 *
 * ⚠ صلاحية العرض كافية — المندوب هو اللي بيستلم على الكاونتر.
 * الإدارة (الحالة والتكلفة) هي المحصورة.
 */
maintenanceRoutes.post('/tickets', requireAuth({ requireAll: [PERMISSIONS.MAINTENANCE_VIEW] }),
  async (c) => {
    const body = await readJson<Record<string, string | null>>(c);
    const container = buildContainer(c.env);
    const created = await createTicket(container.maintenance, c.get('user'), {
      customerName: String(body.customerName ?? ''),
      customerPhone: body.customerPhone ?? null,
      deviceName: String(body.deviceName ?? ''),
      serialNumber: body.serialNumber ?? null,
      deviceColor: body.deviceColor ?? null,
      conditionNote: body.conditionNote ?? null,
      complaint: String(body.complaint ?? ''),
      unlockKind: String(body.unlockKind ?? 'NONE'),
      unlockValue: body.unlockValue ?? null,
      repairShopId: body.repairShopId ?? null,
      cost: body.cost ?? null,
      promisedDate: body.promisedDate ?? null,
      parentTicketId: body.parentTicketId ?? null,
      branchId: body.branchId ?? null,
    });
    return c.json({ ok: true, ...created });
  },
);

maintenanceRoutes.post('/tickets/:id', requireAuth(MANAGE), async (c) => {
  const id = c.req.param('id');
  if (!id) throw Errors.validation('معرّف التذكرة مفقود.');

  const body = await readJson<Record<string, string | null>>(c);
  const container = buildContainer(c.env);
  await updateTicket(container.maintenance, c.get('user'), id, {
    status: body.status ?? undefined,
    cost: body.cost ?? undefined,
    workNote: body.workNote ?? undefined,
    repairShopId: body.repairShopId ?? undefined,
  });
  return c.json({ ok: true });
});

/**
 * تعديل بيانات فتح الجهاز.
 *
 * ⚠ صلاحية **العرض** كافية، مش الإدارة.
 *
 * الموظّف اللي كتب الرقم غلط لازم يصلّح غلطته فورًا. لو خلّيناها
 * للمدير، الرقم الغلط هيفضل مكتوب لحد ما المدير يفضى — والجهاز
 * مقفول طول الوقت ده.
 */
maintenanceRoutes.post('/tickets/:id/unlock',
  requireAuth({ requireAll: [PERMISSIONS.MAINTENANCE_VIEW] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف التذكرة مفقود.');

    const body = await readJson<{ unlockKind?: string; unlockValue?: string }>(c);
    const container = buildContainer(c.env);
    await updateTicketUnlock(container.maintenance, c.get('user'), id, {
      unlockKind: String(body.unlockKind ?? 'NONE'),
      unlockValue: body.unlockValue ?? null,
    });
    return c.json({ ok: true });
  },
);

/**
 * بيانات فتح الجهاز.
 *
 * ⚠ نداء منفصل عن القائمة عن قصد — عشان القراءة تبقى فعل ليه
 * صاحب ووقت، مش حاجة بتيجي مع كل تحميل شاشة. وكل نداء بيتسجّل.
 */
maintenanceRoutes.get('/tickets/:id/unlock',
  requireAuth({ requireAll: [PERMISSIONS.MAINTENANCE_VIEW] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف التذكرة مفقود.');

    const container = buildContainer(c.env);
    const unlock = await getTicketUnlock(container.maintenance, c.get('user'), id);
    return c.json({ ok: true, ...unlock });
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
  branches?: Array<{ code?: string; name?: string }>;
  users?: Array<{
    username?: string;
    fullName?: string;
    password?: string;
    role?: string;
    branchCode?: string;
  }>;
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
    branches: (body.branches ?? []).map((b) => ({
      code: String(b?.code ?? ''),
      name: String(b?.name ?? ''),
    })),
    users: (body.users ?? []).map((u) => ({
      username: String(u?.username ?? ''),
      fullName: String(u?.fullName ?? ''),
      password: String(u?.password ?? ''),
      role: (u?.role === 'BRANCH_MANAGER' ? 'BRANCH_MANAGER' : 'STAFF') as
        | 'BRANCH_MANAGER'
        | 'STAFF',
      branchCode: String(u?.branchCode ?? ''),
    })),
  });

  // ⚠ كلمات المرور بترجع في الرد **مرة واحدة** عشان الملخّص.
  // مفيش مكان تاني في النظام بيرجّع كلمة مرور نصّ صريح.
  return c.json(
    {
      ok: true,
      tenantId: created.tenantId,
      code: created.code,
      branchCount: created.branchCount,
      accounts: created.accounts,
    },
    201,
  );
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
 * جرد المحل — بيتنادى قبل ما شاشة التأكيد تظهر.
 *
 * `touchActivity: false` عشان الفحص ده ما يحسبش نشاط.
 */
platformRoutes.get(
  '/:id/census',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المحل مفقود.');

    const container = buildContainer(c.env);
    const census = await getTenantCensus(container.platform, c.get('user'), id);

    return c.json({ ok: true, census });
  },
);

/**
 * المحو النهائي.
 *
 * ⚠ فعل بلا رجعة. الأقفال الأربعة متوزّعة عن قصد:
 *   • الصلاحية والكود المكتوب  ← في حالة الاستخدام
 *   • الإيقاف ومشغّل المنصّة   ← جوّه دالة قاعدة البيانات
 *
 * التوزيع ده مش تكرار عبثي: نداء جاي من أي مكان تاني في المستقبل
 * (سكربت، أداة إدارية) هيفضل محروس بقفلين على الأقل.
 */
platformRoutes.post(
  '/:id/purge',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المحل مفقود.');

    const body = await readJson<{ confirmCode?: string }>(c);

    const container = buildContainer(c.env);
    const result = await purgeTenant(container.platform, c.get('user'), id, {
      confirmCode: String(body.confirmCode ?? ''),
    });

    return c.json({ ok: true, purged: result });
  },
);

/**
 * فروع محل — لقائمة التوجيه.
 *
 * ⚠ الأسماء بس. الدالة في القاعدة بترفض أي حد مش مشغّل منصّة،
 * والحارس هنا بيفحص `tenant.view` كمان.
 */
platformRoutes.get(
  '/:id/branches',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_VIEW], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف المحل مفقود.');

    const container = buildContainer(c.env);
    const branches = await listTenantBranches(container.platform, c.get('user'), id);
    return c.json({ ok: true, branches });
  },
);

/** سجل ما أُرسل، مع عدّاد القراءة */
platformRoutes.get(
  '/announcements',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_VIEW], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const announcements = await listPlatformAnnouncements(container.platform, c.get('user'));
    return c.json({ ok: true, announcements });
  },
);

/**
 * بثّ إعلان.
 *
 * ⚠ `tenantId` فاضي معناه **كل المحلات المفعّلة**. والرد بيقول
 * `sentCount` — عدد المحلات اللي وصلها فعلاً.
 *
 * الرقم ده مهم في الرد مش في السجل بس: زرار واحد بيوصل لكل
 * عملائك، والمستخدم لازم يشوف حجم اللي حصل فورًا.
 */
platformRoutes.post(
  '/announcements',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }),
  async (c) => {
    const body = await readJson<{
      tenantId?: string | null;
      audience?: string;
      branchId?: string | null;
      title?: string;
      body?: string;
      severity?: string;
      isMandatory?: boolean;
      endsAt?: string | null;
    }>(c);

    const container = buildContainer(c.env);
    const result = await broadcast(container.platform, c.get('user'), {
      tenantId: body.tenantId ?? null,
      audience: body.audience,
      branchId: body.branchId ?? null,
      title: String(body.title ?? ''),
      body: String(body.body ?? ''),
      severity: body.severity,
      isMandatory: body.isMandatory,
      endsAt: body.endsAt ?? null,
    });

    return c.json(
      {
        ok: true,
        ...result,
        message:
          result.sentCount === 1
            ? 'تم البثّ لمحل واحد.'
            : `تم البثّ لـ ${result.sentCount} محل.`,
      },
      201,
    );
  },
);

/**
 * سحب إعلان.
 *
 * ⚠ بيشيل **صف واحد**. لو البثّ راح لأربعين محل، دول أربعين
 * صف وكل واحد بيتسحب لوحده — عشان تقدر تسحب من محل وتسيبه
 * عند الباقيين.
 */
platformRoutes.delete(
  '/announcements/:id',
  requireAuth({ requireAll: [PERMISSIONS.TENANT_MANAGE] }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف الإعلان مفقود.');

    const container = buildContainer(c.env);
    await withdrawAnnouncement(container.platform, c.get('user'), id);

    return c.json({ ok: true, message: 'تم سحب الإعلان.' });
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


// ═══════════════════════════════════════════════════════════
//  شراء البضاعة
//
//  ⚠ مسار منفصل عن الخزنة رغم إن النتيجة حركة خزنة.
//
//  السبب: العملية دي بتكتب **صفّين** في معاملة واحدة (الحركة
//  والبيان). لو حطّيناها في `treasuryRoutes` كنوع مصروف، كان
//  لازم شاشة الخزنة تعرف تفرّق بين مصروف عادي ومصروف بيان —
//  ومن غير ما تفرّق، مصروف "شراء بضاعة" يتسجّل بلا بيان وترجع
//  المشكلة الأصلية.
//
//  ⚠ ولاحظ إن ده ما بيزوّدش المخزون. التوريد لسه من شاشة
//  البضاعة بإيدك.
// ═══════════════════════════════════════════════════════════

export const purchaseRoutes = new Hono<AppBindings>();

/** أسماء الموردين — بلا أي رقم مالي، لملء القائمة المنسدلة */
purchaseRoutes.get(
  '/suppliers',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const suppliers = await listSupplierNames(container.purchases, c.get('user'));
    return c.json({ ok: true, suppliers });
  },
);

purchaseRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const purchases = await listPurchases(
      container.purchases,
      c.get('user'),
      c.req.query('from') ?? null,
      c.req.query('to') ?? null,
    );
    return c.json({ ok: true, purchases });
  },
);

/**
 * تسجيل شراء.
 *
 * ⚠ حالة الاعتماد بترجع من القاعدة مش من الحارس. المندوب
 * حركته بتتسجّل **معلّقة** والدرج ما بيتغيّرش لحد ما مدير
 * يعتمدها — والرسالة لازم تقول كده صراحةً، وإلا هيفتكر إن
 * الفلوس خرجت.
 */
purchaseRoutes.post(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.EXPENSE_CREATE] }),
  async (c) => {
    const body = await readJson<{
      treasuryId?: string;
      amount?: string;
      itemName?: string;
      quantity?: string | number;
      supplierId?: string | null;
      note?: string | null;
    }>(c);

    const container = buildContainer(c.env);
    const result = await recordPurchase(container.purchases, c.get('user'), {
      treasuryId: String(body.treasuryId ?? ''),
      amount: String(body.amount ?? ''),
      itemName: String(body.itemName ?? ''),
      quantity: String(body.quantity ?? ''),
      supplierId: body.supplierId ?? null,
      note: body.note ?? null,
    });

    return c.json(
      {
        ok: true,
        ...result,
        message:
          result.status === 'APPROVED'
            ? 'تم تسجيل الشراء وخصمه من الخزنة.'
            : 'تم تسجيل الشراء. مستنّي اعتماد المدير ولسه ما اتخصمش.',
      },
      201,
    );
  },
);


// ═══════════════════════════════════════════════════════════
//  تقفيل اليومية
//
//  ══ الفرق بين "تشوف" و"تقفل" ══
//  ⚠ الحارس هنا بيفحص **صلاحية** (`sales.view_branch`) بس.
//
//  مين يقدر يقفل فعلاً محكوم بـ`closing_roles` على الفرع،
//  وده إعداد مش صلاحية — فبيتفحص جوّه دالة القاعدة اللي
//  بتكتب الصف، مش في الحارس.
//
//  لو حطّيناه في الحارس، كان لازم نقرا إعداد الفرع في كل
//  طلب قبل ما نعرف نسمح ولا لأ — ودي رحلة زيادة على كل
//  ضغطة، والنتيجة نفسها.
// ═══════════════════════════════════════════════════════════

export const closingRoutes = new Hono<AppBindings>();

/** سجل اليوميات — بلا لقطات، عشان الرد يفضل خفيف */
closingRoutes.get(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.SALES_VIEW_BRANCH], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const closings = await listClosings(container.closings, c.get('user'));
    return c.json({ ok: true, closings });
  },
);

/**
 * معاينة — إيه اللي هيتقفل لو ضغطت دلوقتي.
 *
 * ⚠ بترجّع `canClose` و`reason` عشان الشاشة تعرض السبب **قبل**
 * الضغط. زرار بيرفض بعد الضغط أسوأ من زرار بيقول ليه قبلها.
 */
closingRoutes.get(
  '/preview',
  requireAuth({ requireAll: [PERMISSIONS.SALES_VIEW_BRANCH], touchActivity: false }),
  async (c) => {
    const container = buildContainer(c.env);
    const preview = await previewClosing(
      container.closings,
      c.get('user'),
      c.req.query('branchId') ?? null,
    );
    return c.json({ ok: true, ...preview });
  },
);

/**
 * تفاصيل يومية.
 *
 * ⚠ المعرّف بيتجاب مع المحل من الجلسة — مش بفلترة بعد القراءة.
 * والتكلفة بتترجع بس لصاحب `profit.view_real`، والحجب في
 * القاعدة مش هنا.
 */
closingRoutes.get(
  '/:id',
  requireAuth({ requireAll: [PERMISSIONS.SALES_VIEW_BRANCH], touchActivity: false }),
  async (c) => {
    const id = c.req.param('id');
    if (!id) throw Errors.validation('معرّف اليومية مفقود.');

    const container = buildContainer(c.env);
    const closing = await getClosing(container.closings, c.get('user'), id);
    return c.json({ ok: true, closing });
  },
);

/**
 * تقفيل.
 *
 * ⚠ ما بيمنعش أي عملية جديدة. الفترة الجديدة بتبدأ من نفس
 * اللحظة، والبيع اللي بعدها بثانية بيتسجّل عادي.
 */
closingRoutes.post(
  '/',
  requireAuth({ requireAll: [PERMISSIONS.SALES_VIEW_BRANCH] }),
  async (c) => {
    const body = await readJson<{ branchId?: string | null; note?: string | null }>(c);

    const container = buildContainer(c.env);
    const result = await closeDay(
      container.closings,
      c.get('user'),
      body.branchId ?? null,
      body.note ?? null,
    );

    return c.json({ ok: true, ...result, message: 'تم تقفيل اليومية.' }, 201);
  },
);

/**
 * ضبط مين يقفل — صاحب المحل وحده.
 *
 * ⚠ الفحص على الدور جوّه حالة الاستخدام وجوّه القاعدة، مش في
 * الحارس. مفيش صلاحية مخصّصة للفعل ده، وعمل واحدة عشان إعداد
 * بيتغيّر مرة كل شهور كان هيزوّد الكتالوج بلا فايدة.
 */
closingRoutes.patch(
  '/roles',
  requireAuth({ requireAll: [PERMISSIONS.BRANCH_VIEW] }),
  async (c) => {
    const body = await readJson<{ branchId?: string; roles?: unknown }>(c);

    const container = buildContainer(c.env);
    const change = await setClosingRoles(
      container.closings,
      c.get('user'),
      String(body.branchId ?? ''),
      body.roles,
    );

    return c.json({ ok: true, ...change, message: 'تم حفظ الإعداد.' });
  },
);


/**
 * قراءة مدة الضمان من جسم الطلب.
 *
 * ⚠ التلات حالات لازم تفضل مفصولة لحد حالة الاستخدام:
 *   الحقل مش موجود → undefined → الافتراضي
 *   جه فاضي/null    → null      → بلا ضمان
 *   رقم             → رقم
 *
 * `Number('')` بيساوي **صفر** في جافاسكربت — فلو حوّلنا على
 * طول، الخانة الفاضية كانت هتبقى "ضمان صفر يوم" بدل "بلا ضمان".
 */
function readWarrantyInput(raw: number | string | null | undefined): number | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null || String(raw).trim() === '') return null;

  const days = Number(normalizeDigits(String(raw).trim()));
  if (!Number.isInteger(days)) throw Errors.validation('مدة الضمان لازم تكون رقم صحيح.');
  return days;
}
