/**
 * المستودعات — عبر Supabase
 *
 * ══ ليه اتغيّر عن Prisma؟ ══
 * Prisma بتحتاج خطوة توليد كود + اتصال TCP بقاعدة البيانات.
 * الاتنين صعبين على كلاودفلير، والأصعب إنهم محتاجين terminal
 * وإنت شغّال من الموبايل.
 *
 * البديل: مكتبة supabase-js بتكلّم قاعدة البيانات بـ HTTP عادي —
 * نفس اللي بيعمله المتصفح. صفر خطوات بناء، وبتشتغل على كلاودفلير
 * من غير أي إعداد.
 *
 * تشبيه: بدل ما تمدّ سلك من مكتبك للأرشيف، بتبعت ورقة طلب بالفاكس.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type {
  AnnouncementRecord,
  AnnouncementRepository,
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  BranchSummary,
  ExpenseReason,
  ExpenseReasonRepository,
  MovementDirection,
  MovementRecord,
  MovementRepository,
  MovementStatus,
  MovementType,
  ProductListOptions,
  ProductRecord,
  ProductRepository,
  RateLimiter,
  RoleKey,
  SaleDetail,
  SaleItemLine,
  SaleRepository,
  SaleSummary,
  SessionRecord,
  SessionRepository,
  TeamMember,
  TreasuryRepository,
  UserRecord,
  UserRepository,
} from '../application/ports';
import type { PermissionKey } from '../domain/permissions';
import type { Env } from '../domain/config';
import { Errors } from '../domain/errors';

/**
 * تطبيع الرابط.
 *
 * صفحة سوبابيز بتعرض الرابط أحياناً بالشكل ده:
 *   https://xxxx.supabase.co/rest/v1/
 * لكن المكتبة عايزة الأساس بس:
 *   https://xxxx.supabase.co
 * وهي اللي بتضيف /rest/v1 لوحدها. لو سبناه هيبقى /rest/v1/rest/v1
 * وكل الطلبات هترجع 404 من غير رسالة مفهومة.
 *
 * تشبيه: بتديله عنوان المبنى، مش عنوان المبنى + رقم الشقة اللي هو
 * عارفها أصلاً.
 */
export function normalizeSupabaseUrl(raw: string): string {
  return raw
    .trim()
    .replace(/\/+$/, '')       // شيل السلاش من الآخر
    .replace(/\/rest\/v1$/, '') // شيل مسار الـ API لو ملزوق
    .replace(/\/+$/, '');
}

export function createDb(env: Env): SupabaseClient {
  return createClient(normalizeSupabaseUrl(env.SUPABASE_URL), env.SUPABASE_SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { 'X-Client-Info': 'pos-worker' } },
  });
}

/** تحويل نص التاريخ القادم من قاعدة البيانات إلى كائن Date */
function toDate(value: string | null | undefined): Date | null {
  return value ? new Date(value) : null;
}

interface RawUser {
  id: string;
  username: string;
  full_name: string;
  password_hash: string;
  admin_passkey_hash: string | null;
  is_active: boolean;
  must_change_password: boolean;
  failed_login_count: number;
  locked_until: string | null;
  deleted_at: string | null;
  branch_id: string | null;
  role_key: string;
  permissions: string[] | null;
}

function toUserRecord(raw: RawUser): UserRecord {
  return {
    id: raw.id,
    username: raw.username,
    fullName: raw.full_name,
    passwordHash: raw.password_hash,
    adminPasskeyHash: raw.admin_passkey_hash,
    isActive: raw.is_active,
    mustChangePassword: raw.must_change_password,
    failedLoginCount: raw.failed_login_count,
    lockedUntil: toDate(raw.locked_until),
    deletedAt: toDate(raw.deleted_at),
    branchId: raw.branch_id,
    roleKey: raw.role_key as RoleKey,
    permissions: (raw.permissions ?? []) as PermissionKey[],
  };
}

// ─────────── المستخدمون ───────────

export function createUserRepository(db: SupabaseClient): UserRepository {
  return {
    async findByUsername(username) {
      // رحلة واحدة بتجيب المستخدم + دوره + صلاحياته المدمجة
      const { data, error } = await db.rpc('fn_login_lookup', { p_username: username });
      if (error) throw Errors.internal(`fn_login_lookup: ${error.message}`);

      const rows = data as RawUser[] | null;
      return rows?.[0] ? toUserRecord(rows[0]) : null;
    },

    async findById(id) {
      const { data, error } = await db.rpc('fn_user_by_id', { p_user_id: id });
      if (error) throw Errors.internal(`fn_user_by_id: ${error.message}`);

      const rows = data as RawUser[] | null;
      return rows?.[0] ? toUserRecord(rows[0]) : null;
    },

    async registerFailedLogin(userId, lockUntil) {
      // مفيش increment في PostgREST، فبنقرأ ونكتب.
      // مقبول هنا لأن ده مسار فشل نادر ومش حرج للأداء.
      const { data } = await db
        .from('users')
        .select('failed_login_count')
        .eq('id', userId)
        .single();

      await db
        .from('users')
        .update({
          failed_login_count: ((data?.failed_login_count as number) ?? 0) + 1,
          ...(lockUntil ? { locked_until: lockUntil.toISOString() } : {}),
        })
        .eq('id', userId);
    },

    async clearLoginFailures(userId, loginAt) {
      await db
        .from('users')
        .update({
          failed_login_count: 0,
          locked_until: null,
          last_login_at: loginAt.toISOString(),
        })
        .eq('id', userId);
    },

    async updatePasswordHash(userId, hash) {
      await db.from('users').update({ password_hash: hash }).eq('id', userId);
    },

    async create(data) {
      // نحتاج معرّف الدور الداخلي — الجدول يربط بـ role_id لا role_key مباشرة
      const { data: role, error: roleError } = await db
        .from('roles')
        .select('id')
        .eq('key', data.roleKey)
        .single();

      if (roleError || !role) throw Errors.internal(`role lookup: ${roleError?.message}`);

      const { data: row, error } = await db
        .from('users')
        .insert({
          username: data.username,
          full_name: data.fullName,
          password_hash: data.passwordHash,
          role_id: role.id,
          branch_id: data.branchId,
          is_active: true,
          // لسه مفيش شاشة "غيّر كلمة المرور" مبنية في هذه الوحدة،
          // فتفعيل الإجبار هنا كان سيحبس المستخدم من غير مخرج
          must_change_password: false,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = unique violation في بوستجرس — اسم المستخدم مكرّر
        if (error?.code === '23505') throw Errors.validation('اسم المستخدم ده مُستخدَم بالفعل.');
        throw Errors.internal(`user insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },

    async listInScope(scope) {
      let query = db
        .from('users')
        .select('id, username, full_name, branch_id, is_active, created_at, role:roles(key)')
        .is('deleted_at', null)
        .order('created_at', { ascending: false })
        .limit(200); // سقف احترازي لشاشة موبايل

      // النوع بيجبرنا نتعامل مع الحالتين صراحةً — مفيش "لو نسيت الفلتر
      // هيعرض الكل". لازم تكتب allBranches بإيدك عشان تشوف كل الفروع.
      if (!('allBranches' in scope)) {
        query = query.eq('branch_id', scope.branchId);
      }

      const { data, error } = await query;
      if (error) throw Errors.internal(`users list: ${error.message}`);

      return ((data ?? []) as RawTeamMember[]).map(toTeamMember);
    },

    async setActive(userId, isActive) {
      const { error } = await db.from('users').update({ is_active: isActive }).eq('id', userId);
      if (error) throw Errors.internal(`user setActive: ${error.message}`);
    },
  };
}

// صف الفريق كما يرجعه PostgREST — العلاقة ممكن تيجي كائن أو مصفوفة
// حسب طريقة استنتاجها، فنتعامل مع الاحتمالين بأمان
interface RawTeamMember {
  id: string;
  username: string;
  full_name: string;
  branch_id: string | null;
  is_active: boolean;
  created_at: string;
  role: { key: string } | { key: string }[] | null;
}

function toTeamMember(raw: RawTeamMember): TeamMember {
  const role = Array.isArray(raw.role) ? raw.role[0] : raw.role;
  return {
    id: raw.id,
    username: raw.username,
    fullName: raw.full_name,
    roleKey: (role?.key ?? 'STAFF') as RoleKey,
    branchId: raw.branch_id,
    isActive: raw.is_active,
    createdAt: new Date(raw.created_at),
  };
}

// ─────────── الفروع ───────────

export function createBranchRepository(db: SupabaseClient): BranchRepository {
  const COLUMNS = 'id, code, name, is_active';

  const toSummary = (r: {
    id: string;
    code: string;
    name: string;
    is_active: boolean;
  }): BranchSummary => ({ id: r.id, code: r.code, name: r.name, isActive: r.is_active });

  return {
    async listActive() {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .is('deleted_at', null)
        .eq('is_active', true)
        .order('name');

      if (error) throw Errors.internal(`branches listActive: ${error.message}`);
      return (data ?? []).map(toSummary);
    },

    async listAll() {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .is('deleted_at', null)
        .order('name');

      if (error) throw Errors.internal(`branches listAll: ${error.message}`);
      return (data ?? []).map(toSummary);
    },

    async exists(branchId) {
      const { data, error } = await db
        .from('branches')
        .select('id')
        .eq('id', branchId)
        .is('deleted_at', null)
        .eq('is_active', true)
        .maybeSingle();

      if (error) throw Errors.internal(`branch exists: ${error.message}`);
      return Boolean(data);
    },

    async findByCode(code) {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .eq('code', code)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`branch findByCode: ${error.message}`);
      return data ? toSummary(data) : null;
    },

    async create(data) {
      const { data: row, error } = await db
        .from('branches')
        .insert({
          code: data.code,
          name: data.name,
          address: data.address,
          phone: data.phone,
          is_active: true,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = unique violation — الكود مكرر رغم الفحص المسبق
        // (ممكن يحصل لو اتنين بيضيفوا في نفس اللحظة)
        if (error?.code === '23505') throw Errors.validation('كود الفرع ده مستخدم بالفعل.');
        throw Errors.internal(`branch insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },
  };
}

// ─────────── الخزينة ───────────

export function createTreasuryRepository(db: SupabaseClient): TreasuryRepository {
  return {
    async listBalances(branchId) {
      // الرصيد محسوب في قاعدة البيانات مش هنا — الجمع مكانه جنب
      // الدفتر، مش في رحلة شبكة
      const { data, error } = await db.rpc('fn_treasury_balances', { p_branch_id: branchId });
      if (error) throw Errors.internal(`fn_treasury_balances: ${error.message}`);

      return ((data ?? []) as Array<{
        treasury_id: string;
        name: string;
        type: string;
        branch_id: string | null;
        is_active: boolean;
        balance_piastres: number | string;
        movement_count: number | string;
      }>).map((r) => ({
        treasuryId: r.treasury_id,
        name: r.name,
        type: r.type,
        branchId: r.branch_id,
        isActive: r.is_active,
        // bigint ممكن يرجع كنص من PostgREST — بنوحّده لرقم
        balancePiastres: Number(r.balance_piastres),
        movementCount: Number(r.movement_count),
      }));
    },

    async findScope(treasuryId) {
      const { data, error } = await db
        .from('treasuries')
        .select('branch_id')
        .eq('id', treasuryId)
        .is('deleted_at', null)
        .eq('is_active', true)
        .maybeSingle();

      if (error) throw Errors.internal(`treasury findScope: ${error.message}`);
      return data ? { branchId: data.branch_id as string | null } : null;
    },
  };
}

// ─────────── حركات الخزينة ───────────

const MOVEMENT_COLUMNS =
  'id, treasury_id, branch_id, direction, type, amount_piastres, status, ' +
  'expense_reason_id, related_user_id, note, occurred_at, created_by_id';

interface RawMovement {
  id: string;
  treasury_id: string;
  branch_id: string | null;
  direction: MovementDirection;
  type: MovementType;
  amount_piastres: number | string;
  status: MovementStatus;
  expense_reason_id: string | null;
  related_user_id: string | null;
  note: string | null;
  occurred_at: string;
  created_by_id: string;
}

function toMovement(raw: RawMovement): MovementRecord {
  return {
    id: raw.id,
    treasuryId: raw.treasury_id,
    branchId: raw.branch_id,
    direction: raw.direction,
    type: raw.type,
    amountPiastres: Number(raw.amount_piastres),
    status: raw.status,
    expenseReasonId: raw.expense_reason_id,
    relatedUserId: raw.related_user_id,
    note: raw.note,
    occurredAt: new Date(raw.occurred_at),
    createdById: raw.created_by_id,
  };
}

export function createMovementRepository(db: SupabaseClient): MovementRepository {
  return {
    async create(data) {
      const { data: row, error } = await db
        .from('treasury_movements')
        .insert({
          treasury_id: data.treasuryId,
          branch_id: data.branchId,
          direction: data.direction,
          type: data.type,
          amount_piastres: data.amountPiastres,
          status: data.status,
          expense_reason_id: data.expenseReasonId,
          related_user_id: data.relatedUserId,
          note: data.note,
          occurred_at: data.occurredAt.toISOString(),
          created_by_id: data.createdById,
          approved_by_id: data.approvedById,
          approved_at: data.approvedAt?.toISOString() ?? null,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23514 = check constraint violation — القيود المنطقية في
        // قاعدة البيانات رفضت السجل (سُلفة بلا موظّف مثلاً)
        if (error?.code === '23514') {
          throw Errors.validation('بيانات الحركة ناقصة أو غير متسقة.');
        }
        throw Errors.internal(`movement insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },

    async list(filter) {
      let query = db
        .from('treasury_movements')
        .select(MOVEMENT_COLUMNS)
        .is('deleted_at', null)
        .order('occurred_at', { ascending: false })
        .limit(filter.limit);

      if (filter.branchId !== null) query = query.eq('branch_id', filter.branchId);
      if (filter.status) query = query.eq('status', filter.status);

      const { data, error } = await query;
      if (error) throw Errors.internal(`movements list: ${error.message}`);

      return ((data ?? []) as RawMovement[]).map(toMovement);
    },

    async findById(id) {
      const { data, error } = await db
        .from('treasury_movements')
        .select(MOVEMENT_COLUMNS)
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`movement findById: ${error.message}`);
      return data ? toMovement(data as RawMovement) : null;
    },

    async review(id, status, reviewerId, at) {
      // الشرط على الحالة مهم: بيمنع اعتماد حركة اتراجعت بالفعل
      // لو ضغط اتنين على الزرار في نفس اللحظة
      const { error } = await db
        .from('treasury_movements')
        .update({
          status,
          approved_by_id: reviewerId,
          approved_at: at.toISOString(),
        })
        .eq('id', id)
        .eq('status', 'PENDING');

      if (error) throw Errors.internal(`movement review: ${error.message}`);
    },

    async salaryStatement(userId, from, to) {
      const { data, error } = await db.rpc('fn_user_salary_statement', {
        p_user_id: userId,
        p_from: from.toISOString(),
        p_to: to.toISOString(),
      });

      if (error) throw Errors.internal(`fn_user_salary_statement: ${error.message}`);

      const row = (data as Array<Record<string, number | string>> | null)?.[0];
      return {
        baseSalaryPiastres: Number(row?.base_salary_piastres ?? 0),
        totalAdvancesPiastres: Number(row?.total_advances_piastres ?? 0),
        netDuePiastres: Number(row?.net_due_piastres ?? 0),
        carriedDebtPiastres: Number(row?.carried_debt_piastres ?? 0),
        advanceCount: Number(row?.advance_count ?? 0),
      };
    },
  };
}

// ─────────── أسباب الصرف ───────────

export function createExpenseReasonRepository(db: SupabaseClient): ExpenseReasonRepository {
  const map = (r: {
    id: string;
    name: string;
    is_advance: boolean;
    branch_id: string | null;
  }): ExpenseReason => ({
    id: r.id,
    name: r.name,
    isAdvance: r.is_advance,
    branchId: r.branch_id,
  });

  return {
    async listForBranch(branchId) {
      // الأسباب العامة (branch_id = null) متاحة للكل، زائد أسباب
      // الفرع نفسه لو موجود
      let query = db
        .from('expense_reasons')
        .select('id, name, is_advance, branch_id')
        .is('deleted_at', null)
        .eq('is_active', true)
        .order('name');

      query = branchId ? query.or(`branch_id.is.null,branch_id.eq.${branchId}`) : query.is('branch_id', null);

      const { data, error } = await query;
      if (error) throw Errors.internal(`expense reasons: ${error.message}`);
      return (data ?? []).map(map);
    },

    async findById(id) {
      const { data, error } = await db
        .from('expense_reasons')
        .select('id, name, is_advance, branch_id')
        .eq('id', id)
        .is('deleted_at', null)
        .eq('is_active', true)
        .maybeSingle();

      if (error) throw Errors.internal(`expense reason findById: ${error.message}`);
      return data ? map(data) : null;
    },
  };
}

// ═══════════════════════════════════════════════════════════
//  المنتجات
//
//  ⚠ أهم فقرة أمنية في الملف كله.
//
//  عمود `cost_piastres` بيتحطّ في قائمة الأعمدة المطلوبة **بس لو**
//  اللي بيقرا عنده صلاحية رؤية التكلفة. لو مالوش، العمود مش
//  بيتطلب من قاعدة البيانات أصلاً — يعني مش موجود في الرد الخام،
//  مش موجود وفاضي.
//
//  تشبيه: مش بتصوّر الملف كامل وتغطّي صفحة بشريط أسود. بتصوّر
//  الصفحات اللي المفروض يشوفها بس.
//
//  وكل مسار بيرجّع منتج بيمر على الدالتين دول. صفر استثناءات —
//  ولو حد ضاف مسار جديد بكرة، لازم يعدّي من هنا.
// ═══════════════════════════════════════════════════════════

const PRODUCT_BASE_COLUMNS = 'id, branch_id, name, price_piastres, quantity_on_hand, is_active';

function productColumns(includeCost: boolean): string {
  return includeCost ? `${PRODUCT_BASE_COLUMNS}, cost_piastres` : PRODUCT_BASE_COLUMNS;
}

interface RawProduct {
  id: string;
  branch_id: string;
  name: string;
  price_piastres: number | string;
  quantity_on_hand: number | string;
  is_active: boolean;
  cost_piastres?: number | string;
}

function toProduct(raw: RawProduct): ProductRecord {
  const record: ProductRecord = {
    id: raw.id,
    branchId: raw.branch_id,
    name: raw.name,
    // bigint ممكن يرجع كنص من PostgREST — بنوحّده لرقم
    pricePiastres: Number(raw.price_piastres),
    quantityOnHand: Number(raw.quantity_on_hand),
    isActive: raw.is_active,
  };

  // الحقل بيتضاف **بس** لو رجع فعلاً من القاعدة. مفيش
  // `costPiastres: 0` كقيمة افتراضية — ده كان هيبقى كذب مهذّب.
  if (raw.cost_piastres !== undefined && raw.cost_piastres !== null) {
    record.costPiastres = Number(raw.cost_piastres);
  }

  return record;
}

export function createProductRepository(db: SupabaseClient): ProductRepository {
  return {
    async list(scope, options: ProductListOptions) {
      let query = db
        .from('products')
        .select(productColumns(options.includeCost))
        .is('deleted_at', null)
        .order('name')
        .limit(500);

      // نفس نمط المستخدمين: النوع بيجبرنا نتعامل مع الحالتين
      // صراحةً. مفيش "لو نسيت الفلتر هيعرض الكل".
      if (!('allBranches' in scope)) {
        query = query.eq('branch_id', scope.branchId);
      }
      if (options.activeOnly) {
        query = query.eq('is_active', true);
      }

      const { data, error } = await query;
      if (error) throw Errors.internal(`products list: ${error.message}`);

      return ((data ?? []) as unknown as RawProduct[]).map(toProduct);
    },

    async findById(id, options) {
      const { data, error } = await db
        .from('products')
        .select(productColumns(options.includeCost))
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`product findById: ${error.message}`);
      return data ? toProduct(data as unknown as RawProduct) : null;
    },

    async create(data) {
      const { data: row, error } = await db
        .from('products')
        .insert({
          branch_id: data.branchId,
          name: data.name,
          price_piastres: data.pricePiastres,
          cost_piastres: data.costPiastres,
          quantity_on_hand: data.quantityOnHand,
          is_active: true,
          created_by_id: data.createdById,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = unique violation — نفس الاسم في نفس الفرع
        if (error?.code === '23505') {
          throw Errors.validation('يوجد منتج بالاسم نفسه في هذا الفرع.');
        }
        throw Errors.internal(`product insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },

    async update(id, data) {
      const patch: Record<string, unknown> = {};
      if (data.name !== undefined) patch.name = data.name;
      if (data.pricePiastres !== undefined) patch.price_piastres = data.pricePiastres;
      if (data.costPiastres !== undefined) patch.cost_piastres = data.costPiastres;
      if (data.isActive !== undefined) patch.is_active = data.isActive;

      const { error } = await db.from('products').update(patch).eq('id', id).is('deleted_at', null);

      if (error) {
        if (error.code === '23505') {
          throw Errors.validation('يوجد منتج بالاسم نفسه في هذا الفرع.');
        }
        throw Errors.internal(`product update: ${error.message}`);
      }
    },

    /**
     * تعديل الكمية بأمان ضد التزامن.
     *
     * ══ المشكلة اللي بتحلّها ══
     * المدير بيورّد 5 والموظّف بيبيع 1 في نفس الثانية:
     *   المدير يقرا 10 → الموظّف يبيع فتبقى 9 → المدير يكتب 15
     * النتيجة 15 والصح 14. البيعة اتمسحت من المخزون.
     *
     * ══ الحل ══
     * بنكتب بشرط: "غيّرها لـ 15 **بس لو** لسه 10". لو حد سبقنا،
     * التحديث ما بيأثّرش على أي صف، فبنقرا من جديد ونعيد.
     *
     * تشبيه: بتوقّع على استمارة وتقول "ده صحيح طالما الرصيد لسه
     * زي ما شفته". لو اتغيّر، الاستمارة بتترفض وبتعيد من الأول
     * بدل ما تدهس شغل حد.
     *
     * (البيع نفسه ما بيمرّش من هنا خالص — بيقفل السطر في قاعدة
     * البيانات جوّه المعاملة. ده للتوريد والجرد بس.)
     */
    async adjustQuantity(id, delta) {
      for (let attempt = 0; attempt < 4; attempt++) {
        const { data: current, error: readError } = await db
          .from('products')
          .select('quantity_on_hand')
          .eq('id', id)
          .is('deleted_at', null)
          .maybeSingle();

        if (readError) throw Errors.internal(`product read qty: ${readError.message}`);
        if (!current) throw Errors.notFound('المنتج');

        const before = Number(current.quantity_on_hand);
        const after = before + delta;

        if (after < 0) {
          throw Errors.validation(`الكمية المتاحة ${before} فقط، وهي لا تكفي لهذا الخصم.`);
        }

        const { data: rows, error } = await db
          .from('products')
          .update({ quantity_on_hand: after })
          .eq('id', id)
          .eq('quantity_on_hand', before) // ← الشرط اللي بيمنع الدهس
          .is('deleted_at', null)
          .select('quantity_on_hand');

        if (error) {
          // 23514 = القيد في القاعدة رفض كمية سالبة
          if (error.code === '23514') {
            throw Errors.validation('الكمية لا تكفي لهذا الخصم.');
          }
          throw Errors.internal(`product adjust qty: ${error.message}`);
        }

        if (rows && rows.length > 0) return Number(rows[0].quantity_on_hand);
        // صفر صفوف = حد غيّرها بينا. نعيد بالقيمة الجديدة.
      }

      throw Errors.validation('المخزون قيد التغيير الآن. أعد المحاولة بعد لحظة.');
    },
  };
}

// ═══════════════════════════════════════════════════════════
//  المبيعات
// ═══════════════════════════════════════════════════════════

const SALE_COLUMNS =
  'id, branch_id, staff_id, customer_name, customer_phone, total_piastres, treasury_id, created_at';

interface RawSale {
  id: string;
  branch_id: string;
  staff_id: string;
  customer_name: string | null;
  customer_phone: string | null;
  total_piastres: number | string;
  treasury_id: string;
  created_at: string;
}

function toSale(raw: RawSale): SaleSummary {
  return {
    id: raw.id,
    branchId: raw.branch_id,
    staffId: raw.staff_id,
    customerName: raw.customer_name,
    customerPhone: raw.customer_phone,
    totalPiastres: Number(raw.total_piastres),
    treasuryId: raw.treasury_id,
    createdAt: new Date(raw.created_at),
  };
}

/**
 * ترجمة أخطاء دالة البيع لأخطاء التطبيق.
 *
 * الدالة في قاعدة البيانات بترمي أكواد على وزن أكواد HTTP عشان
 * الترجمة تبقى واضحة ومفيش تخمين:
 *   MZ400 مدخلات غلط · MZ403 بره نطاقك
 *   MZ404 مش موجود   · MZ409 الكمية مش كافية
 *
 * الرسائل نفسها مكتوبة بالعربي جوّه الدالة، فبنمرّرها زي ما هي —
 * هي مكتوبة أصلاً عشان الموظّف يقراها قدّام الزبون.
 */
function raiseSaleError(error: { code?: string; message?: string }): never {
  const message = error.message?.trim() || 'تعذّر إتمام البيع.';

  switch (error.code) {
    case 'MZ409':
    case 'MZ400':
      throw Errors.validation(message);
    case 'MZ403':
      throw Errors.forbidden(`sale scope: ${message}`);
    case 'MZ404':
      throw Errors.notFound('العنصر المطلوب');
    default:
      // 23514 = قيد في القاعدة رفض السجل (مخزون سالب مثلاً)
      if (error.code === '23514') throw Errors.validation('الكمية غير كافية.');
      throw Errors.internal(`fn_create_sale: ${error.message}`);
  }
}

export function createSaleRepository(db: SupabaseClient): SaleRepository {
  return {
    /**
     * نداء واحد بيعمل كل حاجة.
     *
     * مفيش هنا "اخصم المخزون" وبعدين "اكتب الفاتورة" — دي كانت
     * هتبقى رحلتين شبكة، ولو التانية فشلت المخزون يبقى اتخصم بلا
     * فاتورة. الأربع خطوات جوّه معاملة واحدة في القاعدة.
     */
    async create(input) {
      const { data, error } = await db.rpc('fn_create_sale', {
        p_staff_id: input.staffId,
        p_treasury_id: input.treasuryId,
        p_items: input.items.map((line) => ({
          product_id: line.productId,
          quantity: line.quantity,
        })),
        p_customer_name: input.customerName,
        p_customer_phone: input.customerPhone,
      });

      if (error) raiseSaleError(error);

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_sale: مفيش نتيجة');

      return {
        saleId: String(row.sale_id),
        totalPiastres: Number(row.total_piastres),
        movementId: String(row.movement_id),
        itemCount: Number(row.item_count),
      };
    },

    async list(filter) {
      let query = db
        .from('sales')
        .select(SALE_COLUMNS)
        .is('deleted_at', null)
        .order('created_at', { ascending: false })
        .limit(filter.limit);

      if (!('allBranches' in filter.scope)) {
        query = query.eq('branch_id', filter.scope.branchId);
      }
      // الموظّف بيشوف فواتيره هو بس
      if (filter.staffId) {
        query = query.eq('staff_id', filter.staffId);
      }

      const { data, error } = await query;
      if (error) throw Errors.internal(`sales list: ${error.message}`);

      return ((data ?? []) as RawSale[]).map(toSale);
    },

    async findById(id, options) {
      const { data: head, error: headError } = await db
        .from('sales')
        .select(SALE_COLUMNS)
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (headError) throw Errors.internal(`sale findById: ${headError.message}`);
      if (!head) return null;

      // نفس قاعدة التكلفة بالظبط: العمود بيتطلب بس لصاحب الصلاحية
      const itemColumns = options.includeCost
        ? 'product_id, quantity, unit_price_piastres, unit_cost_piastres, product:products(name)'
        : 'product_id, quantity, unit_price_piastres, product:products(name)';

      const { data: rows, error } = await db
        .from('sale_items')
        .select(itemColumns)
        .eq('sale_id', id);

      if (error) throw Errors.internal(`sale items: ${error.message}`);

      const items: SaleItemLine[] = ((rows ?? []) as unknown as Array<{
        product_id: string;
        quantity: number | string;
        unit_price_piastres: number | string;
        unit_cost_piastres?: number | string;
        product: { name: string } | { name: string }[] | null;
      }>).map((r) => {
        // العلاقة ممكن ترجع كائن أو مصفوفة حسب استنتاج PostgREST
        const product = Array.isArray(r.product) ? r.product[0] : r.product;
        const quantity = Number(r.quantity);
        const unitPricePiastres = Number(r.unit_price_piastres);

        const line: SaleItemLine = {
          productId: r.product_id,
          // المنتج ممكن يكون اتحذف ناعمًا بعد البيع — الفاتورة
          // بتفضل صحيحة والاسم بيفضل مكتوب
          productName: product?.name ?? 'منتج محذوف',
          quantity,
          unitPricePiastres,
          lineTotalPiastres: unitPricePiastres * quantity,
        };

        if (r.unit_cost_piastres !== undefined && r.unit_cost_piastres !== null) {
          line.unitCostPiastres = Number(r.unit_cost_piastres);
        }

        return line;
      });

      const detail: SaleDetail = { ...toSale(head as RawSale), items };
      return detail;
    },
  };
}

// ─────────── الجلسات ───────────

interface RawSession {
  id: string;
  user_id: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string | null;
  locked_at: string | null;
}

function toSessionRecord(raw: RawSession): SessionRecord {
  return {
    id: raw.id,
    userId: raw.user_id,
    lastSeenAt: new Date(raw.last_seen_at),
    expiresAt: new Date(raw.expires_at),
    revokedAt: toDate(raw.revoked_at),
    lockedAt: toDate(raw.locked_at),
  };
}

const SESSION_COLUMNS = 'id, user_id, last_seen_at, expires_at, revoked_at, locked_at';

export function createSessionRepository(db: SupabaseClient): SessionRepository {
  return {
    async create(data) {
      const { data: row, error } = await db
        .from('sessions')
        .insert({
          user_id: data.userId,
          refresh_token_hash: data.refreshTokenHash,
          expires_at: data.expiresAt.toISOString(),
          ip_address: data.ipAddress ?? null,
          user_agent: data.userAgent?.slice(0, 255) ?? null,
        })
        .select(SESSION_COLUMNS)
        .single();

      if (error || !row) throw Errors.internal(`session insert: ${error?.message}`);
      return toSessionRecord(row as RawSession);
    },

    async findActiveByDigest(digest) {
      const { data } = await db
        .from('sessions')
        .select(SESSION_COLUMNS)
        .eq('refresh_token_hash', digest)
        .is('revoked_at', null)
        .maybeSingle();

      return data ? toSessionRecord(data as RawSession) : null;
    },

    async findActiveById(id) {
      const { data } = await db
        .from('sessions')
        .select(SESSION_COLUMNS)
        .eq('id', id)
        .is('revoked_at', null)
        .maybeSingle();

      return data ? toSessionRecord(data as RawSession) : null;
    },

    async touch(id, at) {
      await db
        .from('sessions')
        .update({ last_seen_at: at.toISOString() })
        .eq('id', id)
        .is('revoked_at', null);
    },

    async rotate(id, newDigest, at) {
      await db
        .from('sessions')
        .update({ refresh_token_hash: newDigest, last_seen_at: at.toISOString() })
        .eq('id', id);
    },

    async revoke(id, reason, at) {
      await db
        .from('sessions')
        .update({ revoked_at: at.toISOString(), revoke_reason: reason })
        .eq('id', id)
        .is('revoked_at', null);
    },

    async revokeAllForUser(userId, reason, at) {
      await db
        .from('sessions')
        .update({ revoked_at: at.toISOString(), revoke_reason: reason })
        .eq('user_id', userId)
        .is('revoked_at', null);
    },

    async lock(id, at) {
      // ملاحظة: مش بنحدّث last_seen_at هنا. وقت القفل بيتسجّل
      // في locked_at، وعدّاد الخمول بيفضل زي ما هو.
      await db
        .from('sessions')
        .update({ locked_at: at.toISOString() })
        .eq('id', id)
        .is('revoked_at', null);
    },

    async unlock(id, at) {
      // فك القفل + تصفير عدّاد الخمول في تحديث واحد — عشان الموظّف
      // ما يتقفلش تاني بعد ثانية لأن last_seen_at لسه قديم
      await db
        .from('sessions')
        .update({ locked_at: null, last_seen_at: at.toISOString() })
        .eq('id', id)
        .is('revoked_at', null);
    },
  };
}

// ─────────── الإعلانات ───────────

export function createAnnouncementRepository(db: SupabaseClient): AnnouncementRepository {
  return {
    async findPendingFor(user: AuthenticatedUser): Promise<AnnouncementRecord[]> {
      const { data, error } = await db.rpc('fn_pending_announcements', { p_user_id: user.id });
      if (error) throw Errors.internal(`fn_pending_announcements: ${error.message}`);

      const rows = (data ?? []) as Array<{
        id: string;
        title: string;
        body: string;
        severity: 'INFO' | 'WARNING' | 'CRITICAL';
        is_mandatory: boolean;
        created_at: string;
      }>;

      return rows.map((row) => ({
        id: row.id,
        title: row.title,
        body: row.body,
        severity: row.severity,
        isMandatory: row.is_mandatory,
        createdAt: new Date(row.created_at),
      }));
    },

    async acknowledge(announcementId, userId, at) {
      // upsert لأن الضغط المزدوج على شاشة لمس شائع جداً
      await db.from('announcement_receipts').upsert(
        {
          announcement_id: announcementId,
          user_id: userId,
          acknowledged_at: at.toISOString(),
        },
        { onConflict: 'announcement_id,user_id', ignoreDuplicates: true },
      );
    },

    async create(data) {
      const { data: row, error } = await db
        .from('announcements')
        .insert({
          title: data.title,
          body: data.body,
          severity: data.severity,
          audience: data.audience,
          branch_id: data.branchId,
          is_mandatory: data.isMandatory,
          starts_at: data.startsAt.toISOString(),
          ends_at: data.endsAt?.toISOString() ?? null,
          created_by_id: data.createdById,
        })
        .select('id')
        .single();

      if (error || !row) throw Errors.internal(`announcement insert: ${error?.message}`);
      return { id: row.id as string };
    },
  };
}

// ─────────── سجل التدقيق ───────────

export function createAuditLogger(db: SupabaseClient): AuditLogger {
  return {
    async record(entry) {
      try {
        await db.from('audit_logs').insert({
          actor_id: entry.actorId ?? null,
          action: entry.action,
          entity: entry.entity ?? null,
          entity_id: entry.entityId ?? null,
          metadata: entry.metadata ?? null,
          ip_address: entry.ipAddress ?? null,
          user_agent: entry.userAgent?.slice(0, 255) ?? null,
        });
      } catch (error) {
        // فشل التدقيق ما يصحّش يمنع المستخدم من الشغل — بس لازم يتسجّل
        console.error('[audit] فشل كتابة سجل التدقيق:', entry.action, error);
      }
    },
  };
}

// ─────────── حدّ المحاولات ───────────

/**
 * على كلاودفلير مفيش ذاكرة دائمة بين الطلبات — كل طلب بيبدأ من الصفر.
 * تشبيه: الحكم بينسى العدّ بعد كل جولة. فبنخزّن العدّاد في قاعدة البيانات.
 */
export function createRateLimiter(db: SupabaseClient): RateLimiter {
  return {
    async check(key, limit, windowSeconds) {
      const { data, error } = await db.rpc('fn_rate_limit', {
        p_key: key,
        p_limit: limit,
        p_window: windowSeconds,
      });

      if (error) {
        // لو محدّد المحاولات وقع، منقفلش الباب في وش الموظفين.
        // بس بنصرخ في اللوق عشان تعرف إن الحماية دي واقعة.
        console.error('[rate-limit] الدالة فشلت، السماح مؤقتاً:', error.message);
        return null;
      }

      return (data as number | null) ?? null;
    },

    async reset(key) {
      await db.rpc('fn_rate_limit_reset', { p_key: key });
    },
  };
}
