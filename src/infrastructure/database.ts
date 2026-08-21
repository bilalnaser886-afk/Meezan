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
  CustomerRecord,
  CustomerRepository,
  PriceChangeRecord,
  ProductListOptions,
  ProductRecord,
  ProductRepository,
  ProductType,
  RateLimiter,
  ListScope,
  RoleKey,
  SaleDetail,
  SaleItemLine,
  SaleRepository,
  SaleSummary,
  SessionRecord,
  TenantRecord,
  TenantRepository,
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
  tenant_id: string;
  tenant_code: string;
  tenant_name: string;
  tenant_active: boolean;
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
    tenantId: raw.tenant_id,
    tenantCode: raw.tenant_code,
    tenantName: raw.tenant_name,
    tenantActive: raw.tenant_active,
  };
}

// ─────────── المستخدمون ───────────

/**
 * ترجمة نطاق البحث لفلتر استعلام.
 *
 * ⚠ الدالة دي هي **النقطة الوحيدة** اللي بيتحوّل فيها النطاق
 * لفلتر. كل مستودع بيمر منها.
 *
 * ليه واحدة؟ عشان لو فيه غلطة في ترجمة النطاق، تبقى غلطة واحدة
 * في مكان واحد — مش عشر غلطات متفرّقة في عشر استعلامات.
 *
 * تشبيه: مفتاح واحد لكل الأبواب أحسن من عشر أقفال كل واحد بمفتاح
 * مختلف — لما تحتاج تغيّر القفل، بتغيّره مرة.
 */
function applyScope<T extends { eq: (col: string, val: string) => T }>(
  query: T,
  scope: ListScope,
): T {
  // مشغّل المنصّة: مفيش فلتر محل. الحالة الوحيدة، ومكتوبة صراحةً.
  if ('allTenants' in scope) return query;

  let scoped = query.eq('tenant_id', scope.tenantId);
  if ('branchId' in scope) scoped = scoped.eq('branch_id', scope.branchId);
  return scoped;
}

export function createUserRepository(db: SupabaseClient): UserRepository {
  return {
    /**
     * البحث بكود المحل + الاسم.
     *
     * ⚠ الدالة الجديدة `fn_login_lookup_scoped` بتربط جدول المحلات
     * جوّاها، فبترجّع حالة الاشتراك كمان. الفرق ده مهم: التطبيق
     * بيفرّق بين "بيانات غلط" و"اشتراك موقوف" — رسالتين مختلفتين.
     */
    async findByTenantAndUsername(tenantCode, username) {
      const { data, error } = await db.rpc('fn_login_lookup_scoped', {
        p_tenant_code: tenantCode,
        p_username: username,
      });

      if (error) throw Errors.internal(`login lookup: ${error.message}`);

      const row = (data as RawUser[] | null)?.[0];
      return row ? toUserRecord(row) : null;
    },

    async findById(id) {
      const { data, error } = await db.rpc('fn_user_by_id_scoped', { p_user_id: id });
      if (error) throw Errors.internal(`fn_user_by_id_scoped: ${error.message}`);

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
      // ⚠ بنمسح علم "لازم تغيّر كلمة المرور" مع الهاش في نفس
      // التحديث. لو سيبناه، المستخدم يغيّر كلمته والنظام يفضل
      // شايفه كأنه ما غيّرش.
      await db
        .from('users')
        .update({ password_hash: hash, must_change_password: false })
        .eq('id', userId);
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
          tenant_id: data.tenantId,
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
      const query = db
        .from('users')
        .select('id, username, full_name, branch_id, is_active, created_at, roles!inner(key)')
        .is('deleted_at', null)
        .order('full_name')
        .limit(200);

      // ⚠ الفلتر بيمر من applyScope. مفيش استعلام بيبني فلتره بإيده.
      const { data, error } = await applyScope(query, scope);
      if (error) throw Errors.internal(`users listInScope: ${error.message}`);

      return ((data ?? []) as unknown as Array<{
        id: string;
        username: string;
        full_name: string;
        branch_id: string | null;
        is_active: boolean;
        created_at: string;
        roles: { key: string } | { key: string }[] | null;
      }>).map((r): TeamMember => {
        const role = Array.isArray(r.roles) ? r.roles[0] : r.roles;
        return {
          id: r.id,
          username: r.username,
          fullName: r.full_name,
          roleKey: (role?.key ?? 'STAFF') as RoleKey,
          branchId: r.branch_id,
          isActive: r.is_active,
          createdAt: new Date(r.created_at),
        };
      });
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
  const COLUMNS = 'id, tenant_id, code, name, is_active';

  function toBranch(r: {
    id: string; tenant_id: string; code: string; name: string; is_active: boolean;
  }): BranchSummary {
    return {
      id: r.id,
      tenantId: r.tenant_id,
      code: r.code,
      name: r.name,
      isActive: r.is_active,
    };
  }

  return {
    async listActive(tenantId) {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .eq('tenant_id', tenantId)
        .eq('is_active', true)
        .is('deleted_at', null)
        .order('name');

      if (error) throw Errors.internal(`branches listActive: ${error.message}`);
      return ((data ?? []) as never[]).map(toBranch);
    },

    async listAll(tenantId) {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .order('name');

      if (error) throw Errors.internal(`branches listAll: ${error.message}`);
      return ((data ?? []) as never[]).map(toBranch);
    },

    /**
     * ⚠ المحل شرط في الفحص مش سياق حواليه.
     *
     * لو فحصنا وجود الفرع بمعرّفه بس، صاحب محل يقدر يربط موظّف
     * أو منتج بفرع محل تاني — كل اللي محتاجه معرّف صحيح.
     */
    async exists(tenantId, branchId) {
      const { data, error } = await db
        .from('branches')
        .select('id')
        .eq('id', branchId)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`branch exists: ${error.message}`);
      return Boolean(data);
    },

    async findByCode(tenantId, code) {
      const { data, error } = await db
        .from('branches')
        .select(COLUMNS)
        .eq('tenant_id', tenantId)
        .eq('code', code)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`branch findByCode: ${error.message}`);
      return data ? toBranch(data as never) : null;
    },

    async create(data) {
      const { data: row, error } = await db
        .from('branches')
        .insert({
          tenant_id: data.tenantId,
          code: data.code,
          name: data.name,
          address: data.address,
          phone: data.phone,
        })
        .select('id')
        .single();

      if (error || !row) {
        if (error?.code === '23505') {
          throw Errors.validation('كود الفرع ده مستخدم بالفعل.');
        }
        throw Errors.internal(`branch insert: ${error?.message}`);
      }
      return { id: row.id as string };
    },

    /** لفحص حد الفروع المسموح في الاشتراك */
    async countActive(tenantId) {
      const { count, error } = await db
        .from('branches')
        .select('id', { count: 'exact', head: true })
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`branches count: ${error.message}`);
      return count ?? 0;
    },
  };
}

// ─────────── المحلات ───────────

const TENANT_COLUMNS = 'id, code, name, is_active, max_branches, notes, created_at';

interface RawTenant {
  id: string;
  code: string;
  name: string;
  is_active: boolean;
  max_branches: number | string;
  notes: string | null;
  created_at: string;
}

function toTenant(r: RawTenant): TenantRecord {
  return {
    id: r.id,
    code: r.code,
    name: r.name,
    isActive: r.is_active,
    maxBranches: Number(r.max_branches),
    notes: r.notes,
    createdAt: new Date(r.created_at),
  };
}

export function createTenantRepository(db: SupabaseClient): TenantRepository {
  return {
    async findById(id) {
      const { data, error } = await db
        .from('tenants')
        .select(TENANT_COLUMNS)
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`tenant findById: ${error.message}`);
      if (!data) return null;

      const r = data as RawTenant;
      return toTenant(r);
    },

    async findByCode(code) {
      const { data, error } = await db
        .from('tenants')
        .select(TENANT_COLUMNS)
        .ilike('code', code)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`tenant findByCode: ${error.message}`);
      return data ? toTenant(data as RawTenant) : null;
    },

    async listOverview() {
      const { data, error } = await db.rpc('fn_tenants_overview');
      if (error) throw Errors.internal(`tenants overview: ${error.message}`);

      return ((data ?? []) as Array<RawTenant & {
        branch_count: number | string;
        user_count: number | string;
        owner_name: string | null;
      }>).map((r) => ({
        ...toTenant(r),
        branchCount: Number(r.branch_count),
        userCount: Number(r.user_count),
        ownerName: r.owner_name,
      }));
    },

    /**
     * فتح محل — نداء واحد لا يتجزّأ.
     *
     * الدالة في قاعدة البيانات بتعمل: المحل + أول فرع + حساب
     * المالك + أسباب الصرف + خزينة كاش. لو وقع أي جزء، مفيش
     * حاجة بتتكتب — بدل ما يبقى عندنا محل نصّه مركّب وصاحبه
     * يدخل يلاقي نظام مكسور من أول يوم.
     */
    async create(data) {
      const { data: rows, error } = await db.rpc('fn_create_tenant', {
        p_code: data.code,
        p_name: data.name,
        p_max_branches: data.maxBranches,
        p_owner_username: data.ownerUsername,
        p_owner_full_name: data.ownerFullName,
        p_owner_password_hash: data.ownerPasswordHash,
        p_branches: data.branches.map((b) => ({ code: b.code, name: b.name })),
        p_users: data.users.map((u) => ({
          username: u.username,
          full_name: u.fullName,
          password_hash: u.passwordHash,
          role: u.role,
          branch_code: u.branchCode,
        })),
      });

      if (error) {
        if (error.code === 'MZ400') throw Errors.validation(error.message);
        if (error.code === '23505') {
          throw Errors.validation('كود المحل أو اسم المستخدم مستخدم بالفعل.');
        }
        throw Errors.internal(`fn_create_tenant: ${error.message}`);
      }

      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_tenant: مفيش نتيجة');

      return {
        tenantId: String(row.tenant_id),
        ownerId: String(row.owner_id),
        branchCount: Number(row.branch_count),
        userCount: Number(row.user_count),
      };
    },

    async setActive(id, isActive) {
      const { error } = await db
        .from('tenants')
        .update({ is_active: isActive })
        .eq('id', id)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`tenant setActive: ${error.message}`);
    },

    async setMaxBranches(id, maxBranches) {
      const { error } = await db
        .from('tenants')
        .update({ max_branches: maxBranches })
        .eq('id', id)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`tenant setMaxBranches: ${error.message}`);
    },

    async platformAdminExists() {
      const { data, error } = await db.rpc('fn_platform_admin_exists');
      if (error) throw Errors.internal(`platform admin exists: ${error.message}`);
      return Boolean(data);
    },

    async createPlatformAdmin(data) {
      const { data: rows, error } = await db.rpc('fn_create_platform_admin', {
        p_tenant_id: data.tenantId,
        p_username: data.username,
        p_full_name: data.fullName,
        p_password_hash: data.passwordHash,
        p_passkey_hash: data.passkeyHash,
      });

      if (error) {
        if (error.code === 'MZ409') throw Errors.validation('مشغّل المنصّة موجود بالفعل.');
        if (error.code === '23505') throw Errors.validation('اسم المستخدم مستخدم بالفعل.');
        throw Errors.internal(`fn_create_platform_admin: ${error.message}`);
      }

      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_platform_admin: مفيش نتيجة');
      return { id: String(row.user_id) };
    },

    /** جرد المحل — بيتعرض في شاشة التأكيد قبل المحو */
    async census(id) {
      const { data: rows, error } = await db.rpc('fn_tenant_census', { p_tenant_id: id });
      if (error) throw Errors.internal(`fn_tenant_census: ${error.message}`);

      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) return null;

      return {
        code: String(row.code),
        name: String(row.name),
        isActive: Boolean(row.is_active),
        branchCount: Number(row.branch_count),
        userCount: Number(row.user_count),
        productCount: Number(row.product_count),
        customerCount: Number(row.customer_count),
        saleCount: Number(row.sale_count),
        salesTotalPiastres: Number(row.sales_total_piastres),
        movementCount: Number(row.movement_count),
        auditCount: Number(row.audit_count),
        hasPlatformAdmin: Boolean(row.has_platform_admin),
      };
    },

    /**
     * المحو النهائي.
     *
     * ⚠ كل الأقفال جوّه دالة قاعدة البيانات، والرسايل اللي بترجع
     * منها عربية جاهزة للعرض (MZ400). بنعديها زي ما هي بدل ما
     * نكتب نسخة تانية منها هنا وتختلف عنها بعد شهرين.
     */
    async purge(id, actorId) {
      const { data: rows, error } = await db.rpc('fn_purge_tenant', {
        p_tenant_id: id,
        p_actor_id: actorId,
      });

      if (error) {
        if (error.code === 'MZ400') throw Errors.validation(error.message);
        if (error.code === 'MZ403') throw Errors.forbidden('purge tenant');
        if (error.code === 'MZ404') throw Errors.notFound('المحل');
        throw Errors.internal(`fn_purge_tenant: ${error.message}`);
      }

      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_purge_tenant: مفيش نتيجة');

      return {
        code: String(row.purged_code),
        name: String(row.purged_name),
        deletedUsers: Number(row.deleted_users),
        deletedSales: Number(row.deleted_sales),
      };
    },
  };
}

// ─────────── الخزينة ───────────

export function createTreasuryRepository(db: SupabaseClient): TreasuryRepository {
  return {
    async listBalances(tenantId, branchId) {
      // الرصيد محسوب في قاعدة البيانات مش هنا — الجمع مكانه جنب
      // الدفتر، مش في رحلة شبكة
      const { data, error } = await db.rpc('fn_treasury_balances_scoped', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`fn_treasury_balances_scoped: ${error.message}`);

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
        .select('tenant_id, branch_id')
        .eq('id', treasuryId)
        .is('deleted_at', null)
        .eq('is_active', true)
        .maybeSingle();

      if (error) throw Errors.internal(`treasury findScope: ${error.message}`);
      if (!data) return null;

      const r = data as { tenant_id: string; branch_id: string | null };
      return { tenantId: r.tenant_id, branchId: r.branch_id };
    },
  };
}

// ─────────── حركات الخزينة ───────────

const MOVEMENT_COLUMNS =
  'id, tenant_id, treasury_id, branch_id, direction, type, amount_piastres, status, ' +
  'expense_reason_id, related_user_id, note, occurred_at, created_by_id';

interface RawMovement {
  id: string;
  tenant_id: string;
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
    tenantId: raw.tenant_id,
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

      // ⚠ المحل أول فلتر ودايمًا موجود. الفرع فوقه واختياري.
      query = query.eq('tenant_id', filter.tenantId);
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
    tenant_id: string;
    is_advance: boolean;
    branch_id: string | null;
  }): ExpenseReason => ({
    id: r.id,
    name: r.name,
    tenantId: r.tenant_id,
    isAdvance: r.is_advance,
    branchId: r.branch_id,
  });

  return {
    async listForBranch(tenantId, branchId) {
      // الأسباب العامة (branch_id = null) متاحة للكل، زائد أسباب
      // الفرع نفسه لو موجود
      let query = db
        .from('expense_reasons')
        .select('id, tenant_id, name, is_advance, branch_id')
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
        .select('id, tenant_id, name, is_advance, branch_id')
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

const PRODUCT_BASE_COLUMNS =
  'id, tenant_id, branch_id, name, product_type, serial_number, source, entry_date, ' +
  'price_piastres, quantity_on_hand, is_active';

function productColumns(includeCost: boolean): string {
  return includeCost ? `${PRODUCT_BASE_COLUMNS}, cost_piastres` : PRODUCT_BASE_COLUMNS;
}

interface RawProduct {
  id: string;
  tenant_id: string;
  branch_id: string;
  name: string;
  product_type: string;
  serial_number: string | null;
  source: string | null;
  entry_date: string;
  price_piastres: number | string | null;
  quantity_on_hand: number | string;
  is_active: boolean;
  cost_piastres?: number | string;
}

function toProduct(raw: RawProduct): ProductRecord {
  const record: ProductRecord = {
    id: raw.id,
    tenantId: raw.tenant_id,
    branchId: raw.branch_id,
    name: raw.name,
    productType: (raw.product_type === 'device' ? 'device' : 'accessory') as ProductType,
    serialNumber: raw.serial_number,
    source: raw.source,
    // عمود date بيرجع نص زي "2026-08-15" — بنسيبه نص.
    // تحويله لـ Date بيحطّ عليه وقت ومنطقة زمنية، وأول ما يترجع
    // بيتزحلق يوم في اتجاه أو التاني.
    entryDate: String(raw.entry_date).slice(0, 10),
    // ⚠ null معناها "المنتج لسه ما اتسعّرش" — مش صفر.
    // لو حوّلناها صفر، Number(null) هيدّي 0 والفرق يضيع.
    pricePiastres: raw.price_piastres === null ? null : Number(raw.price_piastres),
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
      query = applyScope(query, scope);
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
          tenant_id: data.tenantId,
          branch_id: data.branchId,
          name: data.name,
          product_type: data.productType,
          serial_number: data.serialNumber,
          source: data.source,
          // null = سيب افتراضي قاعدة البيانات يشتغل (تاريخ القاهرة)
          ...(data.entryDate ? { entry_date: data.entryDate } : {}),
          price_piastres: data.pricePiastres,
          cost_piastres: data.costPiastres,
          quantity_on_hand: data.quantityOnHand,
          is_active: true,
          created_by_id: data.createdById,
          updated_by_id: data.createdById,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = تكرار. فيه فهرسين فريدين على الجدول دلوقتي،
        // فبنقرا اسم الفهرس عشان نقول للمستخدم إيه بالظبط المتكرر
        // بدل رسالة عامة تخليه يدوّر.
        if (error?.code === '23505') {
          const detail = `${error.message} ${error.details ?? ''}`;
          if (detail.includes('serial')) {
            throw Errors.validation('الرقم التسلسلي ده مسجّل على منتج آخر.');
          }
          throw Errors.validation('يوجد منتج بالاسم نفسه في هذا الفرع.');
        }
        // 23514 = قيد. الأشهر هنا: جهاز بلا سريال أو كميته أكبر من 1
        if (error?.code === '23514') {
          throw Errors.validation('بيانات المنتج لا تطابق نوعه. الجهاز قطعة واحدة برقم تسلسلي.');
        }
        throw Errors.internal(`product insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },

    async update(id, data) {
      // ⚠ updated_by_id بيتكتب دايمًا. المشغّل اللي بيسجّل تغيير
      // السعر بيقرا منه مين عمل التغيير — من غيره السجل بيتكتب
      // بلا اسم.
      const patch: Record<string, unknown> = { updated_by_id: data.updatedById };
      if (data.name !== undefined) patch.name = data.name;
      if (data.pricePiastres !== undefined) patch.price_piastres = data.pricePiastres;
      if (data.costPiastres !== undefined) patch.cost_piastres = data.costPiastres;
      if (data.isActive !== undefined) patch.is_active = data.isActive;
      if (data.source !== undefined) patch.source = data.source;
      if (data.serialNumber !== undefined) patch.serial_number = data.serialNumber;
      if (data.entryDate !== undefined) patch.entry_date = data.entryDate;

      const { error } = await db.from('products').update(patch).eq('id', id).is('deleted_at', null);

      if (error) {
        if (error.code === '23505') {
          const detail = `${error.message} ${error.details ?? ''}`;
          if (detail.includes('serial')) {
            throw Errors.validation('الرقم التسلسلي ده مسجّل على منتج آخر.');
          }
          throw Errors.validation('يوجد منتج بالاسم نفسه في هذا الفرع.');
        }
        throw Errors.internal(`product update: ${error.message}`);
      }
    },

    /**
     * قراءة سجل الأسعار.
     *
     * الجدول ده بتكتبه قاعدة البيانات بمشغّل، مش الكود. إحنا
     * بنقرا بس — وده مقصود: لو الكتابة كانت من هنا، أي تعديل
     * سعر من محرر سوبابيز مباشرةً كان هيعدّي من غير ما يتسجّل.
     */
    async listPriceHistory(productId, limit) {
      const { data, error } = await db
        .from('product_price_history')
        .select('old_price_piastres, new_price_piastres, changed_by_id, changed_at')
        .eq('product_id', productId)
        .order('changed_at', { ascending: false })
        .limit(limit);

      if (error) throw Errors.internal(`price history: ${error.message}`);

      return ((data ?? []) as Array<{
        old_price_piastres: number | string | null;
        new_price_piastres: number | string | null;
        changed_by_id: string | null;
        changed_at: string;
      }>).map(
        (r): PriceChangeRecord => ({
          oldPricePiastres: r.old_price_piastres === null ? null : Number(r.old_price_piastres),
          newPricePiastres: r.new_price_piastres === null ? null : Number(r.new_price_piastres),
          changedById: r.changed_by_id,
          changedAt: new Date(r.changed_at),
        }),
      );
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
  'id, tenant_id, branch_id, staff_id, customer_name, customer_phone, total_piastres, ' +
  'treasury_id, created_at, exit_date';

interface RawSale {
  id: string;
  tenant_id: string;
  branch_id: string;
  staff_id: string;
  customer_name: string | null;
  customer_phone: string | null;
  total_piastres: number | string;
  treasury_id: string;
  created_at: string;
  exit_date: string;
}

function toSale(raw: RawSale): SaleSummary {
  return {
    id: raw.id,
    tenantId: raw.tenant_id,
    branchId: raw.branch_id,
    staffId: raw.staff_id,
    customerName: raw.customer_name,
    customerPhone: raw.customer_phone,
    totalPiastres: Number(raw.total_piastres),
    treasuryId: raw.treasury_id,
    createdAt: new Date(raw.created_at),
    // نص زي ما هو — تحويله لـ Date بيزحلقه يوم بالتوقيت
    exitDate: String(raw.exit_date).slice(0, 10),
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
          // بيتبعت بس لو موجود. الدالة بتتجاهله لو المنتج له سعر.
          ...(line.unitPricePiastres != null
            ? { unit_price_piastres: line.unitPricePiastres }
            : {}),
        })),
        p_customer_name: input.customerName,
        p_customer_phone: input.customerPhone,
        p_exit_date: input.exitDate,
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

      query = applyScope(query, filter.scope);
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

    /**
     * تعديل تاريخ الخروج — وبس.
     *
     * ⚠ لاحظ إن الكائن المبعوت فيه مفتاح واحد. مفيش updated_at
     * ولا أي حاجة تانية، و`created_at` **مش** في الاستعلام أصلاً.
     *
     * ده مش تقصير — ده الغرض. الختم التقني بيثبت إمتى الفاتورة
     * اتكتبت، والتاريخ التجاري بيقول إمتى البضاعة خرجت. لو عدّلنا
     * الاتنين مع بعض، مش هتعرف أبدًا إن فيه بيعة اتسجّلت متأخر.
     */
    async updateExitDate(id, exitDate) {
      const { error } = await db
        .from('sales')
        .update({ exit_date: exitDate })
        .eq('id', id)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`sale exit date: ${error.message}`);
    },
  };
}

// ═══════════════════════════════════════════════════════════
//  العملاء
// ═══════════════════════════════════════════════════════════

const CUSTOMER_COLUMNS = 'id, tenant_id, branch_id, name, phone, notes, created_at';

interface RawCustomer {
  id: string;
  tenant_id: string;
  branch_id: string;
  name: string;
  phone: string | null;
  notes: string | null;
  created_at: string;
}

function toCustomer(raw: RawCustomer): CustomerRecord {
  return {
    id: raw.id,
    tenantId: raw.tenant_id,
    branchId: raw.branch_id,
    name: raw.name,
    phone: raw.phone,
    notes: raw.notes,
    createdAt: new Date(raw.created_at),
    // الإحصائيات بتتحسب في دالة الترتيب. القراءة بالمعرّف الواحد
    // ما بتحتاجهاش، فبترجع أصفار.
    deviceCount: 0,
    purchaseCount: 0,
    totalPiastres: 0,
  };
}

export function createCustomerRepository(db: SupabaseClient): CustomerRepository {
  return {
    /**
     * القائمة بتتجاب من دالة في قاعدة البيانات مش باستعلام مباشر.
     *
     * السبب: الترتيب محتاج يعدّ الأجهزة في بنود كل فاتورة لكل
     * عميل — ربط تلات جداول وتجميع. لو عملناه هنا، هيبقى استعلام
     * لكل عميل يعني مية رحلة شبكة لصفحة واحدة.
     */
    async list(scope, search, limit) {
      const { data, error } = await db.rpc('fn_customers_ranked_scoped', {
        p_tenant_id: 'allTenants' in scope ? null : scope.tenantId,
        p_branch_id: 'branchId' in scope ? scope.branchId : null,
        p_search: search,
        p_limit: limit,
      });

      if (error) throw Errors.internal(`customers ranked: ${error.message}`);

      return ((data ?? []) as Array<RawCustomer & {
        device_count: number | string;
        purchase_count: number | string;
        total_piastres: number | string;
      }>).map((r) => ({
        ...toCustomer(r),
        deviceCount: Number(r.device_count),
        purchaseCount: Number(r.purchase_count),
        totalPiastres: Number(r.total_piastres),
      }));
    },

    async findById(id) {
      const { data, error } = await db
        .from('customers')
        .select(CUSTOMER_COLUMNS)
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`customer findById: ${error.message}`);
      return data ? toCustomer(data as RawCustomer) : null;
    },

    async create(data) {
      const { data: row, error } = await db
        .from('customers')
        .insert({
          tenant_id: data.tenantId,
          branch_id: data.branchId,
          name: data.name,
          phone: data.phone,
          notes: data.notes,
          created_by_id: data.createdById,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = نفس الرقم مسجّل في الفرع. ده مفيد مش مزعج:
        // بيمنع نفس الزبون يتسجّل مرتين بأشكال مختلفة للاسم.
        if (error?.code === '23505') {
          throw Errors.validation('هذا الرقم مسجّل لعميل آخر في الفرع.');
        }
        throw Errors.internal(`customer insert: ${error?.message}`);
      }

      return { id: row.id as string };
    },

    async update(id, data) {
      const patch: Record<string, unknown> = {};
      if (data.name !== undefined) patch.name = data.name;
      if (data.phone !== undefined) patch.phone = data.phone;
      if (data.notes !== undefined) patch.notes = data.notes;

      const { error } = await db
        .from('customers')
        .update(patch)
        .eq('id', id)
        .is('deleted_at', null);

      if (error) {
        if (error.code === '23505') {
          throw Errors.validation('هذا الرقم مسجّل لعميل آخر في الفرع.');
        }
        throw Errors.internal(`customer update: ${error.message}`);
      }
    },

    async softDelete(id, actorId, at) {
      const { error } = await db
        .from('customers')
        .update({
          deleted_at: at.toISOString(),
          deleted_by: actorId,
          delete_reason: 'حذف من شاشة العملاء',
        })
        .eq('id', id)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`customer delete: ${error.message}`);
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
          tenant_id: data.tenantId,
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
