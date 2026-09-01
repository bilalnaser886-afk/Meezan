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
  WarrantyRepository,
  WarrantyStatus,
  PurchaseRepository,
  PurchaseRow,
  ClosingRepository,
  ClosingRole,
  ClosingSummary,
  ClosingPreview,
  ClosingDetail,
  ClosingSaleLine,
  ClosingMovementLine,
  ClosingPurchaseLine,
  ClosingCostSnapshot,
  CloseDayResult,
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
  CategoryRepository,
  ColorRepository,
  DeviceModel,
  ModelRepository,
  ProductColor,
  ProductRepository,
  ProductType,
  RateLimiter,
  ListScope,
  RoleKey,
  SaleDetail,
  SaleItemLine,
  AlertRepository,
  MaintenanceRecord,
  MaintenanceRepository,
  ShopRepository,
  SupplierBranchBalance,
  SupplierRepository,
  TicketStatus,
  TransferRepository,
  AlertRow,
  ReportRepository,
  ReturnRepository,
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
     * المالك + أسباب الصرف + خزنة كاش. لو وقع أي جزء، مفيش
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
          // ⚠ الرسالة لازم تقول **أنهي** قيد اتكسر، مش تخمّن.
          //
          // الإصدار القديم كان بيقول "كود المحل أو اسم المستخدم"
          // على طول لأنهم أشهر حالتين — والتخمين ده ضيّع وقت
          // تشخيص كامل لما التعارض الحقيقي كان في أسباب الصرف.
          //
          // بوستجرس بيقول اسم القيد في نص الخطأ. بنقراه منه.
          const constraint =
            /constraint "([^"]+)"/.exec(`${error.message} ${error.details ?? ''}`)?.[1] ?? '';

          if (constraint.includes('tenants_code')) {
            throw Errors.validation('كود المحل ده مستخدم بالفعل.');
          }
          if (constraint.includes('users_tenant_username') || constraint.includes('username')) {
            throw Errors.validation('اسم المستخدم ده مستخدم بالفعل داخل هذا المحل.');
          }
          if (constraint.includes('branches_tenant_code')) {
            throw Errors.validation('كود الفرع مكرّر داخل المحل.');
          }
          if (constraint.includes('expense_reasons')) {
            throw Errors.validation(
              'تعارض في أسباب الصرف: القيد الحالي لا يفرّق بين المحلات. شغّل ملف 15_uniqueness_fix.sql.',
            );
          }
          if (constraint.includes('treasur')) {
            throw Errors.validation(
              'تعارض في الخزن: القيد الحالي لا يفرّق بين المحلات. شغّل ملف 15_uniqueness_fix.sql.',
            );
          }
          throw Errors.validation(
            `تعارض في قيد التفرّد: ${constraint || 'غير محدّد'}`,
            error.message,
          );
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

    // ─────────── الإعلانات ───────────

    async branchesOf(actorId, tenantId) {
      const { data, error } = await db.rpc('fn_tenant_branches', {
        p_actor_id: actorId,
        p_tenant_id: tenantId,
      });
      if (error) raisePlatformError(error, 'fn_tenant_branches');

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        branchId: String(r.branch_id),
        branchName: String(r.branch_name),
        branchCode: String(r.branch_code),
      }));
    },

    /**
     * ⚠ نداء واحد بيكتب صف لكل محل مستهدف، كلهم في معاملة
     * واحدة. لو كتبناهم من هنا واحد واحد، أي فشل في النص كان
     * هيسيب نص المحلات شايفة الإعلان والنص التاني لأ.
     */
    async broadcast(input) {
      const { data, error } = await db.rpc('fn_platform_broadcast', {
        p_actor_id: input.actorId,
        p_tenant_id: input.tenantId,
        p_audience: input.audience,
        p_branch_id: input.branchId,
        p_title: input.title,
        p_body: input.body,
        p_severity: input.severity,
        p_is_mandatory: input.isMandatory,
        p_ends_at: input.endsAt ? input.endsAt.toISOString() : null,
      });
      if (error) raisePlatformError(error, 'fn_platform_broadcast');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_platform_broadcast: مفيش نتيجة');

      return { sentCount: Number(row.sent_count ?? 0) };
    },

    async announcements(actorId, limit) {
      const { data, error } = await db.rpc('fn_platform_announcements', {
        p_actor_id: actorId,
        p_limit: limit,
      });
      if (error) raisePlatformError(error, 'fn_platform_announcements');

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        id: String(r.id),
        tenantId: String(r.tenant_id),
        tenantName: String(r.tenant_name),
        title: String(r.title),
        body: String(r.body),
        severity: String(r.severity),
        audience: String(r.audience),
        branchName: r.branch_name === null || r.branch_name === undefined
          ? null
          : String(r.branch_name),
        isMandatory: Boolean(r.is_mandatory),
        startsAt: new Date(String(r.starts_at)),
        endsAt: r.ends_at ? new Date(String(r.ends_at)) : null,
        createdAt: new Date(String(r.created_at)),
        readCount: Number(r.read_count ?? 0),
        targetCount: Number(r.target_count ?? 0),
      }));
    },

    async withdrawAnnouncement(actorId, announcementId) {
      const { error } = await db.rpc('fn_withdraw_announcement', {
        p_actor_id: actorId,
        p_announcement_id: announcementId,
      });
      if (error) raisePlatformError(error, 'fn_withdraw_announcement');
    },
  };
}

/**
 * ترجمة أخطاء دوال المنصّة.
 *
 * ⚠ `MZ403` هنا معناها "مش مشغّل منصّة" — والرسالة العربية جاية
 * من الدالة نفسها، فبنمرّرها زي ما هي.
 */
function raisePlatformError(
  error: { code?: string; message?: string },
  fn: string,
): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';

  switch (error.code) {
    case 'MZ400':
      throw Errors.validation(message);
    case 'MZ403':
      throw Errors.forbidden(`${fn}: ${message}`);
    case 'MZ404':
      throw Errors.notFound('العنصر المطلوب');
    default:
      if (error.code === '23514') throw Errors.validation('قيمة غير مقبولة.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

// ─────────── الخزنة ───────────

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
        provider: string | null;
      }>).map((r) => ({
        treasuryId: r.treasury_id,
        name: r.name,
        type: r.type,
        branchId: r.branch_id,
        isActive: r.is_active,
        // bigint ممكن يرجع كنص من PostgREST — بنوحّده لرقم
        balancePiastres: Number(r.balance_piastres),
        movementCount: Number(r.movement_count),
        provider: r.provider ?? null,
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

    /**
     * الملخّص المالي.
     *
     * ⚠ صف لكل خزنة، والتجميع بيحصل في حالة الاستخدام من نفس
     * الصفوف دي. مفيش استعلام تاني للمجاميع — عشان يستحيل
     * المجموع يخالف الأجزاء.
     */
    async summary(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_treasury_summary', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`fn_treasury_summary: ${error.message}`);

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        treasuryId: String(r.treasury_id),
        name: String(r.name),
        type: String(r.type),
        branchId: r.branch_id === null ? null : String(r.branch_id),
        branchName: r.branch_name === null ? null : String(r.branch_name),
        isActive: Boolean(r.is_active),
        balancePiastres: Number(r.balance_piastres ?? 0),
        movementCount: Number(r.movement_count ?? 0),
        provider: r.provider === null || r.provider === undefined ? null : String(r.provider),
        lastMovementAt: r.last_movement_at ? new Date(String(r.last_movement_at)) : null,
      }));
    },

    async create(input) {
      const { data, error } = await db.rpc('fn_create_treasury', {
        p_actor_id: input.actorId,
        p_branch_id: input.branchId,
        p_name: input.name,
        p_type: input.type,
        p_provider: input.provider,
      });
      if (error) raiseTreasuryError(error, 'fn_create_treasury');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_treasury: مفيش نتيجة');
      return { treasuryId: String(row.treasury_id) };
    },

    async update(input) {
      const { data, error } = await db.rpc('fn_update_treasury', {
        p_treasury_id: input.treasuryId,
        p_actor_id: input.actorId,
        p_name: input.name ?? null,
        p_provider: input.provider ?? null,
        p_is_active: input.isActive ?? null,
      });
      if (error) raiseTreasuryError(error, 'fn_update_treasury');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_update_treasury: مفيش نتيجة');
      return {
        treasuryId: String(row.treasury_id),
        balancePiastres: Number(row.balance_piastres ?? 0),
      };
    },

    /**
     * ⚠ نداء واحد. الحركتين وسجل التحويل بيتكتبوا في معاملة
     * واحدة جوّه القاعدة.
     *
     * لو كتبناهم من هنا، أي فشل في النص هيسيب فلوس طالعة من
     * خزنة وما وصلتش للتانية — وده أسوأ من فشل كامل، لأنه
     * بيبان كأنه نجح.
     */
    async transfer(input) {
      const { data, error } = await db.rpc('fn_transfer_treasury', {
        p_actor_id: input.actorId,
        p_from_id: input.fromTreasuryId,
        p_to_id: input.toTreasuryId,
        p_sent_piastres: input.sentPiastres,
        p_received_piastres: input.receivedPiastres,
        p_note: input.note,
        p_date: input.date,
      });
      if (error) raiseTreasuryError(error, 'fn_transfer_treasury');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_transfer_treasury: مفيش نتيجة');

      return {
        transferId: String(row.transfer_id),
        sentPiastres: Number(row.sent_piastres),
        receivedPiastres: Number(row.received_piastres),
        feePiastres: Number(row.fee_piastres),
        outMovementId: String(row.out_movement_id),
        inMovementId: String(row.in_movement_id),
        fromBalance: Number(row.from_balance),
        toBalance: Number(row.to_balance),
      };
    },

    async listTransfers(tenantId, branchId, from, to, limit) {
      const { data, error } = await db.rpc('fn_treasury_transfers', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
        p_from: from,
        p_to: to,
        p_limit: limit,
      });
      if (error) throw Errors.internal(`fn_treasury_transfers: ${error.message}`);

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        id: String(r.id),
        fromName: String(r.from_name),
        toName: String(r.to_name),
        sentPiastres: Number(r.sent_piastres),
        receivedPiastres: Number(r.received_piastres),
        feePiastres: Number(r.fee_piastres),
        transferDate: String(r.transfer_date).slice(0, 10),
        note: r.note === null || r.note === undefined ? null : String(r.note),
        createdByName:
          r.created_by_name === null || r.created_by_name === undefined
            ? null
            : String(r.created_by_name),
        createdAt: new Date(String(r.created_at)),
      }));
    },
  };
}

// ─────────── حركات الخزنة ───────────

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
          // ⚠⚠ `tenant_id` كان **ناقص** هنا، والعمود `not null`
          // بلا قيمة افتراضية — يعني **كل** حركة خزنة كانت
          // بترفض قبل ما تتكتب، والرد بيطلع 500.
          //
          // ══ إزاي فات علينا شهور؟ ══
          // العقد في `ports.ts` بيطلب `tenantId`، وحالة الاستخدام
          // بتبعته فعلاً. فالأنواع كلها سليمة والبناء بيعدّي —
          // الحقل بيوصل للمستودع وبيتساب على الأرض.
          //
          // ⚠ ودي نفس عيلة الفخ ١٩: **الدالة اللي بتاخد المحل
          // ولا بتستخدمه**. التوقيع بيقول إنها محروسة، فمحدش
          // بيراجعها.
          //
          // ══ وليه البيع كان شغّال؟ ══
          // البيع بيمر على دالة ذرية جوّه القاعدة بتحطّ المحل
          // بنفسها. تسجيل الحركة اليدوي بيكتب في الجدول مباشرةً
          // من هنا. مسارين مختلفين، وواحد بس هو اللي نسي.
          tenant_id: data.tenantId,
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
        // ⚠ 23502 = عمود إلزامي وصل فاضي.
        //
        // الرسالة دي اتضافت عشان الغلطة اللي فوق. من غيرها،
        // العطل بيطلع "حدث خطأ غير متوقّع" — وقعدنا ندوّر ساعات
        // في الصلاحيات والقيود وأسباب الصرف، والسبب كان عمود
        // ناسي اسمه مكتوب في رسالة بوستجرس من أول ثانية.
        //
        // الرسالة للمستخدم تفضل عامة (مفيش أسماء أعمدة تتسرّب)،
        // لكن التفصيلة بتروح للوق.
        if (error?.code === '23502') {
          throw Errors.internal(`movement insert — missing column: ${error.message}`);
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
    is_inventory?: boolean | null;
    branch_id: string | null;
  }): ExpenseReason => ({
    id: r.id,
    name: r.name,
    tenantId: r.tenant_id,
    isAdvance: r.is_advance,
    // ⚠ الافتراضي false: لو العمود لسه ما اتضافش في بيئة قديمة،
    // السبب بيتعامل كمصروف عادي بدل ما الشاشة توقع.
    isInventory: r.is_inventory === true,
    branchId: r.branch_id,
  });

  return {
    async listForBranch(tenantId, branchId) {
      // الأسباب العامة (branch_id = null) متاحة للكل، زائد أسباب
      // الفرع نفسه لو موجود
      //
      // ⚠⚠ `eq('tenant_id')` كان **ناقص** — والمعامل بيتاخد
      // وما بيتستخدمش. النتيجة: القايمة كانت بتجيب أسباب
      // **كل المحلات في النظام**.
      //
      // وده ما بانش كتسريب لأن أسماء الأسباب بذرة موحّدة، فكان
      // شكله "تكرار في العرض". لكن أول ما عميل يكتب سبب باسم
      // مورّد أو شخص، كان هيظهر في قايمة محل تاني.
      //
      // الدرس: **الدالة اللي بتاخد المحل ولا بتستخدمه في
      // الاستعلام أخطر من اللي ما بتاخدوش أصلاً** — التوقيع
      // بيقول إنها محروسة وهي مش محروسة.
      let query = db
        .from('expense_reasons')
        .select('id, tenant_id, name, is_advance, is_inventory, branch_id')
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .eq('is_active', true)
        .order('name');

      query = branchId ? query.or(`branch_id.is.null,branch_id.eq.${branchId}`) : query.is('branch_id', null);

      const { data, error } = await query;
      if (error) throw Errors.internal(`expense reasons: ${error.message}`);
      return (data ?? []).map(map);
    },

    async create(input) {
      const { data, error } = await db
        .from('expense_reasons')
        .insert({
          tenant_id: input.tenantId,
          name: input.name,
          // ⚠ عام على المحل، ومصروف عادي. شوف التعليق على العقد.
          branch_id: null,
          is_advance: false,
          is_inventory: false,
          is_active: true,
        })
        .select('id')
        .single();

      if (error) {
        // 23505 = تعارض تفرّد على (المحل · الفرع · الاسم)
        if (error.code === '23505') throw Errors.validation('السبب ده موجود بالفعل.');
        throw Errors.internal(`expense reason create: ${error.message}`);
      }
      return { id: String((data as { id: string }).id) };
    },

    async findById(id) {
      const { data, error } = await db
        .from('expense_reasons')
        .select('id, tenant_id, name, is_advance, is_inventory, branch_id')
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
//  البضاعة
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
  'id, tenant_id, branch_id, name, product_type, serial_number, serial_unavailable, ' +
  'source, entry_date, ' +
  'price_piastres, quantity_on_hand, quarantined_quantity, reorder_point, ' +
  'customs_cleared, battery_health, storage_capacity, category_id, model_id, color_id, is_active';

function productColumns(includeCost: boolean): string {
  return includeCost ? `${PRODUCT_BASE_COLUMNS}, cost_piastres` : PRODUCT_BASE_COLUMNS;
}

interface RawProduct {
  id: string;
  category_id?: string | null;
  model_id?: string | null;
  color_id?: string | null;
  tenant_id: string;
  branch_id: string;
  name: string;
  product_type: string;
  serial_number: string | null;
  serial_unavailable: boolean | null;
  source: string | null;
  entry_date: string;
  price_piastres: number | string | null;
  quantity_on_hand: number | string;
  quarantined_quantity: number | string | null;
  reorder_point: number | string | null;
  customs_cleared: boolean | null;
  battery_health: number | string | null;
  storage_capacity: string | null;
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
    // ⚠ الافتراضي false مش null. الصفوف القديمة اتعملت قبل ما
    // العمود يوجد، والقيمة الغايبة معناها "ليه سريال عادي".
    serialUnavailable: raw.serial_unavailable === true,
    source: raw.source,
    // عمود date بيرجع نص زي "2026-08-15" — بنسيبه نص.
    // تحويله لـ Date بيحطّ عليه وقت ومنطقة زمنية، وأول ما يترجع
    // بيتزحلق يوم في اتجاه أو التاني.
    entryDate: String(raw.entry_date).slice(0, 10),
    // ⚠ null معناها "المنتج لسه ما اتسعّرش" — مش صفر.
    // لو حوّلناها صفر، Number(null) هيدّي 0 والفرق يضيع.
    pricePiastres: raw.price_piastres === null ? null : Number(raw.price_piastres),
    quantityOnHand: Number(raw.quantity_on_hand),
    quarantinedQuantity: Number(raw.quarantined_quantity ?? 0),
    reorderPoint: Number(raw.reorder_point ?? 0),
    customsCleared: Boolean(raw.customs_cleared),
    batteryHealth: raw.battery_health === null || raw.battery_health === undefined
      ? null : Number(raw.battery_health),
    storageCapacity: raw.storage_capacity ? String(raw.storage_capacity) : null,
    // فاضي = غير مصنّف، والشاشة بتعرضه في درج "غير مصنّف"
    categoryId: raw.category_id ?? null,
    modelId: raw.model_id ?? null,
    colorId: raw.color_id ?? null,
    isActive: raw.is_active,
  };

  // الحقل بيتضاف **بس** لو رجع فعلاً من القاعدة. مفيش
  // `costPiastres: 0` كقيمة افتراضية — ده كان هيبقى كذب مهذّب.
  if (raw.cost_piastres !== undefined && raw.cost_piastres !== null) {
    record.costPiastres = Number(raw.cost_piastres);
  }

  return record;
}

export function createCategoryRepository(db: SupabaseClient): CategoryRepository {
  return {
    /**
     * الشجرة + عدد بضاعة كل درج في **نداء واحد**.
     *
     * ⚠ الدالة في القاعدة هي اللي بتعدّ. لو عدّينا هنا، كانت
     * هتبقى رحلة شبكة لكل درج — سبع أدراج دلوقتي وتلاتين بعد سنة.
     */
    async list(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_product_categories', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`categories list: ${error.message}`);

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        id: String(r.id),
        parentId: (r.parent_id as string | null) ?? null,
        name: String(r.name),
        sortOrder: Number(r.sort_order ?? 0),
        isSystem: Boolean(r.is_system),
        productCount: Number(r.product_count ?? 0),
      }));
    },

    async findById(id, tenantId) {
      // ⚠ المحل جزء من الاستعلام مش فلتر بعده. من غير كده أي حد
      // يعرف معرّف درج يقراه من محل تاني.
      const { data, error } = await db
        .from('product_categories')
        .select('id, parent_id, name, sort_order, is_system')
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`category findById: ${error.message}`);
      if (!data) return null;

      const raw = data as Record<string, unknown>;
      return {
        id: String(raw.id),
        parentId: (raw.parent_id as string | null) ?? null,
        name: String(raw.name),
        sortOrder: Number(raw.sort_order ?? 0),
        isSystem: Boolean(raw.is_system),
        // ⚠ صفر مش العدد الحقيقي — الدالة دي للحراسة مش للعرض.
        // العدّ الحقيقي بييجي من `list` وحدها.
        productCount: 0,
      };
    },

    async create(input) {
      const { data, error } = await db
        .from('product_categories')
        .insert({
          tenant_id: input.tenantId,
          parent_id: input.parentId,
          name: input.name,
          // الجديد بيتحطّ في الآخر. الترتيب بإيد المستخدم بعدين.
          sort_order: 99,
          is_system: false,
        })
        .select('id')
        .single();

      if (error) {
        // 23505 = تعارض تفرّد. والفهرس على (المحل · الأب · الاسم).
        if (error.code === '23505') {
          throw Errors.validation('فيه درج بنفس الاسم في نفس القسم.');
        }
        throw Errors.internal(`category create: ${error.message}`);
      }
      return { id: String((data as { id: string }).id) };
    },

    async rename(id, tenantId, name) {
      const { error } = await db
        .from('product_categories')
        .update({ name })
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) {
        if (error.code === '23505') {
          throw Errors.validation('فيه درج بنفس الاسم في نفس القسم.');
        }
        throw Errors.internal(`category rename: ${error.message}`);
      }
    },

    /**
     * حذف ناعم.
     *
     * ⚠ السجل بيفضل في القاعدة عشان أي منتج قديم لسه بيشاور
     * عليه ما يكسرش. والمنتج بيبان "غير مصنّف" لأن الدرج مش
     * بيترجع في القايمة — من غير ما نلمس صف المنتج أصلاً.
     */
    async softDelete(id, tenantId, actorId, at) {
      const { error } = await db
        .from('product_categories')
        .update({
          deleted_at: at.toISOString(),
          deleted_by: actorId,
          delete_reason: 'حذف من شاشة البضاعة',
        })
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`category delete: ${error.message}`);
    },
  };
}

export function createModelRepository(db: SupabaseClient): ModelRepository {
  const map = (r: Record<string, unknown>): DeviceModel => ({
    id: String(r.id),
    name: String(r.name),
    brand: (r.brand as string | null) ?? null,
    // ⚠ أي قيمة غير معروفة بتترجم null (غير مصنّف) مش بتتمرّر
    // كما هي. القيد في القاعدة بيمنعها، وده حزام تاني.
    family: r.family === 'IPHONE' || r.family === 'ANDROID' ? r.family : null,
    sortOrder: Number(r.sort_order ?? 0),
    deviceCount: Number(r.device_count ?? 0),
    accessoryCount: Number(r.accessory_count ?? 0),
  });

  return {
    /**
     * السجل + العدّين في نداء واحد.
     *
     * ⚠ عمودين عدّ منفصلين مش مجموع واحد: "كام جهاز ١٢ برو ماكس
     * عندي" و"كام صنف إكسسوار ليه" سؤالين مختلفين. الرقم المجمّع
     * كان هيقول "٧" ومش هتعرف سبع أجهزة ولا سبع جرابات.
     */
    async list(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_device_models', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`models list: ${error.message}`);
      return ((data ?? []) as Array<Record<string, unknown>>).map(map);
    },

    async findById(id, tenantId) {
      // ⚠ المحل جزء من الاستعلام مش فلتر بعده
      const { data, error } = await db
        .from('device_models')
        .select('id, name, brand, family, sort_order')
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`model findById: ${error.message}`);
      if (!data) return null;
      // ⚠ العدّ صفر هنا — الدالة دي للحراسة مش للعرض
      return map(data as Record<string, unknown>);
    },

    async create(input) {
      const { data, error } = await db
        .from('device_models')
        .insert({
          tenant_id: input.tenantId,
          name: input.name,
          brand: input.brand,
          family: input.family,
          sort_order: 99,
        })
        .select('id')
        .single();

      if (error) {
        // 23505 = تعارض تفرّد، والفهرس على (المحل · الاسم)
        if (error.code === '23505') throw Errors.validation('الموديل ده مسجّل بالفعل.');
        throw Errors.internal(`model create: ${error.message}`);
      }
      return { id: String((data as { id: string }).id) };
    },

    async update(id, tenantId, patch) {
      const row: Record<string, unknown> = {};
      if (patch.name !== undefined) row.name = patch.name;
      if (patch.brand !== undefined) row.brand = patch.brand;
      if (patch.family !== undefined) row.family = patch.family;
      if (Object.keys(row).length === 0) return;

      const { error } = await db
        .from('device_models')
        .update(row)
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) {
        if (error.code === '23505') throw Errors.validation('الموديل ده مسجّل بالفعل.');
        throw Errors.internal(`model update: ${error.message}`);
      }
    },

    /**
     * حذف ناعم.
     *
     * ⚠ الصف بيفضل عشان البضاعة القديمة اللي بتشاور عليه ما
     * تكسرش. والمنتج بيبان "بلا موديل" لأن الموديل مش بيترجع
     * في القايمة — من غير ما نلمس صف المنتج.
     */
    async softDelete(id, tenantId, actorId, at) {
      const { error } = await db
        .from('device_models')
        .update({
          deleted_at: at.toISOString(),
          deleted_by: actorId,
          delete_reason: 'حذف من شاشة البضاعة',
        })
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`model delete: ${error.message}`);
    },
  };
}

export function createColorRepository(db: SupabaseClient): ColorRepository {
  const map = (r: Record<string, unknown>): ProductColor => ({
    id: String(r.id),
    name: String(r.name),
    hex: (r.hex as string | null) ?? null,
    sortOrder: Number(r.sort_order ?? 0),
    isSystem: Boolean(r.is_system),
    productCount: Number(r.product_count ?? 0),
  });

  return {
    async list(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_product_colors', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`colors list: ${error.message}`);
      return ((data ?? []) as Array<Record<string, unknown>>).map(map);
    },

    async findById(id, tenantId) {
      // ⚠ المحل جزء من الاستعلام مش فلتر بعده
      const { data, error } = await db
        .from('product_colors')
        .select('id, name, hex, sort_order, is_system')
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`color findById: ${error.message}`);
      if (!data) return null;
      // ⚠ العدّ صفر — الدالة دي للحراسة مش للعرض
      return map(data as Record<string, unknown>);
    },

    async create(input) {
      const { data, error } = await db
        .from('product_colors')
        .insert({
          tenant_id: input.tenantId,
          name: input.name,
          hex: input.hex,
          sort_order: 99,
          is_system: false,
        })
        .select('id')
        .single();

      if (error) {
        if (error.code === '23505') throw Errors.validation('اللون ده مسجّل بالفعل.');
        throw Errors.internal(`color create: ${error.message}`);
      }
      return { id: String((data as { id: string }).id) };
    },

    async update(id, tenantId, patch) {
      const row: Record<string, unknown> = {};
      if (patch.name !== undefined) row.name = patch.name;
      if (patch.hex !== undefined) row.hex = patch.hex;
      if (Object.keys(row).length === 0) return;

      const { error } = await db
        .from('product_colors')
        .update(row)
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) {
        if (error.code === '23505') throw Errors.validation('اللون ده مسجّل بالفعل.');
        throw Errors.internal(`color update: ${error.message}`);
      }
    },

    async softDelete(id, tenantId, actorId, at) {
      const { error } = await db
        .from('product_colors')
        .update({
          deleted_at: at.toISOString(),
          deleted_by: actorId,
          delete_reason: 'حذف من شاشة البضاعة',
        })
        .eq('id', id)
        .eq('tenant_id', tenantId)
        .is('deleted_at', null);

      if (error) throw Errors.internal(`color delete: ${error.message}`);
    },
  };
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

    /**
     * ⚠ نداء واحد لدالة قاعدة البيانات، مش إدخال مباشر.
     *
     * السبب إن الإضافة بقت ممكن تحرّك فلوس (تكلفة مدفوعة) أو
     * تزوّد دين مورّد. والتلاتة لازم يتكتبوا في معاملة واحدة.
     *
     * لو كتبنا المنتج هنا وناديّنا الفلوس بعده، بينهم رحلة
     * شبكة — وأي فشل بيسيب جهاز بلا دين أو دين بلا جهاز.
     * والاتنين بيبانوا كأنهم نجاح.
     *
     * نفس نمط `fn_transfer_treasury` بالظبط.
     */
    async create(data) {
      const { data: settled, error: settleError } = await db.rpc(
        'fn_create_product_settled',
        {
          p_product: {
            tenant_id: data.tenantId,
            branch_id: data.branchId,
            name: data.name,
            product_type: data.productType,
            serial_number: data.serialNumber,
            serial_unavailable: data.serialUnavailable,
            source: data.source,
            supplier_id: data.supplierId,
            entry_date: data.entryDate ?? null,
            price_piastres: data.pricePiastres,
            cost_piastres: data.costPiastres,
            quantity_on_hand: data.quantityOnHand,
            customs_cleared: data.customsCleared,
            battery_health: data.batteryHealth,
            storage_capacity: data.storageCapacity,
            category_id: data.categoryId,
            model_id: data.modelId,
            color_id: data.colorId,
          },
          p_actor_id: data.createdById,
          p_settle: data.settle ?? 'NONE',
          p_treasury_id: data.treasuryId ?? null,
        },
      );

      if (settleError) {
        // ⚠ نفس ترجمة أخطاء القاعدة المستخدمة في باقي المشروع:
        // رسالة عربية للمستخدم، والتفاصيل للّوق بس.
        const detail = settleError.message ?? '';
        if (detail.includes('اختر')) throw Errors.validation(detail);
        if (settleError.code === '23505') {
          throw Errors.validation('الرقم التسلسلي ده مسجّل بالفعل.');
        }
        throw Errors.internal(`fn_create_product_settled: ${detail}`);
      }

      const settledRow = (settled as Array<Record<string, unknown>> | null)?.[0];
      if (!settledRow) throw Errors.internal('fn_create_product_settled: مفيش نتيجة');
      return { id: String(settledRow.product_id) };
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
      if (data.serialUnavailable !== undefined) {
        patch.serial_unavailable = data.serialUnavailable;
      }
      if (data.entryDate !== undefined) patch.entry_date = data.entryDate;
      // ⚠ محكوم بصلاحية `inventory.reorder_point` في حالة الاستخدام،
      // مش هنا. المستودع بينفّذ، والقرار فوق.
      if (data.reorderPoint !== undefined) patch.reorder_point = data.reorderPoint;
      if (data.customsCleared !== undefined) patch.customs_cleared = data.customsCleared;
      if (data.batteryHealth !== undefined) patch.battery_health = data.batteryHealth;
      if (data.storageCapacity !== undefined) patch.storage_capacity = data.storageCapacity;
      // ⚠ `undefined` = ما تلمسش الدرج. `null` = شيله (غير مصنّف).
      // من غير التفريق ده مستحيل ترجّع منتج بلا درج بعد ما اتحطّ فيه.
      if (data.categoryId !== undefined) patch.category_id = data.categoryId;
      if (data.modelId !== undefined) patch.model_id = data.modelId;
      if (data.colorId !== undefined) patch.color_id = data.colorId;

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
  'treasury_id, created_at, exit_date, warranty_days';

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
  warranty_days: number | string | null;
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
    // ⚠ null لازم تفضل null. لو حوّلناها لصفر، "بلا ضمان"
    // هتبقى "ضمان صفر يوم" — والاتنين مختلفين في السجل.
    warrantyDays: raw.warranty_days === null ? null : Number(raw.warranty_days),
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
/**
 * ترجمة أخطاء دوال الخزنة.
 *
 * ⚠ الرسائل مكتوبة عربي جوّه الدوال وبتمرّ زي ما هي — هي
 * مكتوبة أصلاً عشان المستخدم يقراها: "رصيد النقدي 196.50 —
 * مش كفاية للتحويل" أنفع بكتير من "فشلت العملية".
 */
function raiseTreasuryError(
  error: { code?: string; message?: string },
  fn: string,
): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';

  switch (error.code) {
    case 'MZ400':
    case 'MZ409':
      throw Errors.validation(message);
    case 'MZ403':
      throw Errors.forbidden(`${fn}: ${message}`);
    case 'MZ404':
      throw Errors.notFound('العنصر المطلوب');
    default:
      // 23505 = تكرار. الفهرس الفريد على (المحل، الفرع، الاسم)
      if (error.code === '23505') {
        throw Errors.validation('فيه خزنة بنفس الاسم في الفرع ده.');
      }
      // 23514 = قيد رفض السجل. أشهرهم هنا: العمولة مش مساوية الفرق
      if (error.code === '23514') {
        throw Errors.validation('القيم غير متسقة — راجع المبالغ.');
      }
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

function raiseSaleError(error: { code?: string; message?: string }): never {
  const message = error.message?.trim() || 'تعذّر إتمام البيع.';

  switch (error.code) {
    case 'MZ409':
    case 'MZ400':
      throw Errors.validation(message);

    // ══ ⚠ MZ403 هنا **مش** فشل صلاحية، وده مقصود ══
    //
    // الدالة بترمي الكود ده في حالتين بس: الخزنة من فرع تاني،
    // أو منتج في السلة من فرع تاني. الاتنين **غلطة على الكاونتر**
    // مش محاولة تجاوز.
    //
    // والحراسة الحقيقية اتعملت قبل ما نوصل هنا: `createSale`
    // بتقفل غير صاحب المحل على خزنة فرعه. اللي بيوصل للكود ده
    // هو صاحب المحل اللي فروعه كلها بتاعته — بيخلط بينهم بس.
    //
    // ══ وليه اتغيّر من forbidden ══
    // `Errors.forbidden` رسالته للمستخدم **ثابتة**: "لا تملك
    // صلاحية تنفيذ هذا الإجراء." والرسالة الحقيقية — «المنتج
    // "س" مش تابع لفرعك» — كانت بتروح للوق وتختفي.
    //
    // فصاحب المحل كان بيقرا إنه مش مصرّح له يبيع في محله هو،
    // والسبب الفعلي مكتوب وموجود وما بيوصلش. الرسالة اللي
    // بتشاور على المكان الغلط أوحش من مفيش رسالة.
    case 'MZ403':
      throw Errors.validation(message);

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
        p_warranty_days: input.warrantyDays,
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
    /**
     * ⚠ دالة مستقلة في القاعدة، مش تعديل مباشر على الجدول.
     * الحاجز اللي بيمنع محل يكتب على فاتورة محل تاني جوّاها.
     */
    async setNote(id, actorId, note) {
      const { error } = await db.rpc('fn_set_sale_note', {
        p_sale_id: id,
        p_actor_id: actorId,
        p_note: note,
      });
      if (error) throw Errors.internal(`fn_set_sale_note: ${error.message}`);
    },

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


// ═══════════════ المرتجعات ورفّ المراجعة ═══════════════

/**
 * ترجمة أخطاء دوال المرتجع.
 *
 * ⚠ الرسايل بتيجي من قاعدة البيانات **عربية جاهزة** (MZ400).
 * بنعدّيها زي ما هي بدل ما نكتب نسخة تانية هنا وتختلف عنها بعد
 * شهرين — وساعتها المستخدم يشوف رسالتين مختلفتين لنفس السبب.
 */
function raiseReturnError(error: { code?: string; message?: string }, fn: string): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';

  switch (error.code) {
    case 'MZ400':
      throw Errors.validation(message);
    case 'MZ403':
      throw Errors.forbidden(`return scope: ${message}`);
    case 'MZ404':
      throw Errors.notFound('العنصر المطلوب');
    default:
      // 23514 = قيد في القاعدة رفض السجل (رفّ مراجعة بالسالب مثلاً)
      if (error.code === '23514') throw Errors.validation('الكمية غير صالحة.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

export function createReturnRepository(db: SupabaseClient): ReturnRepository {
  return {
    async returnableLines(saleId) {
      const { data, error } = await db.rpc('fn_sale_returnable', { p_sale_id: saleId });
      if (error) raiseReturnError(error, 'fn_sale_returnable');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        saleItemId: String(row.sale_item_id),
        productId: String(row.product_id),
        productName: String(row.product_name),
        productType: String(row.product_type),
        serialNumber: row.serial_number ? String(row.serial_number) : null,
        quantitySold: Number(row.quantity_sold),
        quantityReturned: Number(row.quantity_returned),
        quantityRemaining: Number(row.quantity_remaining),
        unitPricePiastres: Number(row.unit_price_piastres),
      }));
    },

    /**
     * نداء واحد بيعمل الأربع خطوات.
     *
     * مفيش هنا "رجّع البضاعة" وبعدين "طلّع الفلوس" — دي كانت
     * هتبقى رحلتين، ولو التانية فشلت تبقى البضاعة رجعت والزبون
     * ماخدش فلوسه.
     */
    async create(input) {
      const { data, error } = await db.rpc('fn_create_return', {
        p_sale_id: input.saleId,
        p_actor_id: input.actorId,
        p_treasury_id: input.treasuryId,
        p_items: input.items.map((line) => ({
          sale_item_id: line.saleItemId,
          quantity: line.quantity,
          unit_refund_piastres: line.unitRefundPiastres,
        })),
        p_reason: input.reason,
        p_return_date: input.returnDate,
        p_override_warranty: input.overrideWarranty,
      });

      if (error) raiseReturnError(error, 'fn_create_return');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_return: مفيش نتيجة');

      return {
        returnId: String(row.return_id),
        refundedPiastres: Number(row.refunded_piastres),
        feePiastres: Number(row.fee_piastres),
        itemCount: Number(row.item_count),
        movementId: String(row.movement_id),
        // ⚠ من رد القاعدة مش من الطلب — النتيجة مش النيّة
        warrantyOverridden: Boolean(row.warranty_overridden),
      };
    },

    async quarantineList(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_quarantine_list', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) raiseReturnError(error, 'fn_quarantine_list');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        productId: String(row.product_id),
        productName: String(row.product_name),
        productType: String(row.product_type),
        serialNumber: row.serial_number ? String(row.serial_number) : null,
        branchId: String(row.branch_id),
        quarantinedQuantity: Number(row.quarantined_quantity),
        lastReturnDate: row.last_return_date ? String(row.last_return_date) : null,
        lastReason: row.last_reason ? String(row.last_reason) : null,
      }));
    },

    async review(productId, actorId, quantity, decision) {
      const { data, error } = await db.rpc('fn_review_quarantine', {
        p_product_id: productId,
        p_actor_id: actorId,
        p_quantity: quantity,
        p_decision: decision,
      });
      if (error) raiseReturnError(error, 'fn_review_quarantine');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_review_quarantine: مفيش نتيجة');

      return {
        productName: String(row.product_name),
        movedQuantity: Number(row.moved_quantity),
        remainingHeld: Number(row.remaining_held),
        nowOnHand: Number(row.now_on_hand),
      };
    },
  };
}


// ═══════════════ التقارير ═══════════════

/**
 * ⚠ الدالتين دول **قراءة بس**. مفيش ولا سطر بيتكتب.
 *
 * وحجب التكلفة بيحصل في قاعدة البيانات: لو `includeCost` false،
 * أعمدة التكلفة والربح بترجع فاضية ومش بتتحسب أصلاً. يعني مفيش
 * حاجة تتخبّى في الواجهة — الرقم ما وصلش الخادم أصلاً.
 */
export function createReportRepository(db: SupabaseClient): ReportRepository {
  return {
    async incomeStatement(tenantId, branchId, from, to, includeCost) {
      const { data, error } = await db.rpc('fn_income_statement', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
        p_from: from,
        p_to: to,
        p_include_cost: includeCost,
      });
      if (error) throw Errors.internal(`fn_income_statement: ${error.message}`);

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      // فترة بلا حركة بترجّع صف بأصفار، مش صف ناقص — بس نحرس برضه
      if (!row) {
        return {
          salesCount: 0,
          salesPiastres: 0,
          refundsCount: 0,
          refundsPiastres: 0,
          refundFeesPiastres: 0,
          netSalesPiastres: 0,
          cogsPiastres: includeCost ? 0 : null,
          returnedCogsPiastres: includeCost ? 0 : null,
          grossProfitPiastres: includeCost ? 0 : null,
          netProfitPiastres: includeCost ? 0 : null,
          expensesPiastres: 0,
          advancesPiastres: 0,
          inventoryPurchasesPiastres: 0,
          transferFeesPiastres: 0,
        };
      }

      const maybe = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

      return {
        salesCount: Number(row.sales_count),
        salesPiastres: Number(row.sales_piastres),
        refundsCount: Number(row.refunds_count),
        refundsPiastres: Number(row.refunds_piastres),
        refundFeesPiastres: Number(row.refund_fees_piastres),
        netSalesPiastres: Number(row.net_sales_piastres),
        cogsPiastres: maybe(row.cogs_piastres),
        returnedCogsPiastres: maybe(row.returned_cogs_piastres),
        grossProfitPiastres: maybe(row.gross_profit_piastres),
        netProfitPiastres: maybe(row.net_profit_piastres),
        expensesPiastres: Number(row.expenses_piastres),
        advancesPiastres: Number(row.advances_piastres),
        inventoryPurchasesPiastres: Number(row.inventory_purchases_piastres ?? 0),
        // ⚠ `?? 0` هنا حارس مقصود مش كسل: لو الدالة في القاعدة
        // اترجّعت لنسخة أقدم يوم ما، الشاشة بتقول صفر بدل ما
        // توقع. بس ده بيخفي الغلط — فالفحص في آخر ملف SQL
        // بيتأكد إن العمود موجود فعلاً.
        transferFeesPiastres: Number(row.transfer_fees_piastres ?? 0),
      };
    },

    async expenseBreakdown(tenantId, branchId, from, to) {
      const { data, error } = await db.rpc('fn_expense_breakdown', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
        p_from: from,
        p_to: to,
      });
      if (error) throw Errors.internal(`fn_expense_breakdown: ${error.message}`);

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        reasonName: String(row.reason_name),
        movementCount: Number(row.movement_count),
        totalPiastres: Number(row.total_piastres),
      }));
    },
  };
}


// ═══════════════ التنبيهات ═══════════════

/**
 * ⚠ مفيش جدول تنبيهات. الدالة بتحسب الحالة الحالية كل مرة.
 *
 * لو خزّنّاها، تنبيه "مخزون منخفض" اتكتب الساعة ٣ هيفضل معلّق
 * بعد ما توّرد الساعة ٤. الشاشة تقول حاجة والمخزن يقول حاجة.
 */
export function createAlertRepository(db: SupabaseClient): AlertRepository {
  return {
    async list(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_alerts', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) throw Errors.internal(`fn_alerts: ${error.message}`);

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        alertType: String(row.alert_type) as AlertRow['alertType'],
        severity: String(row.severity) as AlertRow['severity'],
        entityId: String(row.entity_id),
        title: String(row.title),
        detail: String(row.detail),
        metric: Number(row.metric),
      }));
    },
  };
}


// ═══════════════ التحويل بين الفروع ═══════════════

function raiseTransferError(error: { code?: string; message?: string }, fn: string): never {
  const message = error.message?.trim() || 'تعذّر إتمام التحويل.';
  switch (error.code) {
    case 'MZ400': throw Errors.validation(message);
    case 'MZ403': throw Errors.forbidden(`transfer scope: ${message}`);
    case 'MZ404': throw Errors.notFound('العنصر المطلوب');
    default:
      if (error.code === '23514') throw Errors.validation('الكمية غير صالحة.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

export function createTransferRepository(db: SupabaseClient): TransferRepository {
  return {
    async create(input) {
      const { data, error } = await db.rpc('fn_create_transfer', {
        p_product_id: input.productId,
        p_actor_id: input.actorId,
        p_to_branch_id: input.toBranchId,
        p_quantity: input.quantity,
        p_note: input.note,
      });
      if (error) raiseTransferError(error, 'fn_create_transfer');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_create_transfer: مفيش نتيجة');

      return {
        transferId: String(row.transfer_id),
        productName: String(row.product_name),
        moved: Number(row.moved),
      };
    },

    async resolve(transferId, actorId, decision) {
      const { data, error } = await db.rpc('fn_resolve_transfer', {
        p_transfer_id: transferId,
        p_actor_id: actorId,
        p_decision: decision,
      });
      if (error) raiseTransferError(error, 'fn_resolve_transfer');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_resolve_transfer: مفيش نتيجة');

      return {
        productName: String(row.product_name),
        moved: Number(row.moved),
        finalStatus: String(row.final_status),
      };
    },

    async listPending(tenantId, branchId) {
      const { data, error } = await db.rpc('fn_pending_transfers', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
      });
      if (error) raiseTransferError(error, 'fn_pending_transfers');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        id: String(row.id),
        direction: String(row.direction) as 'IN' | 'OUT' | 'BOTH',
        productName: String(row.product_name),
        productType: String(row.product_type),
        serialNumber: row.serial_number ? String(row.serial_number) : null,
        quantity: Number(row.quantity),
        fromBranch: String(row.from_branch),
        toBranch: String(row.to_branch),
        note: row.note ? String(row.note) : null,
        createdAt: String(row.created_at),
        createdBy: String(row.created_by),
      }));
    },
  };
}


// ═══════════════ الموردين والديون ═══════════════

function raiseSupplierError(error: { code?: string; message?: string }, fn: string): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';
  switch (error.code) {
    case 'MZ400': throw Errors.validation(message);
    case 'MZ403': throw Errors.forbidden('supplier scope');
    case 'MZ404': throw Errors.notFound('المورّد');
    case 'MZ500': throw Errors.internal(message);
    default:
      if (error.code === '23505') throw Errors.validation('اسم المورّد ده مسجّل بالفعل.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

/**
 * مستودع حساب المحلات.
 *
 * ⚠ العمليتين اللي بتغيّروا أرقام (`consign` و`recordPayment`)
 * بيتنادوا كدوال في القاعدة، مش إدخال مباشر. كل واحدة بتكتب
 * في جدولين أو تلاتة، وأي فصل بينهم بيسيب النظام في حالة
 * بتبان كأنها نجاح.
 */
export function createShopRepository(db: SupabaseClient): ShopRepository {
  return {
    async listBalances(tenantId) {
      const { data, error } = await db.rpc('fn_shop_balances', { p_tenant_id: tenantId });
      if (error) throw Errors.internal(`shop balances: ${error.message}`);

      return ((data ?? []) as Array<Record<string, unknown>>).map((r) => ({
        shopId: String(r.shop_id),
        name: String(r.name),
        contactName: (r.contact_name as string | null) ?? null,
        phone: (r.phone as string | null) ?? null,
        totalOut: Number(r.total_out ?? 0),
        totalPaid: Number(r.total_paid ?? 0),
        balancePiastres: Number(r.balance_piastres ?? 0),
        lastMovement: (r.last_movement as string | null) ?? null,
      }));
    },

    async create(data) {
      const { data: row, error } = await db
        .from('shop_accounts')
        .insert({
          tenant_id: data.tenantId,
          branch_id: data.branchId,
          name: data.name,
          contact_name: data.contactName,
          phone: data.phone,
          notes: data.notes,
          created_by_id: data.createdById,
        })
        .select('id')
        .single();

      if (error || !row) {
        // 23505 = تكرار الاسم جوّه نفس المحل
        if (error?.code === '23505') throw Errors.validation('فيه حساب بالاسم ده بالفعل.');
        throw Errors.internal(`shop insert: ${error?.message}`);
      }
      return { id: row.id as string };
    },

    async update(id, data) {
      const row: Record<string, unknown> = {};
      if (data.name !== undefined) row.name = data.name;
      if (data.contactName !== undefined) row.contact_name = data.contactName;
      if (data.phone !== undefined) row.phone = data.phone;
      if (Object.keys(row).length === 0) return;

      const { error } = await db
        .from('shop_accounts')
        .update(row)
        .eq('id', id)
        .is('deleted_at', null);

      if (error) {
        if (error.code === '23505') throw Errors.validation('فيه حساب بالاسم ده بالفعل.');
        throw Errors.internal(`shop update: ${error.message}`);
      }
    },

    async findById(id) {
      const { data, error } = await db
        .from('shop_accounts')
        .select('id, tenant_id, name')
        .eq('id', id)
        .is('deleted_at', null)
        .maybeSingle();

      if (error) throw Errors.internal(`shop findById: ${error.message}`);
      if (!data) return null;
      return {
        id: String(data.id),
        tenantId: String(data.tenant_id),
        name: String(data.name),
      };
    },

    async consign(input) {
      const { data, error } = await db.rpc('fn_shop_consign', {
        p_shop_id: input.shopId,
        p_actor_id: input.actorId,
        // ⚠ الأسماء بصيغة القاعدة (snake_case) لأن الدالة
        // بتقرا الـjsonb بالمفتاح مباشرةً.
        p_items: input.items.map((line) => ({
          product_id: line.productId,
          quantity: line.quantity,
          unit_price: line.unitPricePiastres,
        })),
        p_note: input.note,
        p_date: input.date,
      });
      if (error) raiseShopError(error, 'fn_shop_consign');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_shop_consign: مفيش نتيجة');
      return {
        movementId: String(row.movement_id),
        totalPiastres: Number(row.total_piastres ?? 0),
        newBalance: Number(row.new_balance ?? 0),
      };
    },

    async recordPayment(input) {
      const { data, error } = await db.rpc('fn_shop_payment', {
        p_shop_id: input.shopId,
        p_actor_id: input.actorId,
        p_treasury_id: input.treasuryId,
        p_amount: input.amountPiastres,
        p_note: input.note,
        p_date: input.date,
      });
      if (error) raiseShopError(error, 'fn_shop_payment');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_shop_payment: مفيش نتيجة');
      return {
        movementId: String(row.movement_id),
        treasuryMovementId: String(row.treasury_movement_id),
        newBalance: Number(row.new_balance ?? 0),
      };
    },
  };
}

/**
 * ترجمة أخطاء دوال المحلات.
 *
 * ⚠ الرسايل العربية اللي الدالة بترميها بتوصل للمستخدم زي ما
 * هي (الكمية المتاحة، المحل غير موجود). أي حاجة تانية بتتحوّل
 * لخطأ داخلي — تسريب نص خطأ القاعدة بيدّي خريطة للنظام.
 */
function raiseShopError(error: { message?: string; code?: string }, fn: string): never {
  const detail = error.message ?? '';
  if (detail.includes('غير موجود') || detail.includes('الكمية') || detail.includes('اختر')) {
    throw Errors.validation(detail);
  }
  throw Errors.internal(`${fn}: ${detail}`);
}

export function createSupplierRepository(db: SupabaseClient): SupplierRepository {
  return {
    /**
     * الأرصدة + توزيعها على الفروع.
     *
     * ══ ⚠ نداءين مش واحد، وده مقصود ══
     * `fn_supplier_balances` بتتنادى من جوّه دالة الدين ودالة
     * السداد عشان ترجّع الرصيد الجديد. تعديل شكل ردّها كان
     * هيكسر التلاتة مع بعض.
     *
     * فسبناها زي ما هي، والتوزيع في دالة لوحدها، والدمج هنا.
     * رحلة شبكة زيادة أرخص من كسر تلات دوال شغّالة.
     *
     * ⚠ ومدير الفرع بياخد أرقام **فرعه** في الأعمدة الكلية،
     * مش إجمالي المحل. عرض إجمالي المحل عليه كان هيوريه رقم
     * هو مش مسؤول عنه ولا بيقدر يسدّده.
     */
    async listBalances(tenantId, branchId) {
      const [balances, breakdown] = await Promise.all([
        db.rpc('fn_supplier_balances', { p_tenant_id: tenantId }),
        db.rpc('fn_supplier_branch_balances', {
          p_tenant_id: tenantId,
          p_branch_id: branchId,
        }),
      ]);

      if (balances.error) raiseSupplierError(balances.error, 'fn_supplier_balances');
      if (breakdown.error) raiseSupplierError(breakdown.error, 'fn_supplier_branch_balances');

      // ⚠ التوزيع بيتلمّ بالمورّد قبل الدمج. اللفّ جوّه اللفّ
      // كان هيبقى عدد الموردين × عدد الصفوف — وده بيبان بطيء
      // بعد سنة من الحركات مش دلوقتي.
      const bySupplier = new Map<string, SupplierBranchBalance[]>();
      for (const raw of (breakdown.data as Array<Record<string, unknown>> | null) ?? []) {
        const key = String(raw.supplier_id);
        const list = bySupplier.get(key) ?? [];
        list.push({
          branchId: raw.branch_id ? String(raw.branch_id) : null,
          branchName: raw.branch_name ? String(raw.branch_name) : null,
          debtPiastres: Number(raw.debt_piastres),
          paidPiastres: Number(raw.paid_piastres),
          balancePiastres: Number(raw.balance_piastres),
          movementCount: Number(raw.movement_count),
          lastMovement: raw.last_movement ? String(raw.last_movement).slice(0, 10) : null,
        });
        bySupplier.set(key, list);
      }

      return ((balances.data as Array<Record<string, unknown>> | null) ?? []).map((row) => {
        const id = String(row.supplier_id);
        const branches = bySupplier.get(id) ?? [];

        // ⚠ صاحب المحل بياخد الإجمالي من الدالة القديمة.
        // مدير الفرع بياخده **مجموع فرعه** — والدالة القديمة
        // مالهاش فلتر فرع أصلاً، فالجمع هنا هو الطريق الوحيد.
        const scoped = branchId !== null;
        const sum = (pick: (b: SupplierBranchBalance) => number): number =>
          branches.reduce((total, b) => total + pick(b), 0);

        return {
          supplierId: id,
          name: String(row.name),
          phone: row.phone ? String(row.phone) : null,
          notes: row.notes ? String(row.notes) : null,
          isActive: Boolean(row.is_active),
          productCount: Number(row.product_count),
          debtPiastres: scoped ? sum((b) => b.debtPiastres) : Number(row.debt_piastres),
          paidPiastres: scoped ? sum((b) => b.paidPiastres) : Number(row.paid_piastres),
          balancePiastres: scoped
            ? sum((b) => b.balancePiastres)
            : Number(row.balance_piastres),
          lastMovement: row.last_movement ? String(row.last_movement).slice(0, 10) : null,
          branches,
        };
      });
    },

    /**
     * دفتر المورّد.
     *
     * ⚠ كل سطر بيجاوب على أربع أسئلة: إمتى · على إيه · مين · بكام.
     * والاسم بيتقرا من سجل المنتج مش من الملاحظة، عشان يفضل صح
     * لو الجهاز اتغيّر اسمه بعدين.
     */
    async listMovements(supplierId, tenantId, branchId, limit = 200) {
      const { data, error } = await db.rpc('fn_supplier_movements', {
        p_supplier_id: supplierId,
        // ⚠ فلتر الفرع في الاستعلام مش بعده — مدير الفرع
        // ما بيشوفش حركات فرع تاني أصلاً، مش بيشوفها وتتشال.
        p_branch_id: branchId,
        // ⚠ المحل بيتبعت للدالة نفسها مش بيتفلتر هنا. لو فلترنا
        // بعد الرد، الصفوف كانت هتسافر على الشبكة الأول —
        // والتسريب بيحصل قبل الفلترة مش بعدها.
        p_tenant_id: tenantId,
        p_limit: limit,
      });
      if (error) raiseSupplierError(error, 'fn_supplier_movements');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        id: String(row.id),
        direction: String(row.direction) === 'DEBT' ? ('DEBT' as const) : ('PAYMENT' as const),
        isDiscount: Boolean(row.is_discount),
        amountPiastres: Number(row.amount_piastres),
        note: row.note ? String(row.note) : null,
        occurredAt: String(row.occurred_at).slice(0, 10),
        branchId: row.branch_id ? String(row.branch_id) : null,
        branchName: row.branch_name ? String(row.branch_name) : null,
        productId: row.product_id ? String(row.product_id) : null,
        itemName: row.item_name ? String(row.item_name) : null,
        entryDate: row.entry_date ? String(row.entry_date).slice(0, 10) : null,
        serialNumber: row.serial_number ? String(row.serial_number) : null,
        actorName: String(row.actor_name ?? '—'),
        actorRole: String(row.actor_role ?? '—'),
        treasuryName: row.treasury_name ? String(row.treasury_name) : null,
      }));
    },

    async create(data) {
      const { data: rows, error } = await db
        .from('suppliers')
        .insert({
          tenant_id: data.tenantId,
          name: data.name,
          phone: data.phone,
          notes: data.notes,
          created_by_id: data.createdById,
        })
        .select('id');

      if (error) raiseSupplierError(error, 'suppliers.insert');
      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('suppliers.insert: مفيش نتيجة');
      return { id: String(row.id) };
    },

    async update(id, data) {
      const patch: Record<string, unknown> = {};
      if (data.name !== undefined) patch.name = data.name;
      if (data.phone !== undefined) patch.phone = data.phone;
      if (data.notes !== undefined) patch.notes = data.notes;
      if (data.isActive !== undefined) patch.is_active = data.isActive;

      const { error } = await db
        .from('suppliers').update(patch).eq('id', id).is('deleted_at', null);
      if (error) raiseSupplierError(error, 'suppliers.update');
    },

    async findById(id) {
      const { data, error } = await db
        .from('suppliers').select('id, tenant_id, name')
        .eq('id', id).is('deleted_at', null).maybeSingle();

      if (error) raiseSupplierError(error, 'suppliers.findById');
      if (!data) return null;

      const row = data as Record<string, unknown>;
      return { id: String(row.id), tenantId: String(row.tenant_id), name: String(row.name) };
    },

    /**
     * ⚠ نفس نمط الدين بالظبط، والفرق الوحيد إن الدالة دي
     * **ما بتلمسش الخزنة**. الحساب كله جوّه القاعدة.
     */
    async recordDiscount(input) {
      const { data, error } = await db.rpc('fn_supplier_discount', {
        p_supplier_id: input.supplierId,
        p_actor_id: input.actorId,
        p_amount: input.amountPiastres,
        p_note: input.note,
        p_date: input.date,
        // ⚠ بيتجاهل جوّه القاعدة لغير صاحب المحل — الفرع
        // بيتاخد من جلسة المنفّذ هناك، مش من السطر ده.
        p_branch_id: input.branchId,
      });
      if (error) raiseSupplierError(error, 'fn_supplier_discount');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_supplier_discount: مفيش نتيجة');
      return { movementId: String(row.movement_id), newBalance: Number(row.new_balance) };
    },

    async recordDebt(input) {
      const { data, error } = await db.rpc('fn_supplier_debt', {
        p_supplier_id: input.supplierId,
        p_actor_id: input.actorId,
        p_amount: input.amountPiastres,
        p_note: input.note,
        p_date: input.date,
        // ⚠ بيتجاهل جوّه القاعدة لغير صاحب المحل — الفرع
        // بيتاخد من جلسة المنفّذ هناك، مش من السطر ده.
        p_branch_id: input.branchId,
      });
      if (error) raiseSupplierError(error, 'fn_supplier_debt');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_supplier_debt: مفيش نتيجة');
      return { movementId: String(row.movement_id), newBalance: Number(row.new_balance) };
    },

    async recordPayment(input) {
      const { data, error } = await db.rpc('fn_supplier_payment', {
        p_supplier_id: input.supplierId,
        p_actor_id: input.actorId,
        p_treasury_id: input.treasuryId,
        p_amount: input.amountPiastres,
        p_note: input.note,
        p_date: input.date,
      });
      if (error) raiseSupplierError(error, 'fn_supplier_payment');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_supplier_payment: مفيش نتيجة');
      return {
        movementId: String(row.movement_id),
        treasuryMovementId: String(row.treasury_movement_id),
        newBalance: Number(row.new_balance),
      };
    },
  };
}


// ═══════════════ الصيانة ═══════════════

function raiseMaintError(error: { code?: string; message?: string }, fn: string): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';
  switch (error.code) {
    case 'MZ400': throw Errors.validation(message);
    case 'MZ403': throw Errors.forbidden(message);
    case 'MZ404': throw Errors.notFound('العنصر المطلوب');
    default:
      if (error.code === '23505') throw Errors.validation('الاسم ده مسجّل بالفعل.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

export function createMaintenanceRepository(db: SupabaseClient): MaintenanceRepository {
  return {
    // ─── الورش ───
    async listShops(tenantId) {
      const { data, error } = await db
        .from('repair_shops')
        .select('id, name, phone, notes, is_active')
        .eq('tenant_id', tenantId)
        .is('deleted_at', null)
        .order('name');

      if (error) raiseMaintError(error, 'repair_shops.list');
      return ((data as Array<Record<string, unknown>> | null) ?? []).map((r) => ({
        id: String(r.id),
        name: String(r.name),
        phone: r.phone ? String(r.phone) : null,
        notes: r.notes ? String(r.notes) : null,
        isActive: Boolean(r.is_active),
      }));
    },

    async createShop(data) {
      const { data: rows, error } = await db
        .from('repair_shops')
        .insert({
          tenant_id: data.tenantId,
          name: data.name,
          phone: data.phone,
          notes: data.notes,
          created_by_id: data.createdById,
        })
        .select('id');

      if (error) raiseMaintError(error, 'repair_shops.insert');
      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('repair_shops.insert: مفيش نتيجة');
      return { id: String(row.id) };
    },

    async shopHistory(shopId, tenantId) {
      const { data, error } = await db.rpc('fn_repair_shop_history', {
        p_shop_id: shopId,
        p_tenant_id: tenantId,
      });
      if (error) raiseMaintError(error, 'fn_repair_shop_history');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((r) => ({
        kind: String(r.kind) as 'OWN' | 'CUSTOMER',
        refId: String(r.ref_id),
        title: String(r.title),
        detail: String(r.detail),
        costPiastres: Number(r.cost_piastres),
        onDate: String(r.on_date).slice(0, 10),
        status: String(r.status),
      }));
    },

    // ─── أجهزة المحل ───
    async sendToShop(input) {
      const { data, error } = await db.rpc('fn_send_to_maintenance', {
        p_product_id: input.productId,
        p_actor_id: input.actorId,
        p_shop_id: input.shopId,
        p_fault: input.fault,
        p_cost: input.costPiastres,
      });
      if (error) raiseMaintError(error, 'fn_send_to_maintenance');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_send_to_maintenance: مفيش نتيجة');
      return { recordId: String(row.record_id), productName: String(row.product_name) };
    },

    async returnFromShop(recordId, actorId, status, costPiastres, note) {
      const { data, error } = await db.rpc('fn_return_from_maintenance', {
        p_record_id: recordId,
        p_actor_id: actorId,
        p_status: status,
        p_cost: costPiastres,
        p_note: note,
      });
      if (error) raiseMaintError(error, 'fn_return_from_maintenance');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_return_from_maintenance: مفيش نتيجة');
      return { productName: String(row.product_name), finalStatus: String(row.final_status) };
    },

    async listRecords(tenantId, branchId, filter) {
      const { data, error } = await db.rpc('fn_maintenance_records', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
        p_scope: filter.scope,
        p_search: filter.search,
        p_from: filter.from,
        p_to: filter.to,
        p_shop_id: filter.shopId,
      });
      if (error) raiseMaintError(error, 'fn_maintenance_records');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((r) => ({
        id: String(r.id),
        productId: String(r.product_id),
        productName: String(r.product_name),
        serialNumber: r.serial_number ? String(r.serial_number) : null,
        shopName: r.shop_name ? String(r.shop_name) : null,
        repairShopId: r.repair_shop_id ? String(r.repair_shop_id) : null,
        faultNote: String(r.fault_note),
        costPiastres: Number(r.cost_piastres),
        sentDate: String(r.sent_date).slice(0, 10),
        returnedDate: r.returned_date ? String(r.returned_date).slice(0, 10) : null,
        status: String(r.status) as MaintenanceRecord['status'],
        resultNote: r.result_note ? String(r.result_note) : null,
        daysOut: Number(r.days_out),
      }));
    },

    // ─── تذاكر العملاء ───
    async listTickets(tenantId, branchId, filter) {
      const { data, error } = await db.rpc('fn_tickets', {
        p_tenant_id: tenantId,
        p_branch_id: branchId,
        p_scope: filter.scope,
        p_search: filter.search,
        p_from: filter.from,
        p_to: filter.to,
        p_shop_id: filter.shopId,
      });
      if (error) raiseMaintError(error, 'fn_tickets');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((r) => ({
        id: String(r.id),
        customerName: String(r.customer_name),
        customerPhone: r.customer_phone ? String(r.customer_phone) : null,
        deviceName: String(r.device_name),
        serialNumber: r.serial_number ? String(r.serial_number) : null,
        deviceColor: r.device_color ? String(r.device_color) : null,
        conditionNote: r.condition_note ? String(r.condition_note) : null,
        complaint: String(r.complaint),
        shopName: r.shop_name ? String(r.shop_name) : null,
        repairShopId: r.repair_shop_id ? String(r.repair_shop_id) : null,
        costPiastres: Number(r.cost_piastres),
        receivedDate: String(r.received_date).slice(0, 10),
        promisedDate: r.promised_date ? String(r.promised_date).slice(0, 10) : null,
        deliveredDate: r.delivered_date ? String(r.delivered_date).slice(0, 10) : null,
        status: String(r.status) as TicketStatus,
        workNote: r.work_note ? String(r.work_note) : null,
        unlockKind: String(r.unlock_kind ?? 'NONE'),
        hasUnlock: Boolean(r.has_unlock),
        parentId: r.parent_id ? String(r.parent_id) : null,
        visitNumber: Number(r.visit_number),
        createdById: String(r.created_by_id),
        createdByName: r.created_by_name ? String(r.created_by_name) : null,
        daysOpen: Number(r.days_open),
      }));
    },

    async productHistory(productId) {
      const { data, error } = await db.rpc('fn_product_maintenance', {
        p_product_id: productId,
      });
      if (error) raiseMaintError(error, 'fn_product_maintenance');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((r) => ({
        id: String(r.id),
        shopName: r.shop_name ? String(r.shop_name) : null,
        faultNote: String(r.fault_note),
        resultNote: r.result_note ? String(r.result_note) : null,
        costPiastres: Number(r.cost_piastres),
        sentDate: String(r.sent_date).slice(0, 10),
        returnedDate: r.returned_date ? String(r.returned_date).slice(0, 10) : null,
        status: String(r.status),
        daysOut: Number(r.days_out),
      }));
    },

    async createTicket(data) {
      const { data: rows, error } = await db.from('repair_tickets').insert(data).select('id');
      if (error) raiseMaintError(error, 'repair_tickets.insert');
      const row = (rows as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('repair_tickets.insert: مفيش نتيجة');
      return { id: String(row.id) };
    },

    async updateTicket(id, patch) {
      const { error } = await db
        .from('repair_tickets').update(patch).eq('id', id).is('deleted_at', null);
      if (error) raiseMaintError(error, 'repair_tickets.update');
    },

    async findTicket(id) {
      const { data, error } = await db
        .from('repair_tickets').select('id, tenant_id, branch_id')
        .eq('id', id).is('deleted_at', null).maybeSingle();

      if (error) raiseMaintError(error, 'repair_tickets.find');
      if (!data) return null;
      const r = data as Record<string, unknown>;
      return { id: String(r.id), tenantId: String(r.tenant_id), branchId: String(r.branch_id) };
    },

    /**
     * ⚠ بيانات الفتح.
     *
     * `canManage` بيتحسب في حالة الاستخدام من الصلاحيات، ودالة
     * القاعدة بتفحصه مع هوية اللي استلم الجهاز. الفحص مرتين
     * عن قصد: نداء مباشر من أي مكان تاني يفضل محروس.
     */
    async unlock(ticketId, actorId, canManage) {
      const { data, error } = await db.rpc('fn_ticket_unlock', {
        p_ticket_id: ticketId,
        p_actor_id: actorId,
        p_can_manage: canManage,
      });
      if (error) raiseMaintError(error, 'fn_ticket_unlock');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.notFound('التذكرة');
      return {
        kind: String(row.unlock_kind),
        value: row.unlock_value ? String(row.unlock_value) : null,
      };
    },
  };
}


// ═══════════════════════════════════════════════════════════
//  الضمان · شراء البضاعة · تقفيل اليومية
//
//  ⚠ نفس قواعد الملف كله: كل نداء بيمرّ على دالة RPC موقّعة
//  بـ service_role، ومفيش استعلام على جدول من غير محل.
// ═══════════════════════════════════════════════════════════

/**
 * ترجمة أخطاء دوال القاعدة.
 *
 * نفس نمط `raiseSaleError` و`raiseReturnError` في `database.ts`.
 * الرسائل مكتوبة عربي جوّه الدوال، فبنمرّرها زي ما هي — هي
 * مكتوبة أصلاً عشان الموظّف يقراها قدّام الزبون.
 */
function raiseError(error: { code?: string; message?: string }, fn: string): never {
  const message = error.message?.trim() || 'تعذّر إتمام العملية.';

  switch (error.code) {
    case 'MZ400':
    case 'MZ409':
      throw Errors.validation(message);
    case 'MZ403':
      throw Errors.forbidden(`${fn}: ${message}`);
    case 'MZ404':
      throw Errors.notFound('العنصر المطلوب');
    default:
      if (error.code === '23514') throw Errors.validation('القيمة غير صالحة.');
      throw Errors.internal(`${fn}: ${error.message}`);
  }
}

/** قراءة رقم من رد القاعدة — bigint بيرجع نص من PostgREST */
function num(value: unknown): number {
  return Number(value ?? 0);
}

function text(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

// ═══════════════════ الضمان ═══════════════════

export function createWarrantyRepository(db: SupabaseClient): WarrantyRepository {
  return {
    async status(saleId) {
      const { data, error } = await db.rpc('fn_sale_warranty', { p_sale_id: saleId });
      if (error) raiseError(error, 'fn_sale_warranty');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) return null;

      return {
        // ⚠ null هنا معناها "بلا ضمان" — مش صفر ومش الافتراضي
        warrantyDays: row.warranty_days === null ? null : num(row.warranty_days),
        startsOn: String(row.starts_on).slice(0, 10),
        expiresOn: row.expires_on ? String(row.expires_on).slice(0, 10) : null,
        daysLeft: row.days_left === null ? null : num(row.days_left),
        isCovered: Boolean(row.is_covered),
      } satisfies WarrantyStatus;
    },

    async setDays(saleId, actorId, warrantyDays) {
      const { data, error } = await db.rpc('fn_set_sale_warranty', {
        p_sale_id: saleId,
        p_actor_id: actorId,
        p_warranty_days: warrantyDays,
      });
      if (error) raiseError(error, 'fn_set_sale_warranty');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_set_sale_warranty: مفيش نتيجة');

      return {
        previousDays: row.previous_days === null ? null : num(row.previous_days),
        newDays: row.new_days === null ? null : num(row.new_days),
        expiresOn: row.expires_on ? String(row.expires_on).slice(0, 10) : null,
      };
    },
  };
}

// ═══════════════════ شراء البضاعة ═══════════════════

export function createPurchaseRepository(db: SupabaseClient): PurchaseRepository {
  return {
    async create(input) {
      const { data, error } = await db.rpc('fn_record_purchase', {
        p_actor_id: input.actorId,
        p_treasury_id: input.treasuryId,
        p_amount_piastres: input.amountPiastres,
        p_item_name: input.itemName,
        p_quantity: input.quantity,
        p_supplier_id: input.supplierId,
        p_note: input.note,
      });
      if (error) raiseError(error, 'fn_record_purchase');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_record_purchase: مفيش نتيجة');

      return {
        purchaseId: String(row.purchase_id),
        movementId: String(row.movement_id),
        status: String(row.status) === 'APPROVED' ? 'APPROVED' : 'PENDING',
      };
    },

    async list(filter) {
      const { data, error } = await db.rpc('fn_purchases', {
        p_tenant_id: filter.tenantId,
        p_branch_id: filter.branchId,
        p_from: filter.from,
        p_to: filter.to,
        p_limit: filter.limit,
      });
      if (error) raiseError(error, 'fn_purchases');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map(
        (row): PurchaseRow => ({
          id: String(row.id),
          movementId: String(row.movement_id),
          itemName: String(row.item_name),
          quantity: num(row.quantity),
          amountPiastres: num(row.amount_piastres),
          supplierId: text(row.supplier_id),
          supplierName: text(row.supplier_name),
          status: String(row.status),
          note: text(row.note),
          occurredAt: new Date(String(row.occurred_at)),
          createdById: String(row.created_by_id),
          createdByName: text(row.created_by_name),
        }),
      );
    },

    /**
     * ⚠ الاستعلام بياخد المحل صراحةً في نفس السطر.
     * ولا بيلمس أي عمود مالي — الاسم والمعرّف وبس.
     */
    async listSupplierNames(tenantId) {
      const { data, error } = await db
        .from('suppliers')
        .select('id, name')
        .eq('tenant_id', tenantId)
        .eq('is_active', true)
        .is('deleted_at', null)
        .order('name');

      if (error) throw Errors.internal(`suppliers.listNames: ${error.message}`);

      return ((data as Array<Record<string, unknown>> | null) ?? []).map((row) => ({
        id: String(row.id),
        name: String(row.name),
      }));
    },
  };
}

// ═══════════════════ تقفيل اليومية ═══════════════════

/**
 * قراءة مصفوفة الأدوار من القاعدة.
 *
 * ⚠ بنفلتر على القيم المعروفة بدل ما نثق في اللي جاي. القيد في
 * القاعدة بيمنع غيرها أصلاً، بس النوع هنا بيبقى صادق من غير ما
 * يعتمد على القيد ده.
 */
function toRoles(value: unknown): ClosingRole[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item))
    .filter((item): item is ClosingRole => item === 'BRANCH_MANAGER' || item === 'STAFF');
}

/** اللقطات بترجع jsonb — ممكن توصل ككائن أو كنص حسب الرحلة */
function parseArray<T>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? (parsed as T[]) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function parseObject(value: unknown): Record<string, unknown> | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }
  return null;
}

function toSummary(row: Record<string, unknown>): ClosingSummary {
  return {
    id: String(row.id),
    branchId: String(row.branch_id),
    branchName: String(row.branch_name),
    periodFrom: new Date(String(row.period_from)),
    periodTo: new Date(String(row.period_to)),
    salesCount: num(row.sales_count),
    salesPiastres: num(row.sales_piastres),
    returnsCount: num(row.returns_count),
    returnsPiastres: num(row.returns_piastres),
    expensesPiastres: num(row.expenses_piastres),
    advancesPiastres: num(row.advances_piastres),
    purchasesPiastres: num(row.purchases_piastres),
    cashInPiastres: num(row.cash_in_piastres),
    cashOutPiastres: num(row.cash_out_piastres),
    note: text(row.note),
    closedById: String(row.closed_by_id ?? ''),
    closedByName: text(row.closed_by_name),
    closedAt: new Date(String(row.closed_at)),
  };
}

export function createClosingRepository(db: SupabaseClient): ClosingRepository {
  return {
    async preview(branchId, actorId) {
      const { data, error } = await db.rpc('fn_closing_preview', {
        p_branch_id: branchId,
        p_actor_id: actorId,
      });
      if (error) raiseError(error, 'fn_closing_preview');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_closing_preview: مفيش نتيجة');

      return {
        canClose: Boolean(row.can_close),
        reason: text(row.reason),
        periodFrom: new Date(String(row.period_from)),
        minutesOpen: num(row.minutes_open),
        minutesLeft: num(row.minutes_left),
        salesCount: num(row.sales_count),
        salesPiastres: num(row.sales_piastres),
        returnsCount: num(row.returns_count),
        movementsCount: num(row.movements_count),
        closingRoles: toRoles(row.closing_roles),
      } satisfies ClosingPreview;
    },

    /**
     * ⚠ نداء واحد. كل اللقطات بتتبني جوّه القاعدة في نفس
     * المعاملة اللي بتكتب الصف.
     *
     * لو بنيناها هنا، كنا هنقرا المبيعات في رحلة والحركات في
     * رحلة تانية — وأي بيعة بتتسجّل بينهم بتقع في الشق: مش في
     * اليومية القديمة ولا الجديدة.
     */
    async close(branchId, actorId, note) {
      const { data, error } = await db.rpc('fn_close_day', {
        p_branch_id: branchId,
        p_actor_id: actorId,
        p_note: note,
      });
      if (error) raiseError(error, 'fn_close_day');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_close_day: مفيش نتيجة');

      return {
        closingId: String(row.closing_id),
        periodFrom: new Date(String(row.period_from)),
        periodTo: new Date(String(row.period_to)),
        salesCount: num(row.sales_count),
        salesPiastres: num(row.sales_piastres),
        returnsPiastres: num(row.returns_piastres),
        expensesPiastres: num(row.expenses_piastres),
        purchasesPiastres: num(row.purchases_piastres),
        cashInPiastres: num(row.cash_in_piastres),
        cashOutPiastres: num(row.cash_out_piastres),
      } satisfies CloseDayResult;
    },

    /**
     * ⚠ النطاق بيتفكّ هنا بدل ما يتبعت كقيمة.
     *
     * النوع `ListScope` بيمنع حالة "بلا محل" من الأساس، فمفيش
     * فرع في الدالة دي بيبعت `p_tenant_id` فاضي.
     */
    async list(scope: ListScope, limit) {
      if (!('tenantId' in scope)) {
        throw Errors.forbidden('closings: tenant scope required');
      }

      const { data, error } = await db.rpc('fn_closings', {
        p_tenant_id: scope.tenantId,
        p_branch_id: 'branchId' in scope ? scope.branchId : null,
        p_limit: limit,
      });
      if (error) raiseError(error, 'fn_closings');

      return ((data as Array<Record<string, unknown>> | null) ?? []).map(toSummary);
    },

    async detail(closingId, tenantId, includeCost) {
      const { data, error } = await db.rpc('fn_closing_detail', {
        p_closing_id: closingId,
        p_tenant_id: tenantId,
        p_include_cost: includeCost,
      });
      if (error) raiseError(error, 'fn_closing_detail');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) return null;

      const summary = toSummary(row);
      const cost = parseObject(row.cost_snapshot);

      const detail: ClosingDetail = {
        id: summary.id,
        branchId: summary.branchId,
        branchName: summary.branchName,
        periodFrom: summary.periodFrom,
        periodTo: summary.periodTo,
        salesCount: summary.salesCount,
        salesPiastres: summary.salesPiastres,
        returnsCount: summary.returnsCount,
        returnsPiastres: summary.returnsPiastres,
        expensesPiastres: summary.expensesPiastres,
        advancesPiastres: summary.advancesPiastres,
        purchasesPiastres: summary.purchasesPiastres,
        cashInPiastres: summary.cashInPiastres,
        cashOutPiastres: summary.cashOutPiastres,
        note: summary.note,
        closedByName: summary.closedByName,
        closedAt: summary.closedAt,
        sales: parseArray<ClosingSaleLine>(row.sales_snapshot),
        movements: parseArray<ClosingMovementLine>(row.treasury_snapshot),
        purchases: parseArray<ClosingPurchaseLine>(row.purchases_snapshot),
      };

      // ⚠ الحقل بيتضاف **بس** لو القاعدة رجّعته. القاعدة بترجّعه
      // بس لو `includeCost` — فمفيش مسار بيحط صفر مكان الممنوع.
      if (cost) {
        detail.cost = {
          cogsPiastres: num(cost.cogs_piastres),
          grossProfitPiastres: num(cost.gross_profit_piastres),
          lines: parseArray<Record<string, unknown>>(cost.lines).map((line) => ({
            saleId: String(line.sale_id),
            name: String(line.name),
            quantity: num(line.quantity),
            unitCostPiastres: num(line.unit_cost_piastres),
            unitPricePiastres: num(line.unit_price_piastres),
          })),
        } satisfies ClosingCostSnapshot;
      }

      return detail;
    },

    async setRoles(branchId, actorId, roles) {
      const { data, error } = await db.rpc('fn_set_closing_roles', {
        p_branch_id: branchId,
        p_actor_id: actorId,
        p_roles: roles,
      });
      if (error) raiseError(error, 'fn_set_closing_roles');

      const row = (data as Array<Record<string, unknown>> | null)?.[0];
      if (!row) throw Errors.internal('fn_set_closing_roles: مفيش نتيجة');

      return {
        previousRoles: toRoles(row.previous_roles),
        newRoles: toRoles(row.new_roles),
      };
    },
  };
}
