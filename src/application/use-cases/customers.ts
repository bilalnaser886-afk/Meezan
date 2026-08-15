/**
 * العملاء
 *
 * ══ نطاق المرحلة دي ══
 * اسم ورقم وملاحظات. وبس.
 *
 * الأوسمة التلقائية (عميل مميّز / عميل دائم) **مؤجّلة عن قصد**:
 * الوسام اللي بيتحسب من غير بيانات مبيعات كافية بيبقى كذب مهذّب.
 * "عميل مميّز" بعد فاتورتين معناها لا حاجة، وبتخلّي الموظّف يبطّل
 * يصدّق أي وسام تاني بعدها.
 *
 * ══ ملاحظة على الازدواجية — مهمة ══
 * جدول الفواتير فيه `customer_name` و `customer_phone` كنص حر،
 * والجدول ده منفصل عنهم تمامًا.
 *
 * يعني عندنا دلوقتي **مصدرين** لاسم العميل. ده دين تقني مقصود
 * ومسجّل مش سهو: ربط الفاتورة بسجل عميل قرار ليه نتايج (إيه اللي
 * يحصل للفواتير لو العميل اتحذف؟)، ولسه ما اتحسمش.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  BranchRepository,
  Clock,
  CustomerRecord,
  CustomerRepository,
  ListScope,
} from '../ports';

export interface CustomerDeps {
  customers: CustomerRepository;
  branches: BranchRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateCustomerRequest {
  name: string;
  phone?: string | null;
  notes?: string | null;
  /** مطلوب من المالك بس */
  branchId?: string | null;
}

export interface UpdateCustomerRequest {
  name?: string;
  phone?: string | null;
  notes?: string | null;
}

/**
 * نطاق القراءة.
 * المالك يشوف كل الفروع. غيره فرعه هو بس، ولو مالوش فرع ما يشوفش
 * حاجة — fail-closed.
 */
function scopeFor(actor: AuthenticatedUser): ListScope {
  if (actor.roleKey === 'SUPER_ADMIN') return { allBranches: true };
  return { branchId: actor.branchId ?? '__none__' };
}

function assertBranchAccess(actor: AuthenticatedUser, targetBranchId: string): void {
  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');
  if (targetBranchId !== actor.branchId) throw Errors.forbidden('branch scope');
}

// ─────────── القراءة ───────────

export async function listCustomers(
  deps: CustomerDeps,
  actor: AuthenticatedUser,
  search: string | null = null,
): Promise<CustomerRecord[]> {
  if (!actor.permissions.includes(PERMISSIONS.CUSTOMER_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.CUSTOMER_VIEW);
  }

  const term = (search ?? '').trim();
  return deps.customers.list(scopeFor(actor), term || null, 200);
}

// ─────────── الكتابة ───────────

export async function createCustomer(
  deps: CustomerDeps,
  actor: AuthenticatedUser,
  input: CreateCustomerRequest,
): Promise<{ id: string }> {
  // تسجيل عميل من مهام مندوب المبيعات الأساسية — مش صلاحية إدارية
  if (!actor.permissions.includes(PERMISSIONS.CUSTOMER_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.CUSTOMER_CREATE);
  }

  // نفس نمط المنتجات والمستخدمين: الفرع من هوية المنشئ مش من الطلب
  let targetBranchId: string;
  if (actor.roleKey === 'SUPER_ADMIN') {
    if (!input.branchId) throw Errors.validation('اختر الفرع.');
    const exists = await deps.branches.exists(input.branchId);
    if (!exists) throw Errors.validation('الفرع المختار غير موجود.');
    targetBranchId = input.branchId;
  } else {
    if (!actor.branchId) throw Errors.forbidden('branch scope');
    targetBranchId = actor.branchId;
  }

  const name = readName(input.name);
  const phone = readPhone(input.phone);
  const notes = readNotes(input.notes);

  const created = await deps.customers.create({
    branchId: targetBranchId,
    name,
    phone,
    notes,
    createdById: actor.id,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'customer.create',
    entity: 'Customer',
    entityId: created.id,
    metadata: { name, branchId: targetBranchId, hasPhone: phone !== null },
  });

  return created;
}

export async function updateCustomer(
  deps: CustomerDeps,
  actor: AuthenticatedUser,
  customerId: string,
  input: UpdateCustomerRequest,
): Promise<void> {
  if (!actor.permissions.includes(PERMISSIONS.CUSTOMER_EDIT)) {
    throw Errors.forbidden(PERMISSIONS.CUSTOMER_EDIT);
  }

  const existing = await deps.customers.findById(customerId);
  if (!existing) throw Errors.notFound('العميل');
  assertBranchAccess(actor, existing.branchId);

  const patch: UpdateCustomerRequest = {};
  if (input.name !== undefined) patch.name = readName(input.name);
  if (input.phone !== undefined) patch.phone = readPhone(input.phone);
  if (input.notes !== undefined) patch.notes = readNotes(input.notes);

  if (Object.keys(patch).length === 0) throw Errors.validation('لم يتغيّر شيء.');

  await deps.customers.update(customerId, patch);

  await deps.audit.record({
    actorId: actor.id,
    action: 'customer.update',
    entity: 'Customer',
    entityId: customerId,
    metadata: { changed: Object.keys(patch) },
  });
}

/**
 * حذف ناعم.
 *
 * السجل بيفضل في قاعدة البيانات ومش بيظهر في القوائم. الفواتير
 * القديمة ما بتتأثّرش أصلاً لأنها بتخزّن اسم العميل كنص عندها.
 */
export async function deleteCustomer(
  deps: CustomerDeps,
  actor: AuthenticatedUser,
  customerId: string,
): Promise<void> {
  if (!actor.permissions.includes(PERMISSIONS.CUSTOMER_EDIT)) {
    throw Errors.forbidden(PERMISSIONS.CUSTOMER_EDIT);
  }

  const existing = await deps.customers.findById(customerId);
  if (!existing) throw Errors.notFound('العميل');
  assertBranchAccess(actor, existing.branchId);

  await deps.customers.softDelete(customerId, actor.id, deps.clock.now());

  await deps.audit.record({
    actorId: actor.id,
    action: 'customer.delete',
    entity: 'Customer',
    entityId: customerId,
    metadata: { name: existing.name, phone: existing.phone },
  });
}

// ─────────── فاحصات المدخلات ───────────

function readName(raw: string | undefined): string {
  const name = String(raw ?? '').trim();
  if (name.length < 2 || name.length > 80) {
    throw Errors.validation('اسم العميل من حرفين إلى 80 حرفًا.');
  }
  return name;
}

/**
 * الرقم بيتقبل بشكله المكتوب.
 *
 * ما بنفرضش صيغة معيّنة عن قصد: الموظّف بيكتب اللي الزبون قاله،
 * وممكن يكون فيه مسافات أو شرطات أو مفتاح دولة. لو رفضناه، هيكتب
 * أي حاجة عشان يعدّي — وده تلويث أسوأ من التنوّع.
 */
function readPhone(raw: string | null | undefined): string | null {
  const phone = String(raw ?? '').trim();
  if (!phone) return null;
  if (phone.length > 32) throw Errors.validation('رقم الهاتف طويل جدًا.');
  return phone;
}

function readNotes(raw: string | null | undefined): string | null {
  const notes = String(raw ?? '').trim();
  if (!notes) return null;
  if (notes.length > 1000) throw Errors.validation('الملاحظات أطول من الحد المسموح.');
  return notes;
}
