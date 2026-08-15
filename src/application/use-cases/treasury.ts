/**
 * الخزينة — منطق حركة الفلوس
 *
 * ══ المبدأ اللي بيحكم الملف كله ══
 * الدفتر هو الحقيقة. الرصيد مش رقم مخزّن، هو ناتج جمع الحركات
 * المعتمدة. والحركة المعلّقة **ما بتأثّرش على الرصيد** لحد ما
 * تتعتمد — زي شيك اتكتب ولسه ما اتصرفش.
 *
 * ══ تشبيه ══
 * الموظّف بيكتب طلب صرف في الدفتر. المدير بيمضي جنبه.
 * قبل الإمضا، الفلوس لسه في الخزنة على الورق.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  EnrichedMovement,
  ExpenseReasonRepository,
  ManualMovementType,
  MovementDirection,
  MovementRepository,
  MovementStatus,
  SalaryStatement,
  TreasuryBalance,
  TreasuryRepository,
  UserRepository,
} from '../ports';

export interface TreasuryDeps {
  treasuries: TreasuryRepository;
  movements: MovementRepository;
  expenseReasons: ExpenseReasonRepository;
  users: UserRepository;
  clock: Clock;
  audit: AuditLogger;
}

/**
 * اتجاه كل نوع حركة — ثابت مش اختيار من المستخدم.
 *
 * ليه؟ عشان "مصروف بيزوّد الرصيد" يبقى مستحيل. الاتجاه صفة
 * ملازمة للنوع، مش حقل حرّ حد ممكن يغلط فيه أو يتلاعب بيه.
 *
 * ⚠ لاحظ `ManualMovementType` مش `MovementType`.
 * نوع البيع (SALE) **مش** في الجدول ده عن قصد — البيع بيتولّد من
 * دالة البيع الذرية مع الفاتورة وخصم المخزون، وعمره ما بيتسجّل
 * من شاشة الخزينة.
 *
 * لو حد جه بكرة وحاول يضيف SALE هنا عشان "يكمّل الجدول"، لازم
 * يقرا السطور دي الأول ويفهم إن النقص مقصود.
 */
const DIRECTION: Record<ManualMovementType, MovementDirection> = {
  DEPOSIT: 'IN',
  WITHDRAWAL: 'OUT',
  EXPENSE: 'OUT',
  ADVANCE: 'OUT',
  ADJUSTMENT: 'IN', // التسوية بتتعامل بشكل خاص تحت
};

/** الأنواع اللي محتاجة صلاحية اعتماد عشان تتسجّل أصلاً */
const RESTRICTED_TYPES: ManualMovementType[] = ['DEPOSIT', 'WITHDRAWAL', 'ADJUSTMENT'];

export interface RecordMovementInput {
  treasuryId: string;
  /** البيع مستبعد بالنوع نفسه — مفيش طريقة تمرّره من هنا */
  type: ManualMovementType;
  amountPiastres: number;
  expenseReasonId?: string | null;
  relatedUserId?: string | null;
  note?: string | null;
  /** للتسوية فقط — الأنواع التانية اتجاهها ثابت */
  adjustmentDirection?: MovementDirection;
}

export async function recordMovement(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  input: RecordMovementInput,
): Promise<{ id: string; status: MovementStatus }> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_CREATE);
  }

  const canApprove = actor.permissions.includes(PERMISSIONS.EXPENSE_APPROVE);

  // إيداع / سحب / تسوية: دي حركات بتغيّر الرصيد من بره دورة البيع
  // العادية، فمينفعش موظّف يعملها حتى كطلب معلّق.
  if (RESTRICTED_TYPES.includes(input.type) && !canApprove) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_APPROVE);
  }

  if (!Number.isInteger(input.amountPiastres) || input.amountPiastres <= 0) {
    throw Errors.validation('المبلغ غير صالح.');
  }

  // ─── نطاق الخزينة ───
  const scope = await deps.treasuries.findScope(input.treasuryId);
  if (!scope) throw Errors.notFound('الخزينة');
  assertBranchAccess(actor, scope.branchId);

  // ─── الحقول المشروطة بالنوع ───
  let expenseReasonId: string | null = null;
  let relatedUserId: string | null = null;

  // ⚠ السبب مطلوب للمصروف وحده.
  //
  // السُلفة سببها معروف من نوعها — "سُلفة" هي السبب. لما كنّا
  // بنطلب سبب معاها كمان، كان لازم يبقى فيه بند اسمه "سُلفة موظّف"
  // في قائمة الأسباب، فيبقى نفس المعلومة مكتوبة في مكانين:
  // في `type` وفي `expense_reason_id`. ولما يختلفوا، مين الصح؟
  //
  // قيد قاعدة البيانات `expense_needs_reason` أصلاً بيطلب السبب
  // للمصروف بس — يعني الاشتراط الزيادة ده كان من عندنا، والقاعدة
  // مش محتاجاه.
  if (input.type === 'EXPENSE') {
    if (!input.expenseReasonId) throw Errors.validation('اختر سبب الصرف.');

    const reason = await deps.expenseReasons.findById(input.expenseReasonId);
    if (!reason) throw Errors.validation('سبب الصرف غير موجود.');

    // سبب خاص بفرع تاني ما ينفعش يتستخدم هنا
    if (reason.branchId && reason.branchId !== scope.branchId) {
      throw Errors.validation('سبب الصرف هذا غير متاح لهذا الفرع.');
    }
    expenseReasonId = reason.id;
  }

  if (input.type === 'ADVANCE') {
    if (!input.relatedUserId) throw Errors.validation('اختر الموظّف صاحب السُلفة.');

    const target = await deps.users.findById(input.relatedUserId);
    if (!target || target.deletedAt) throw Errors.validation('الموظّف غير موجود.');

    // السُلفة بتتخصم من راتب حد — فلازم يكون في نطاقك
    assertBranchAccess(actor, target.branchId);
    relatedUserId = target.id;
  }

  // ─── الاتجاه ───
  const direction =
    input.type === 'ADJUSTMENT' ? (input.adjustmentDirection ?? 'IN') : DIRECTION[input.type];

  if (input.type === 'ADJUSTMENT' && direction !== 'IN' && direction !== 'OUT') {
    throw Errors.validation('اتجاه التسوية غير صحيح.');
  }

  // ─── الاعتماد ───
  // اللي عنده صلاحية اعتماد، حركته بتتعتمد فورًا وباسمه.
  // اللي مالوش، حركته بتفضل معلّقة وما بتأثّرش على الرصيد.
  const now = deps.clock.now();
  const status: MovementStatus = canApprove ? 'APPROVED' : 'PENDING';

  const note = input.note?.trim() || null;
  if (note && note.length > 500) throw Errors.validation('الملاحظة طويلة جدًا.');

  const created = await deps.movements.create({
    treasuryId: input.treasuryId,
    branchId: scope.branchId,
    direction,
    type: input.type,
    amountPiastres: input.amountPiastres,
    status,
    expenseReasonId,
    relatedUserId,
    note,
    occurredAt: now,
    createdById: actor.id,
    approvedById: canApprove ? actor.id : null,
    approvedAt: canApprove ? now : null,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'treasury.movement.create',
    entity: 'TreasuryMovement',
    entityId: created.id,
    metadata: {
      type: input.type,
      direction,
      amountPiastres: input.amountPiastres,
      status,
      treasuryId: input.treasuryId,
    },
  });

  return { id: created.id, status };
}

/**
 * اعتماد أو رفض حركة معلّقة.
 *
 * ⚠ المعتمِد لازم يكون **غير** اللي أنشأها. من غير القاعدة دي،
 * "الاعتماد" يبقى خطوة شكلية أي حد يعمل لنفسه — وده اللي بيسمّى
 * في المحاسبة فصل المهام (segregation of duties).
 */
export async function reviewMovement(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  movementId: string,
  decision: 'APPROVED' | 'REJECTED',
): Promise<void> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_APPROVE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_APPROVE);
  }

  const movement = await deps.movements.findById(movementId);
  if (!movement) throw Errors.notFound('الحركة');

  if (movement.status !== 'PENDING') {
    throw Errors.validation('سبق مراجعة هذه الحركة.');
  }

  // ⚠ حركة البيع معتمدة من لحظة إنشائها ومربوطة بفاتورة.
  // الشرط اللي فوق بيمنعها أصلاً (حالتها APPROVED مش PENDING)،
  // لكن الحارس ده صريح عشان أي تغيير مستقبلي في قواعد الاعتماد
  // ما يفتحش باب "رفض" فاتورة مباعة والفلوس في الدرج.
  if (movement.type === 'SALE') {
    throw Errors.validation('لا تخضع حركة البيع للمراجعة. استخدم المرتجع.');
  }

  // فصل المهام: اللي كتب الطلب مش هو اللي يمضيه.
  // عمليًا الحالة دي نادرة (صاحب صلاحية الاعتماد حركته بتتعتمد
  // فورًا فما بتوصلش لحالة معلّقة)، بس الحارس موجود عشان أي
  // تغيير مستقبلي في قواعد الاعتماد ما يفتحش الباب ده بالغلط.
  if (movement.createdById === actor.id) {
    throw Errors.forbidden('لا يمكن اعتماد حركة أنشأتها بنفسك.');
  }

  assertBranchAccess(actor, movement.branchId);

  await deps.movements.review(movementId, decision, actor.id, deps.clock.now());

  await deps.audit.record({
    actorId: actor.id,
    action: decision === 'APPROVED' ? 'treasury.movement.approve' : 'treasury.movement.reject',
    entity: 'TreasuryMovement',
    entityId: movementId,
    metadata: { amountPiastres: movement.amountPiastres, type: movement.type },
  });
}

// ─────────── القراءة ───────────

export async function listBalances(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
): Promise<TreasuryBalance[]> {
  return deps.treasuries.listBalances(scopeFor(actor));
}

export async function listMovements(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  status?: MovementStatus,
): Promise<EnrichedMovement[]> {
  const scope = scopeFor(actor);

  // أربع قوائم صغيرة على التوازي، وبنركّب الأسماء منها.
  // أرخص وأمتن من ربط جدول المستخدمين أربع مرات في استعلام واحد.
  const [movements, treasuries, reasons, team] = await Promise.all([
    deps.movements.list({ branchId: scope, status, limit: 50 }),
    deps.treasuries.listBalances(scope),
    deps.expenseReasons.listForBranch(actor.branchId),
    deps.users.listInScope(
      actor.roleKey === 'SUPER_ADMIN' ? { allBranches: true } : { branchId: scope ?? '__none__' },
    ),
  ]);

  const treasuryNames = new Map(treasuries.map((t) => [t.treasuryId, t.name]));
  const reasonNames = new Map(reasons.map((r) => [r.id, r.name]));
  const userNames = new Map(team.map((u) => [u.id, u.fullName]));

  return movements.map((m) => ({
    ...m,
    treasuryName: treasuryNames.get(m.treasuryId) ?? '—',
    reasonName: m.expenseReasonId ? (reasonNames.get(m.expenseReasonId) ?? null) : null,
    relatedUserName: m.relatedUserId ? (userNames.get(m.relatedUserId) ?? null) : null,
    createdByName: userNames.get(m.createdById) ?? null,
  }));
}

export async function listExpenseReasons(deps: TreasuryDeps, actor: AuthenticatedUser) {
  return deps.expenseReasons.listForBranch(actor.branchId);
}

/**
 * كشف حساب الموظّف.
 * الموظّف يقدر يشوف كشفه هو. المدير يشوف كشوف فرعه. المالك الكل.
 */
export async function getSalaryStatement(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  targetUserId: string,
  from: Date,
  to: Date,
): Promise<SalaryStatement> {
  if (targetUserId !== actor.id) {
    if (!actor.permissions.includes(PERMISSIONS.USER_VIEW)) {
      throw Errors.forbidden(PERMISSIONS.USER_VIEW);
    }
    const target = await deps.users.findById(targetUserId);
    if (!target) throw Errors.notFound('الموظّف');
    assertBranchAccess(actor, target.branchId);
  }

  if (!(from instanceof Date) || Number.isNaN(from.getTime())) {
    throw Errors.validation('تاريخ البداية غير صالح.');
  }
  if (!(to instanceof Date) || Number.isNaN(to.getTime()) || to <= from) {
    throw Errors.validation('يجب أن يكون تاريخ النهاية بعد تاريخ البداية.');
  }

  return deps.movements.salaryStatement(targetUserId, from, to);
}

// ─────────── حراسة النطاق ───────────

/** null = كل الفروع. للمالك بس. */
function scopeFor(actor: AuthenticatedUser): string | null {
  if (actor.roleKey === 'SUPER_ADMIN') return null;
  // fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف الكل
  return actor.branchId ?? '__none__';
}

function assertBranchAccess(actor: AuthenticatedUser, targetBranchId: string | null): void {
  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');

  // خزينة على مستوى الشركة (branchId = null) للمالك بس
  if (targetBranchId === null) throw Errors.forbidden('company-level treasury');
  if (targetBranchId !== actor.branchId) throw Errors.forbidden('branch scope');
}
