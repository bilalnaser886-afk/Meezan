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
 *
 * ══ والخزينة مش نوع واحد ══
 * نقدي · محفظة · فيزا · إنستاباي — وكل واحدة ليها **جهة**
 * (البنك أو شركة الاتصالات). وتقدر تعمل أكتر من واحدة من نفس
 * النوع: فيزا الأهلي وفيزا CIB، محفظة فودافون ومحفظة اتصالات.
 *
 * ⚠ والنقدي مش الكاش. فلوس محفظة فودافون **مش في الدرج** —
 * لو عدّيناها نقدي، هتقفل الدرج آخر اليوم تلاقي ورق أقل من
 * الدفتر، وتفضل تدوّر على فرق مش موجود.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import {
  MoneyError,
  formatPiastres,
  parseCostToPiastres,
  parseMoneyToPiastres,
} from '../../domain/money';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  ListScope,
  EnrichedMovement,
  ExpenseReasonRepository,
  ManualMovementType,
  MovementDirection,
  MovementRepository,
  MovementStatus,
  SalaryStatement,
  TransferRow,
  TransferTreasuryResult,
  TreasuryBalance,
  StatementRow,
  TreasuryRepository,
  TreasuryStatementPage,
  TreasurySummaryRow,
  TreasuryType,
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
 * أسماء الأنواع بالعربي.
 *
 * ⚠ مكانها هنا مش في الواجهة عشان تبقى **مصدر واحد**: الشاشة
 * والـAPI وأي تصدير مستقبلي بيقروا من نفس المكان. لو اتكتبت في
 * الواجهة كمان، هييجي يوم تتغيّر في واحدة وتفضل القديمة في التانية.
 */
export const TREASURY_TYPE_LABELS: Record<TreasuryType, string> = {
  CASH: 'نقدي',
  WALLET: 'محفظة',
  VISA: 'فيزا',
  INSTAPAY: 'إنستاباي',
};

const VALID_TYPES: TreasuryType[] = ['CASH', 'WALLET', 'VISA', 'INSTAPAY'];

/**
 * اتجاه كل نوع حركة — ثابت مش اختيار من المستخدم.
 *
 * ليه؟ عشان "مصروف بيزوّد الرصيد" يبقى مستحيل. الاتجاه صفة
 * ملازمة للنوع، مش حقل حرّ حد ممكن يغلط فيه أو يتلاعب بيه.
 *
 * ⚠ لاحظ `ManualMovementType` مش `MovementType`.
 * نوع البيع (SALE) وأنواع التحويل (TRANSFER_IN/OUT) **مش** في
 * الجدول ده عن قصد — البيع بيتولّد من دالة البيع الذرية،
 * والتحويل من دالة التحويل الذرية. عمرهم ما بيتسجّلوا من شاشة
 * الحركات اليدوية.
 *
 * لو حد جه بكرة وحاول يضيفهم هنا عشان "يكمّل الجدول"، لازم
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
  assertScopeAccess(actor, scope.tenantId, scope.branchId);

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
    // سبب من محل تاني = غير موجود بالنسبة لك
    if (!reason || reason.tenantId !== actor.tenantId) {
      throw Errors.validation('سبب الصرف غير موجود.');
    }

    // ⚠ شرا البضاعة له مساره الخاص اللي بيكتب بيان (صنف · كمية ·
    // مورّد) جنب الحركة. لو سمحنا بيه هنا كمصروف عادي، هيبقى فيه
    // طريقتين لتسجيل نفس الحاجة — واحدة ببيان وواحدة من غير،
    // والتانية بتلغي الميزة كلها.
    if (reason.isInventory) {
      throw Errors.validation('استخدم "شراء بضاعة" من قائمة النوع لتسجيل بيانه.');
    }

    // سبب خاص بفرع تاني ما ينفعش يتستخدم هنا
    if (reason.branchId && reason.branchId !== scope.branchId) {
      throw Errors.validation('سبب الصرف هذا غير متاح لهذا الفرع.');
    }
    expenseReasonId = reason.id;
  }

  if (input.type === 'ADVANCE') {
    if (!input.relatedUserId) throw Errors.validation('اختر الموظّف صاحب السُلفة.');

    const target = await deps.users.findById(input.relatedUserId);
    if (!target || target.deletedAt || target.tenantId !== actor.tenantId) {
      throw Errors.validation('الموظّف غير موجود.');
    }

    // السُلفة بتتخصم من راتب حد — فلازم يكون في نطاقك
    assertScopeAccess(actor, target.tenantId, target.branchId);
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
    tenantId: actor.tenantId,
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

  // ⚠ ونفس الكلام على التحويل: الفلوس اتنقلت فعلاً بين خزينتين،
  // والطرفين مربوطين بمعرّف مجموعة واحد. "رفض" طرف واحد كان
  // هيسيب فلوس طالعة من خزينة وما وصلتش للتانية.
  if (movement.type === 'TRANSFER_IN' || movement.type === 'TRANSFER_OUT') {
    throw Errors.validation('لا تخضع حركة التحويل للمراجعة.');
  }

  // فصل المهام: اللي كتب الطلب مش هو اللي يمضيه.
  // عمليًا الحالة دي نادرة (صاحب صلاحية الاعتماد حركته بتتعتمد
  // فورًا فما بتوصلش لحالة معلّقة)، بس الحارس موجود عشان أي
  // تغيير مستقبلي في قواعد الاعتماد ما يفتحش الباب ده بالغلط.
  if (movement.createdById === actor.id) {
    throw Errors.forbidden('لا يمكن اعتماد حركة أنشأتها بنفسك.');
  }

  assertScopeAccess(actor, movement.tenantId, movement.branchId);

  await deps.movements.review(movementId, decision, actor.id, deps.clock.now());

  await deps.audit.record({
    actorId: actor.id,
    action: decision === 'APPROVED' ? 'treasury.movement.approve' : 'treasury.movement.reject',
    entity: 'TreasuryMovement',
    entityId: movementId,
    metadata: { amountPiastres: movement.amountPiastres, type: movement.type },
  });
}

// ─────────── الملخّص المالي ───────────

/**
 * صف الخزنة + حالته تجاه حدّ السحب.
 *
 * ⚠ الحالة **محسوبة** مش مخزّنة، ومصدرها `overdraftView` وحدها.
 */
export interface SummaryRowWithLimit extends TreasurySummaryRow {
  overdraft: OverdraftView;
}

export interface SummaryBranch {
  branchId: string | null;
  branchName: string;
  totalPiastres: number;
  rows: SummaryRowWithLimit[];
}

export interface SummaryType {
  type: string;
  label: string;
  totalPiastres: number;
  count: number;
}

export interface FinancialSummary {
  rows: SummaryRowWithLimit[];
  /** فلوسك مقسّمة على الفروع */
  branches: SummaryBranch[];
  /** ونفس الفلوس مقسّمة على الأنواع — نقدي كام، محافظ كام */
  byType: SummaryType[];
  /** المجموع الكلي */
  totalPiastres: number;
  scopeLabel: 'كل الفروع' | 'فرعك';
}

/**
 * الملخّص المالي: فلوسك فين، وكام في كل مكان.
 *
 * ══ ⚠ كل الأرقام بتتحسب من **نفس الصفوف** ══
 * دي أهم تفصيلة في الدالة. المستودع بيرجّع صف لكل خزينة، وكل
 * المجاميع (الكلي · كل فرع · كل نوع) بتتحسب من المصفوفة دي هنا.
 *
 * ليه مش تلات استعلامات؟ عشان **يستحيل المجموع يخالف الأجزاء**.
 * لو كل رقم له استعلامه، هييجي يوم واحد فيهم يتعدّل ويفضل الباقي
 * قديم — والشاشة تقول "الإجمالي ١٠٠٠" وتحته أربع خزائن مجموعهم
 * ٩٠٠، ومحدش يعرف مين الصح.
 *
 * ودي نفس قاعدة الرصيد نفسه: **ناتج جمع مش رقم مخزّن**.
 *
 * ══ والموقوفة بتتحسب ══
 * الخزينة الموقوفة لسه فيها فلوس. إخفاؤها من المجموع كان هيخلّي
 * الإجمالي يكدب. وقاعدة البيانات بترفض إيقاف خزينة رصيدها مش
 * صفر أصلاً، فالحالة دي نادرة — بس المجموع لازم يفضل صادق.
 */
export async function getFinancialSummary(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
): Promise<FinancialSummary> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_CREATE);
  }

  const branchScope = branchScopeFor(actor);

  // ⚠ استعلامين على التوازي مش واحد ورا التاني.
  //
  // الحدود جدول تاني خالص، والأرصدة دالة. لو مشيناهم بالترتيب،
  // كنا هنضيف رحلة شبكة كاملة على شاشة بتتفتح كل شوية.
  const [baseRows, limits] = await Promise.all([
    deps.treasuries.summary(actor.tenantId, branchScope),
    deps.treasuries.listOverdraftLimits(actor.tenantId),
  ]);

  const limitMap = new Map(limits.map((l) => [l.treasuryId, l.limitPiastres]));

  // ⚠ الحالة بتتحسب **مرة واحدة هنا** وبتتوزّع على كل التجميعات.
  // لو كل تجميعة حسبتها لوحدها، كانوا هيختلفوا يوم ما.
  const rows: SummaryRowWithLimit[] = baseRows.map((row) => ({
    ...row,
    overdraft: overdraftView(
      row.balancePiastres,
      limitMap.has(row.treasuryId) ? (limitMap.get(row.treasuryId) as number) : null,
    ),
  }));

  // ─── التجميع بالفرع ───
  const branchMap = new Map<string, SummaryBranch>();
  for (const row of rows) {
    const key = row.branchId ?? '__tenant__';
    let group = branchMap.get(key);
    if (!group) {
      group = {
        branchId: row.branchId,
        branchName: row.branchName ?? 'على مستوى المحل',
        totalPiastres: 0,
        rows: [],
      };
      branchMap.set(key, group);
    }
    group.rows.push(row);
    group.totalPiastres += row.balancePiastres;
  }

  // ─── التجميع بالنوع ───
  const typeMap = new Map<string, SummaryType>();
  for (const row of rows) {
    let group = typeMap.get(row.type);
    if (!group) {
      group = {
        type: row.type,
        label: TREASURY_TYPE_LABELS[row.type as TreasuryType] ?? row.type,
        totalPiastres: 0,
        count: 0,
      };
      typeMap.set(row.type, group);
    }
    group.totalPiastres += row.balancePiastres;
    group.count += 1;
  }

  return {
    rows,
    branches: [...branchMap.values()],
    byType: [...typeMap.values()],
    totalPiastres: rows.reduce((sum, row) => sum + row.balancePiastres, 0),
    scopeLabel: branchScope === null ? 'كل الفروع' : 'فرعك',
  };
}

// ─────────── إدارة الخزائن ───────────

// ═══════════════ حدّ السحب على المكشوف ═══════════════

/**
 * حالة الخزنة تجاه حدّها.
 *
 *   NONE     مفيش حد متحطّ
 *   OK       لسه فيه مساحة
 *   NEAR     فاضل 20% أو أقل
 *   BREACHED عدّى الحد
 */
export type OverdraftState = 'NONE' | 'OK' | 'NEAR' | 'BREACHED';

export interface OverdraftView {
  limitPiastres: number | null;
  state: OverdraftState;
  /** كام لسه فاضل قبل الحد. سالب = عدّاه بكام. */
  roomPiastres: number | null;
}

/** فاضل 20% أو أقل = "قرّب". نسبة واحدة في مكان واحد. */
const NEAR_RATIO = 0.2;

/**
 * ⚠⚠ الدالة دي هي **المصدر الوحيد** لحالة الحد في النظام كله.
 *
 * الشاشة بتقرا منها، والتنبيهات بتقرا منها، والإشعار المنبثق
 * بيقرا منها. مفيش أي مكان تاني بيقارن رصيد بحد.
 *
 * ══ ليه الإصرار ده؟ ══
 * أشهر عيب في المشروع إن نفس المعلومة بتتكتب في تلات نسخ
 * (الشاشة · الكود · القاعدة) ومفيش حاجة بتجبرهم يتطابقوا.
 * لو النسبة اتكتبت في الشاشة كمان، هييجي يوم تتغيّر في واحدة
 * وتفضل التانية — والكارت يقول "قرّب" والتنبيه يقول "تمام".
 *
 * ══ ⚠ حالة الحد = صفر ══
 * صفر معناه "ممنوع السالب خالص". وساعتها مفيش مساحة أصلاً،
 * فمفيش معنى لـ"قرّب" — بتبقى `OK` وهي موجبة و`BREACHED` أول
 * ما تنزل تحت الصفر. من غير الاستثناء ده، أي خزنة رصيدها صفر
 * بالظبط كانت هترفع تنبيه "قرّبت" كل يوم بلا سبب.
 */
export function overdraftView(
  balancePiastres: number,
  limitPiastres: number | null,
): OverdraftView {
  if (limitPiastres === null || limitPiastres === undefined) {
    return { limitPiastres: null, state: 'NONE', roomPiastres: null };
  }

  const limit = Math.max(0, Math.trunc(limitPiastres));

  // الأرضية اللي مش المفروض ينزل تحتها
  const floor = -limit;
  const room = balancePiastres - floor;

  if (room < 0) {
    return { limitPiastres: limit, state: 'BREACHED', roomPiastres: room };
  }
  if (limit > 0 && room <= limit * NEAR_RATIO) {
    return { limitPiastres: limit, state: 'NEAR', roomPiastres: room };
  }
  return { limitPiastres: limit, state: 'OK', roomPiastres: room };
}

/** نص جاهز للعرض — نفس الصياغة في الشاشة والتنبيه والإشعار */
export function overdraftMessage(name: string, view: OverdraftView): string | null {
  if (view.state === 'BREACHED') {
    return `${name} عدّت حدّ السحب بـ ${formatPiastres(Math.abs(view.roomPiastres ?? 0))} ج.م.`;
  }
  if (view.state === 'NEAR') {
    return `${name} قرّبت من حدّ السحب — فاضل ${formatPiastres(view.roomPiastres ?? 0)} ج.م.`;
  }
  return null;
}

/**
 * قراءة الحد من مدخل المستخدم.
 *
 * ⚠ الفاضي = `null` = "شيل الحد"، مش صفر. الاتنين معنيين
 * مختلفين وموثّقين في مايجريشن ٥٥.
 */
function readOverdraftLimit(raw: string | null | undefined): number | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  try {
    // ⚠ `parseCostToPiastres` مش `parseMoneyToPiastres`:
    // التانية بترفض الصفر، والصفر هنا قيمة صحيحة تمامًا
    // (ممنوع السالب خالص).
    return parseCostToPiastres(text);
  } catch (error) {
    throw Errors.validation(
      error instanceof MoneyError ? error.message : 'حد السحب غير صالح.',
    );
  }
}

export interface CreateTreasuryRequest {
  branchId: string;
  name: string;
  type: string;
  provider?: string | null;
  /** نص من المستخدم. فاضي = مفيش حد. */
  overdraftLimit?: string | null;
}

/**
 * إنشاء خزينة — صاحب المحل وحده.
 *
 * ══ ليه مقفولة عليه؟ ══
 * إضافة خزينة = فتح **مكان جديد الفلوس تعيش فيه**. وده قرار
 * مِلكية زي إنشاء فرع، مش قرار تشغيلي زي تسجيل مصروف.
 *
 * ولو فتحناها لمدير الفرع، كان هيقدر يعمل خزينة جديدة ويحوّل
 * عليها — والمجموع يبان مظبوط والفلوس في مكان مالكش عليه عين.
 *
 * ⚠ الفحص على الدور مباشرةً، وبيتكرّر جوّه دالة القاعدة.
 */
export async function createTreasury(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  input: CreateTreasuryRequest,
): Promise<{ treasuryId: string }> {
  if (actor.roleKey !== 'SUPER_ADMIN') {
    throw Errors.forbidden('إنشاء الخزائن لصاحب المحل وحده.');
  }

  const branchId = String(input.branchId ?? '').trim();
  if (!branchId) throw Errors.validation('اختر الفرع.');

  const name = String(input.name ?? '').trim();
  if (name.length < 2 || name.length > 60) {
    throw Errors.validation('اسم الخزينة من حرفين إلى 60 حرفًا.');
  }

  const type = String(input.type ?? '').trim().toUpperCase() as TreasuryType;
  if (!VALID_TYPES.includes(type)) {
    throw Errors.validation('نوع الخزينة غير معروف.');
  }

  // ⚠ النقدي مالوش جهة — الدرج مش بنك. بنفضّيها بهدوء بدل ما
  // نرفض: المستخدم ممكن يكون ساب القيمة من اختيار قبله.
  const provider = type === 'CASH' ? null : readProvider(input.provider);

  const created = await deps.treasuries.create({
    actorId: actor.id,
    branchId,
    name,
    type,
    provider,
  });

  // ── الحد ──
  //
  // ⚠ كتابة تانية بعد الإنشاء، مش جوّه نفس المعاملة.
  //
  // البديل كان تعديل `fn_create_treasury` عشان تاخد معامل
  // زيادة — والدالة دي شغّالة ومش شايفينها، وفخ ٢ بيقول إن
  // `create or replace` بمعاملات مختلفة بيعمل دالة تانية.
  //
  // ⚠ التمن: لو الخطوة دي فشلت، الخزنة بتكون اتعملت من غير حد.
  // والفشل **بيبان**: بنرمي رسالة صريحة تقول للمالك يظبطه من
  // التعديل، بدل ما نبلعها ونسيبه فاكر إن الحد اتحفظ.
  const limit = readOverdraftLimit(input.overdraftLimit);
  if (limit !== null) {
    try {
      await deps.treasuries.setOverdraftLimit({
        treasuryId: created.treasuryId,
        tenantId: actor.tenantId,
        limitPiastres: limit,
      });
    } catch {
      throw Errors.validation(
        'الخزنة اتعملت، بس حدّ السحب ما اتحفظش. اظبطه من تعديل الخزنة.',
      );
    }
  }

  await deps.audit.record({
    actorId: actor.id,
    action: 'treasury.create',
    entity: 'Treasury',
    entityId: created.treasuryId,
    metadata: {
      name,
      type,
      provider,
      branchId,
      overdraftLimitPiastres: limit,
      tenantId: actor.tenantId,
    },
  });

  return created;
}

export interface UpdateTreasuryRequest {
  name?: string | null;
  provider?: string | null;
  isActive?: boolean | null;
}

/** ⚠ منفصلة عن `UpdateTreasuryRequest` لأن دي بتروح لدالة
 *  القاعدة، والحد بيتكتب على الجدول مباشرةً. الفصل بيمنع إن
 *  حد يبعت الحد للدالة اللي ما بتعرفوش. */
export interface UpdateTreasuryExtras {
  /** نص من المستخدم. `''` أو null = شيل الحد. `undefined` = ما تلمسوش. */
  overdraftLimit?: string | null;
}

/**
 * تعديل خزينة — الاسم والجهة والتفعيل.
 *
 * ⚠ النوع **ما بيتعدّلش**، ومفيش حقل ليه هنا أصلاً.
 *
 * تحويل خزينة من نقدي لمحفظة بعد ما اتسجّل عليها حركات معناه إن
 * كل حركة قديمة بقت في مكان غير اللي حصلت فيه فعلاً — والدفتر
 * بيكدب بأثر رجعي.
 *
 * عايز تغيّر النوع؟ اعمل خزينة جديدة وحوّل الرصيد. خطوتين
 * ظاهرتين في الدفتر أحسن من تعديل صامت.
 */
export async function updateTreasury(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  treasuryId: string,
  input: UpdateTreasuryRequest & UpdateTreasuryExtras,
): Promise<{ treasuryId: string; balancePiastres: number }> {
  if (actor.roleKey !== 'SUPER_ADMIN') {
    throw Errors.forbidden('تعديل الخزائن لصاحب المحل وحده.');
  }
  if (!treasuryId) throw Errors.validation('معرّف الخزينة مفقود.');

  // ⚠ حاجز المحل قبل أي كتابة. `findScope` بترجع null للخزنة
  // الموقوفة كمان — ودي حالة مقصودة: الموقوفة ما بتتعدّلش من
  // هنا غير عن طريق دالة القاعدة اللي بتعرف تفكّ الإيقاف.
  const scope = await deps.treasuries.findScope(treasuryId);
  if (scope && scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزنة');

  const patch: UpdateTreasuryRequest = {};

  if (input.name !== undefined && input.name !== null) {
    const name = String(input.name).trim();
    if (name.length < 2 || name.length > 60) {
      throw Errors.validation('اسم الخزينة من حرفين إلى 60 حرفًا.');
    }
    patch.name = name;
  }
  if (input.provider !== undefined) patch.provider = readProvider(input.provider);
  if (input.isActive !== undefined && input.isActive !== null) {
    patch.isActive = input.isActive === true;
  }

  // ⚠ `undefined` معناها "ما تلمسش الحد"، و`null`/`''` معناها
  // "شيله". من غير التفرقة دي، أي تعديل للاسم كان هيمسح الحد.
  const touchesLimit = input.overdraftLimit !== undefined;
  const nextLimit = touchesLimit ? readOverdraftLimit(input.overdraftLimit) : null;

  if (Object.keys(patch).length === 0 && !touchesLimit) {
    throw Errors.validation('لم يتغيّر شيء.');
  }

  if (touchesLimit) {
    await deps.treasuries.setOverdraftLimit({
      treasuryId,
      tenantId: actor.tenantId,
      limitPiastres: nextLimit,
    });
  }

  // ⚠ لو الحد وحده اللي اتغيّر، مفيش داعي نستدعي دالة القاعدة
  // بتلات قيم فاضية — بعض النسخ بتعتبرها "لم يتغيّر شيء" وترمي.
  if (Object.keys(patch).length === 0) {
    const rows = await deps.treasuries.summary(actor.tenantId, branchScopeFor(actor));
    const row = rows.find((t) => t.treasuryId === treasuryId);

    await deps.audit.record({
      actorId: actor.id,
      action: 'treasury.update',
      entity: 'Treasury',
      entityId: treasuryId,
      metadata: { changed: ['overdraftLimit'], overdraftLimitPiastres: nextLimit },
    });

    return { treasuryId, balancePiastres: row?.balancePiastres ?? 0 };
  }

  const result = await deps.treasuries.update({
    treasuryId,
    actorId: actor.id,
    name: patch.name ?? null,
    provider: patch.provider ?? null,
    isActive: patch.isActive ?? null,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'treasury.update',
    entity: 'Treasury',
    entityId: treasuryId,
    metadata: {
      changed: touchesLimit ? [...Object.keys(patch), 'overdraftLimit'] : Object.keys(patch),
      overdraftLimitPiastres: touchesLimit ? nextLimit : undefined,
      balancePiastres: result.balancePiastres,
    },
  });

  return result;
}

// ─────────── التحويل بين الخزائن ───────────

export interface TransferRequest {
  fromTreasuryId: string;
  toTreasuryId: string;
  /** نص من المستخدم — اللي طلع من المصدر */
  sent: string;
  /** نص كمان — اللي وصل للوجهة */
  received: string;
  note?: string | null;
  date?: string | null;
}

/**
 * تحويل بين خزينتين، والعمولة بتتحسب.
 *
 * ══ ⚠ إنت بتكتب اللي شفته ══
 * طلع كام، ووصل كام. والفرق **هو** العمولة — محسوبة مش مكتوبة.
 *
 * البديل كان خانة تالتة للعمولة، وساعتها ممكن تكتب أرقام
 * متناقضة (طلع ١٠٠٠، وصل ٩٨٠، عمولة ٥٠) ومحدش يعرف مين الصح.
 * دلوقتي التناقض ده **مستحيل تمثيليًا**، وفيه قيد في القاعدة
 * بيحرسه كمان.
 *
 * ══ ومين يقدر؟ ══
 * اللي عنده `expense.approve` — نفس قاعدة الإيداع والسحب
 * والتسوية. دي حركات بتغيّر الرصيد من بره دورة البيع العادية.
 *
 * والخطر الحقيقي مش التحويل (الفلوس بتفضل عندك)، الخطر هو
 * **العمولة**: حد يكتب عمولة ٢٠٠ على تحويل ١٠٠٠ ويحط ١٨٠ في
 * جيبه. عشان كده الرقمين بيتسجّلوا والفرق بيتحفظ.
 *
 * ══ وجوّه الفرع الواحد بس ══
 * الفلوس بين فرعين بتبقى في جيب واحد في العربية — نفس مشكلة
 * "بضاعة بالطريق". الحارس ده جوّه دالة القاعدة.
 */
export async function transferBetweenTreasuries(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  input: TransferRequest,
): Promise<TransferTreasuryResult> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_APPROVE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_APPROVE);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  const fromTreasuryId = String(input.fromTreasuryId ?? '').trim();
  const toTreasuryId = String(input.toTreasuryId ?? '').trim();

  if (!fromTreasuryId || !toTreasuryId) throw Errors.validation('اختر الخزينتين.');
  if (fromTreasuryId === toTreasuryId) {
    throw Errors.validation('اختر خزينتين مختلفتين.');
  }

  const sentPiastres = readAmount(input.sent, 'المبلغ المُرسَل');
  const receivedPiastres = readAmount(input.received, 'المبلغ المستلَم');

  if (receivedPiastres > sentPiastres) {
    throw Errors.validation('المبلغ المستلَم أكبر من المُرسَل.');
  }

  // ─── نطاق الخزينتين ───
  //
  // ⚠ الفحص هنا بيطلّع رسالة عربية واضحة، والحراسة الحقيقية
  // (نفس الفرع · الرصيد كافي · الصلاحية) جوّه دالة القاعدة.
  const fromScope = await deps.treasuries.findScope(fromTreasuryId);
  if (!fromScope || fromScope.tenantId !== actor.tenantId) {
    throw Errors.notFound('الخزينة المُرسِلة');
  }
  const toScope = await deps.treasuries.findScope(toTreasuryId);
  if (!toScope || toScope.tenantId !== actor.tenantId) {
    throw Errors.notFound('الخزينة المستقبِلة');
  }
  assertScopeAccess(actor, fromScope.tenantId, fromScope.branchId);

  let date: string | null;
  try {
    date = parseDateInput(input.date);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  const note = String(input.note ?? '').trim() || null;
  if (note && note.length > 500) throw Errors.validation('الملاحظة طويلة جدًا.');

  const result = await deps.treasuries.transfer({
    // ⚠ من الجلسة مش من الطلب. التحويل بيحرّك فلوس — لو أخدناه
    // من الطلب، أي حد يسجّل باسم زميله ويختفي من السجل.
    actorId: actor.id,
    fromTreasuryId,
    toTreasuryId,
    sentPiastres,
    receivedPiastres,
    note,
    date,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'treasury.transfer',
    entity: 'TreasuryTransfer',
    entityId: result.transferId,
    // ⚠ العمولة من رد القاعدة مش من حسابنا. لو اتغيّرت قاعدة
    // الحساب يوم ما، السجل بيفضل صادق مع اللي اتكتب فعلاً.
    metadata: {
      fromTreasuryId,
      toTreasuryId,
      sentPiastres: result.sentPiastres,
      receivedPiastres: result.receivedPiastres,
      feePiastres: result.feePiastres,
      outMovementId: result.outMovementId,
      inMovementId: result.inMovementId,
      branchId: fromScope.branchId,
      date,
      note,
    },
  });

  return result;
}

export async function listTransfers(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  rawFrom?: string | null,
  rawTo?: string | null,
): Promise<TransferRow[]> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_CREATE);
  }

  let from: string | null;
  let to: string | null;
  try {
    from = parseDateInput(rawFrom);
    to = parseDateInput(rawTo);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }
  if (from && to && from > to) {
    throw Errors.validation('تاريخ البداية بعد تاريخ النهاية.');
  }

  return deps.treasuries.listTransfers(actor.tenantId, branchScopeFor(actor), from, to, 100);
}

// ─────────── القراءة ───────────

export async function listBalances(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
): Promise<TreasuryBalance[]> {
  return deps.treasuries.listBalances(actor.tenantId, branchScopeFor(actor));
}

export async function listMovements(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  status?: MovementStatus,
): Promise<EnrichedMovement[]> {
  const branchScope = branchScopeFor(actor);

  // أربع قوائم صغيرة على التوازي، وبنركّب الأسماء منها.
  // أرخص وأمتن من ربط جدول المستخدمين أربع مرات في استعلام واحد.
  //
  // ⚠ كل واحدة فيهم بتاخد المحل صراحةً. مفيش واحدة بتستنتجه.
  const [movements, treasuries, reasons, team] = await Promise.all([
    deps.movements.list({ tenantId: actor.tenantId, branchId: branchScope, status, limit: 50 }),
    // ⚠ `summary` مش `listBalances` — عشان اسم الفرع يوصل.
    //
    // بعد ما خزينة كل فرع بقت اسمها "نقدي"، الحركة اللي مكتوب
    // جنبها "نقدي" وحدها ما بتقولش لصاحب المحل حصلت فين.
    // والدالتين بيقروا من نفس المصدر، فمفيش تكلفة زيادة.
    deps.treasuries.summary(actor.tenantId, branchScope),
    deps.expenseReasons.listForBranch(actor.tenantId, actor.branchId),
    deps.users.listInScope(listScopeFor(actor)),
  ]);

  const treasuryNames = new Map(treasuries.map((t) => [t.treasuryId, treasuryLabel(t)]));
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

export interface StatementRequest {
  /** مؤشّر الصفحة السابقة — فاضي = من الأول */
  beforeAt?: string | null;
  beforeId?: string | null;
  /**
   * الرصيد المرحّل من آخر سطر في الصفحة السابقة.
   *
   * ⚠ فاضي = ابدأ من رصيد الخزنة الحالي.
   */
  carryPiastres?: number | null;
  limit?: number;
}

/** حجم الصفحة الافتراضي والأقصى — الشاشة بتطلب، والحد هنا */
const STATEMENT_PAGE = 60;
const STATEMENT_MAX = 200;

/**
 * كشف حساب خزنة — كل الحركات، الأحدث فوق، بالرصيد الجاري.
 *
 * ══ ⚠ الرصيد الجاري بيتحسب بالمشي للورا ══
 *
 * الرصيد المخزّن مش موجود أصلاً في النظام ده — رصيد الخزنة ناتج
 * جمع بيتحسب في القاعدة. فمفيش عمود "الرصيد بعد الحركة" نقرا منه.
 *
 * فبنبدأ من الرصيد الحالي (وهو الرصيد **بعد** أحدث حركة) وننزل:
 *
 *     الرصيد بعد الحركة اللي تحتي = رصيدي − مبلغ حركتي بإشارتها
 *
 * تشبيه: كشف البنك بيبدأ من رصيدك النهارده ويرجع لورا. مش
 * بيحسب من أول يوم فتحت فيه الحساب.
 *
 * ══ ⚠⚠ والمعلّق ما بيحرّكش الرصيد ══
 * الحركة اللي لسه ما اتراجعتش (`PENDING`) أو اتـرفضت (`REJECTED`)
 * **مش داخلة** في رصيد الخزنة — ده مكتوب في `recordMovement` فوق.
 *
 * فبتتعرض في الكشف (لأنها حصلت فعلاً ولازم تتشاف) لكن رصيدها
 * `null`. لو حسبناها، كل الأرقام تحتها كانت هتبقى غلط بمبلغها.
 *
 * ══ ⚠ التمن — اقراه ══
 * نقطة الارتساء هي الرصيد **لحظة فتح الصفحة**. لو حد سجّل حركة
 * وإنت بتقلّب في القديم، الأرقام اللي قدامك بتبقى متأخّرة بمبلغها.
 *
 * والحل هو التحديث — الصفحة بتعيد الارتساء من الرصيد الجديد.
 *
 * ⚠ والبديل الدقيق كان: استعلام تجميعي يجمع كل حركة أحدث من
 * المؤشّر في كل صفحة. اتأجّل عن قصد لأنه استعلام زيادة على كل
 * ضغطة "هات أقدم"، والرقم ده **للعرض بس** — مفيش قرار مالي
 * بيتبنى عليه. رصيد الخزنة نفسه لسه بيتحسب في القاعدة زي ما هو.
 */
export async function getTreasuryStatement(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  treasuryId: string,
  input: StatementRequest = {},
): Promise<TreasuryStatementPage> {
  // نفس صلاحية شاشة الخزينة — الكشف مش بيكشف حاجة جديدة، هو
  // نفس الحركات المعروضة هناك مرتّبة بشكل تاني.
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_CREATE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_CREATE);
  }

  const id = String(treasuryId ?? '').trim();
  if (!id) throw Errors.validation('اختر الخزنة.');

  // ⚠ الحاجز الأول: الخزنة دي بتاعة محلك أصلاً؟
  // خزنة محل تاني = "غير موجودة"، مش "ممنوعة".
  const scope = await deps.treasuries.findScope(id);
  if (!scope) throw Errors.notFound('الخزنة');
  assertScopeAccess(actor, scope.tenantId, scope.branchId);

  const limit = Math.min(Math.max(Number(input.limit) || STATEMENT_PAGE, 1), STATEMENT_MAX);

  // ── المؤشّر ──
  //
  // ⚠ الاتنين مع بعض أو ولا واحد. مؤشّر نصّه ناقص معناه ترحيل
  // بيتخطّى صفوف بصمت — وده أسوأ من رسالة رفض.
  let before: { occurredAt: Date; id: string } | undefined;
  const rawAt = String(input.beforeAt ?? '').trim();
  const rawId = String(input.beforeId ?? '').trim();
  if (rawAt || rawId) {
    if (!rawAt || !rawId) throw Errors.validation('مؤشّر الترحيل غير مكتمل.');
    const at = new Date(rawAt);
    if (Number.isNaN(at.getTime())) throw Errors.validation('مؤشّر الترحيل غير صالح.');
    before = { occurredAt: at, id: rawId };
  }

  // ⚠ بنطلب سطر زيادة عشان نعرف "فيه كمان؟" من غير عدّ منفصل.
  // العدّ المنفصل استعلام تاني ممكن يختلف عن الأول في نفس اللحظة.
  const [raw, treasuries, reasons, team] = await Promise.all([
    deps.movements.list({
      tenantId: actor.tenantId,
      branchId: branchScopeFor(actor),
      treasuryId: id,
      before,
      limit: limit + 1,
    }),
    deps.treasuries.summary(actor.tenantId, branchScopeFor(actor)),
    deps.expenseReasons.listForBranch(actor.tenantId, actor.branchId),
    deps.users.listInScope(listScopeFor(actor)),
  ]);

  const hasMore = raw.length > limit;
  const movements = hasMore ? raw.slice(0, limit) : raw;

  const info = treasuries.find((t) => t.treasuryId === id);
  if (!info) throw Errors.notFound('الخزنة');

  const reasonNames = new Map(reasons.map((r) => [r.id, r.name]));
  const userNames = new Map(team.map((u) => [u.id, u.fullName]));
  const label = treasuryLabel(info);

  // ── الرصيد الجاري ──
  //
  // نبدأ من نقطة الارتساء وننزل. المعلّق والمرفوض بيعدّوا من غير
  // ما يلمسوا العدّاد.
  let carry =
    input.carryPiastres === null || input.carryPiastres === undefined
      ? info.balancePiastres
      : Number(input.carryPiastres);
  if (!Number.isFinite(carry)) carry = info.balancePiastres;
  carry = Math.trunc(carry);

  const rows: StatementRow[] = movements.map((m) => {
    const counts = m.status === 'APPROVED';
    const balanceAfterPiastres = counts ? carry : null;
    if (counts) {
      // الرصيد اللي قبل الحركة دي = الرصيد بعدها ناقص أثرها
      carry -= m.direction === 'IN' ? m.amountPiastres : -m.amountPiastres;
    }

    return {
      ...m,
      treasuryName: label,
      reasonName: m.expenseReasonId ? (reasonNames.get(m.expenseReasonId) ?? null) : null,
      relatedUserName: m.relatedUserId ? (userNames.get(m.relatedUserId) ?? null) : null,
      createdByName: userNames.get(m.createdById) ?? null,
      balanceAfterPiastres,
    };
  });

  const last = movements[movements.length - 1];

  return {
    treasuryId: id,
    label,
    type: info.type,
    isActive: info.isActive,
    balancePiastres: info.balancePiastres,
    movementCount: info.movementCount,
    rows,
    nextCursor:
      hasMore && last
        ? { occurredAt: last.occurredAt.toISOString(), id: last.id }
        : null,
    hasMore,
  };
}

/**
 * لافتة الخزينة: الاسم + الجهة.
 *
 * ⚠ من غير الجهة، تلات فيزا في نفس الفرع بيبانوا "فيزا · فيزا ·
 * فيزا" في كل قايمة — والموظّف بيختار عشوائي، والفلوس تتسجّل في
 * المكان الغلط.
 *
 * ⚠ ومُصدَّرة عشان كل شاشة تستخدم **نفس** اللافتة. لو كل شاشة
 * ركّبتها بطريقتها، هتلاقي نفس الخزينة باسمين مختلفين.
 */
export function treasuryLabel(t: {
  name: string;
  provider?: string | null;
  branchName?: string | null;
}): string {
  const parts = [t.name];

  const provider = t.provider?.trim();
  if (provider) parts.push(provider);

  // ⚠ الفرع بيتضاف **لما يكون معروف بس**.
  //
  // بعد ما خزينة كل فرع بقت اسمها "نقدي"، صاحب المحل بيشوف
  // "نقدي · نقدي · نقدي" في أي قايمة مسطّحة. الفرع هو اللي
  // بيفرّق.
  //
  // ومدير الفرع ما بيشوفش الفرع لأن قايمته فرعه بس — إضافته
  // كانت هتبقى تكرار على كل سطر بلا فايدة. القاعدة: **اعرض
  // اللي بيفرّق، مش كل اللي تعرفه.**
  const branch = t.branchName?.trim();
  if (branch) parts.push(branch);

  return parts.join(' — ');
}

export async function listExpenseReasons(deps: TreasuryDeps, actor: AuthenticatedUser) {
  return deps.expenseReasons.listForBranch(actor.tenantId, actor.branchId);
}

/**
 * سبب صرف جديد.
 *
 * ══ ⚠ `expense.approve` مش `expense.create` — وده قرار ══
 *
 * أي حد بيصرف من الدرج عنده `expense.create`. لكن سبب الصرف مش
 * بيان على الحركة — هو **بند في قائمة الدخل**. تفصيل المصروفات
 * بيتجمّع بيه، وهو اللي بيوري صاحب المحل بيصرف فين.
 *
 * لو كل موظّف يقدر يزوّد بند، هتلاقي "نثرية" و"نثريات" و"فطار"
 * و"فطار الصبح" — والتقرير بيبقى عشرين سطر بجنيهات، وصاحب
 * المحل يبطّل يقراه.
 *
 * والموظّف اللي مالوش الصلاحية مش متعطّل: "مصروفات نثرية"
 * موجودة في البذرة عشان الحالات دي بالظبط، والملاحظة بتشيل
 * التفصيل.
 *
 * ⚠ لو حبيت تفتحها للمندوب، غيّر `EXPENSE_APPROVE` لـ
 * `EXPENSE_CREATE` في السطرين تحت وخلاص.
 */
export async function createExpenseReason(
  deps: TreasuryDeps,
  actor: AuthenticatedUser,
  rawName: unknown,
): Promise<{ id: string }> {
  if (!actor.permissions.includes(PERMISSIONS.EXPENSE_APPROVE)) {
    throw Errors.forbidden(PERMISSIONS.EXPENSE_APPROVE);
  }

  const name = String(rawName ?? '').trim();
  if (name.length < 2 || name.length > 60) {
    throw Errors.validation('اسم السبب من حرفين إلى 60 حرفًا.');
  }

  const created = await deps.expenseReasons.create({ tenantId: actor.tenantId, name });

  await deps.audit.record({
    actorId: actor.id,
    action: 'expense_reason.create',
    entity: 'ExpenseReason',
    entityId: created.id,
    metadata: { name, tenantId: actor.tenantId },
  });

  return created;
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
    if (!target || target.tenantId !== actor.tenantId) throw Errors.notFound('الموظّف');
    assertScopeAccess(actor, target.tenantId, target.branchId);
  }

  if (!(from instanceof Date) || Number.isNaN(from.getTime())) {
    throw Errors.validation('تاريخ البداية غير صالح.');
  }
  if (!(to instanceof Date) || Number.isNaN(to.getTime()) || to <= from) {
    throw Errors.validation('يجب أن يكون تاريخ النهاية بعد تاريخ البداية.');
  }

  return deps.movements.salaryStatement(targetUserId, from, to);
}

// ─────────── فاحصات المدخلات ───────────

function readAmount(raw: string, label: string): number {
  try {
    // نفس دالة الفلوس المستخدمة في كل النظام — بتقبل الأرقام
    // العربية وبترفض السالب والكسور الزيادة
    return parseMoneyToPiastres(String(raw ?? ''));
  } catch (error) {
    throw Errors.validation(
      error instanceof MoneyError ? `${label}: ${error.message}` : `${label} غير صالح.`,
    );
  }
}

function readProvider(raw: string | null | undefined): string | null {
  const provider = String(raw ?? '').trim();
  if (!provider) return null;
  if (provider.length < 2 || provider.length > 60) {
    throw Errors.validation('اسم الجهة من حرفين إلى 60 حرفًا.');
  }
  return provider;
}

// ─────────── حراسة النطاق ───────────

/**
 * الفرع اللي بيتفلتر بيه — **جوّه المحل**.
 *
 * ⚠ null هنا معناها "كل فروع محله هو"، مش "كل النظام".
 * المحل نفسه بيتبعت منفصل لكل استعلام وما بيعتمدش على الدالة دي.
 */
function branchScopeFor(actor: AuthenticatedUser): string | null {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (actor.roleKey === 'SUPER_ADMIN') return null;
  // fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله
  return actor.branchId ?? '__none__';
}

/** نطاق قائمة الفريق — النوع بيجبرنا نذكر المحل */
function listScopeFor(actor: AuthenticatedUser): ListScope {
  if (actor.roleKey === 'SUPER_ADMIN') return { tenantId: actor.tenantId };
  return { tenantId: actor.tenantId, branchId: actor.branchId ?? '__none__' };
}

/**
 * حراسة السجل الواحد: المحل الأول، وبعدين الفرع.
 *
 * ⚠ لما المحل ما يطابقش، بنرمي "غير موجود" مش "ممنوع".
 * "ممنوع" بتأكّد للسائل إن الحاجة موجودة في مكان ما — ودي معلومة
 * ما ينفعش يعرفها عن محل تاني أصلاً.
 */
function assertScopeAccess(
  actor: AuthenticatedUser,
  targetTenantId: string,
  targetBranchId: string | null,
): void {
  if (targetTenantId !== actor.tenantId) throw Errors.notFound('العنصر');
  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');

  // خزينة على مستوى المحل كله (branchId = null) لصاحب المحل بس
  if (targetBranchId === null) throw Errors.forbidden('tenant-level treasury');
  if (targetBranchId !== actor.branchId) throw Errors.forbidden('branch scope');
}
