/**
 * المرتجعات ورفّ المراجعة
 *
 * ══ المرتجع مش عكس البيع ══
 * البيع بيمشي في اتجاه واحد. المرتجع بيمسّ **تلات حاجات** في نفس
 * اللحظة: المخزون، الخزينة، والفاتورة القديمة. وكل واحد فيهم ليه
 * سؤال مختلف.
 *
 * ══ القرارات اللي التصميم مبني عليها ══
 *
 *  1) المرتجع **ما بيرجعش للبيع** — بيروح لرفّ المراجعة.
 *     الجهاز اللي رجع بقى مستعمل، وبيعه كجديد كذب على الزبون
 *     الجاي. فبيستنّى حد يفحصه بإيده ويقول سليم ولا تالف.
 *
 *  2) ممكن ترجّع **أقل** من سعر البيع، والفرق رسوم استرجاع.
 *
 *  3) المرتجع **بند بند**، مش الفاتورة كلها. الزبون بيرجّع
 *     الجراب ويخلّي الموبايل — ودي الحالة الشائعة مش الاستثناء.
 *
 *  4) **بوّابة الضمان** — إضافة جديدة. المرتجع بره مدة الضمان
 *     محتاج موافقة صاحب المحل صراحةً.
 *
 * ══ الفلوس ══
 * بعت بـ1000 ورجّعت 900؟ الـ100 **ما خرجتش من الدرج أصلاً**.
 * فحركة الخزينة بتسجّل 900 بس، والرسوم بتتخزّن على سجل المرتجع.
 *
 * تشبيه: الدرج هو الحقيقة. بنسجّل اللي طلع فعلاً، مش اللي كان
 * ممكن يطلع. ولو عملنا حركتين (خروج 1000 + دخول 100)، الدفتر
 * هيقول إن فيه 1100 اتحرّكوا وهما 900 بس.
 */

import { DateError, parseDateInput } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  CreateReturnResult,
  QuarantineDecision,
  QuarantineReviewResult,
  QuarantineRow,
  ReturnLineInput,
  ReturnRepository,
  ReturnableLine,
  SaleRepository,
  TreasuryRepository,
} from '../ports';
import type { WarrantyRepository, WarrantyStatus } from '../ports';

export interface ReturnDeps {
  returns: ReturnRepository;
  sales: SaleRepository;
  treasuries: TreasuryRepository;
  warranty: WarrantyRepository;
  clock: Clock;
  audit: AuditLogger;
}

/** سقف البنود في مرتجع واحد — نفس منطق سقف السلة في البيع */
const MAX_LINES = 100;

export interface CreateReturnRequest {
  treasuryId: string;
  items: ReturnLineInput[];
  reason?: string | null;
  returnDate?: string | null;
  /**
   * تجاوز الضمان — صاحب المحل وحده.
   *
   * ⚠ ما بيتبعتش تلقائيًا. الواجهة بتوري لصاحب المحل إن الضمان
   * انتهى وبتطلب تأكيد صريح، وساعتها بس بتبعت العلم ده.
   *
   * لو اتبعت من حد مش صاحب المحل، بيترفض هنا وبيترفض تاني جوّه
   * دالة قاعدة البيانات.
   */
  overrideWarranty?: boolean;
}

/** البنود + حالة الضمان في رحلة واحدة */
export interface ReturnContext {
  lines: ReturnableLine[];
  warranty: WarrantyStatus;
  /**
   * هل اللي فاتح الشاشة يقدر يتجاوز الضمان؟
   *
   * الواجهة بتقرا منها: تعرض زرار التأكيد ولا تعرض رسالة رفض.
   * وهي **مش** الحماية — الحماية في الفحصين تحت.
   */
  canOverride: boolean;
}

// ─────────── القراءة ───────────

/**
 * البنود القابلة للاسترجاع.
 *
 * ⚠ الفاتورة بتتفحص هنا **قبل** ما نرجّع أي بند — الفلتر اللي
 * في القوايم ما بيحميش الجلب بالمعرّف المباشر. من غير الفحص ده،
 * أي حد يعرف رقم فاتورة يقرا بنودها.
 */
export async function getReturnableLines(
  deps: ReturnDeps,
  actor: AuthenticatedUser,
  saleId: string,
): Promise<ReturnableLine[]> {
  assertRefundAccess(actor);

  const sale = await deps.sales.findById(saleId, { includeCost: false });
  if (!sale) throw Errors.notFound('الفاتورة');

  assertSaleScope(actor, sale.tenantId, sale.branchId);

  return deps.returns.returnableLines(saleId);
}

/**
 * سياق شاشة الاسترجاع كاملًا — البنود والضمان مع بعض.
 *
 * ══ ليه رحلة واحدة؟ ══
 * الشاشة محتاجة الاتنين قبل ما تعرض أي حاجة. لو جبناهم في
 * رحلتين، الموظّف هيشوف البنود الأول وبعدين تظهرله رسالة الضمان
 * فجأة — والزبون واقف قدامه.
 *
 * والأهم: **الفحص بيحصل مرة واحدة على الاتنين**. لو كل واحد
 * ليه مساره، هييجي يوم يتعدّل فحص في واحد ويفضل القديم في التاني.
 */
export async function getReturnContext(
  deps: ReturnDeps,
  actor: AuthenticatedUser,
  saleId: string,
): Promise<ReturnContext> {
  assertRefundAccess(actor);

  const sale = await deps.sales.findById(saleId, { includeCost: false });
  if (!sale) throw Errors.notFound('الفاتورة');
  assertSaleScope(actor, sale.tenantId, sale.branchId);

  const [lines, warranty] = await Promise.all([
    deps.returns.returnableLines(saleId),
    deps.warranty.status(saleId),
  ]);

  if (!warranty) throw Errors.notFound('الفاتورة');

  return {
    lines,
    warranty,
    canOverride: actor.roleKey === 'SUPER_ADMIN',
  };
}

// ─────────── الاسترجاع ───────────

export async function createReturn(
  deps: ReturnDeps,
  actor: AuthenticatedUser,
  saleId: string,
  input: CreateReturnRequest,
): Promise<CreateReturnResult> {
  assertRefundAccess(actor);

  // ─── الفاتورة ───
  const sale = await deps.sales.findById(saleId, { includeCost: false });
  if (!sale) throw Errors.notFound('الفاتورة');
  assertSaleScope(actor, sale.tenantId, sale.branchId);

  // ─── ⚠ بوّابة الضمان ───
  //
  // العلم ده بيمرّ للقاعدة، والقاعدة هي اللي بتقرر لو الضمان
  // انتهى فعلاً ولا لأ. لكن **مين يحق له يتجاوز** بيتفحص هنا
  // كمان — عشان الرسالة تطلع عربية واضحة بدل خطأ من القاعدة،
  // وعشان الحماية تفضل موجودة لو حد نادى الدالة من مكان تاني.
  const overrideWarranty = input.overrideWarranty === true;
  if (overrideWarranty && actor.roleKey !== 'SUPER_ADMIN') {
    throw Errors.forbidden('تجاوز الضمان لصاحب المحل وحده.');
  }

  // ─── البنود ───
  if (!Array.isArray(input.items) || input.items.length === 0) {
    throw Errors.validation('اختر بندًا واحدًا على الأقل.');
  }
  if (input.items.length > MAX_LINES) {
    throw Errors.validation(`عدد البنود أكبر من الحد المسموح (${MAX_LINES}).`);
  }

  const items: ReturnLineInput[] = input.items.map((line) => {
    const saleItemId = typeof line?.saleItemId === 'string' ? line.saleItemId.trim() : '';
    const quantity = Number(line?.quantity);
    const unitRefundPiastres = Number(line?.unitRefundPiastres);

    if (!saleItemId) throw Errors.validation('يوجد بند بلا معرّف.');
    if (!Number.isInteger(quantity) || quantity <= 0) {
      throw Errors.validation('كمية غير صالحة في أحد البنود.');
    }
    // الصفر مقبول: ممكن ترجّع بند بلا فلوس طالما بند تاني في نفس
    // المرتجع فيه مبلغ. المجموع هو اللي لازم يكون أكبر من صفر،
    // وده بيتفحص في قاعدة البيانات.
    if (!Number.isInteger(unitRefundPiastres) || unitRefundPiastres < 0) {
      throw Errors.validation('مبلغ الاسترجاع غير صالح.');
    }

    return { saleItemId, quantity, unitRefundPiastres };
  });

  // ─── الخزينة ───
  //
  // ⚠ لازم تكون في نفس فرع الفاتورة. الفحص هنا بيطلّع رسالة
  // عربية واضحة، والحراسة الحقيقية جوّه دالة قاعدة البيانات.
  if (!input.treasuryId) throw Errors.validation('اختر الخزينة.');

  const scope = await deps.treasuries.findScope(input.treasuryId);
  if (!scope || scope.tenantId !== actor.tenantId) throw Errors.notFound('الخزينة');
  if (scope.branchId !== sale.branchId) {
    throw Errors.validation('اختر خزينة تابعة لنفس فرع الفاتورة.');
  }

  // ─── التاريخ ───
  let returnDate: string | null;
  try {
    returnDate = parseDateInput(input.returnDate);
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  const reason = readReason(input.reason);

  // ─── التنفيذ ───
  //
  // ⚠ `actorId` من الجلسة مش من الطلب. المرتجع بيطلّع فلوس من
  // الدرج — لو أخدناه من الطلب، أي حد يقدر يسجّل مرتجع باسم
  // مدير تاني ويختفي من السجل.
  const result = await deps.returns.create({
    saleId,
    actorId: actor.id,
    treasuryId: input.treasuryId,
    items,
    reason,
    returnDate,
    overrideWarranty,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'sale.return',
    entity: 'SaleReturn',
    entityId: result.returnId,
    metadata: {
      saleId,
      refundedPiastres: result.refundedPiastres,
      feePiastres: result.feePiastres,
      itemCount: result.itemCount,
      treasuryId: input.treasuryId,
      branchId: sale.branchId,
      movementId: result.movementId,
      returnDate,
      reason,
      // ⚠ التجاوز بيتسجّل بالقيمة اللي القاعدة رجّعتها مش اللي
      // إحنا بعتناها. الطلب ممكن يبعت `true` والفاتورة تكون
      // لسه في الضمان — ساعتها مفيش تجاوز حصل، والسجل لازم
      // يقول الحقيقة مش النيّة.
      warrantyOverridden: result.warrantyOverridden,
      saleWarrantyDays: sale.warrantyDays ?? null,
      saleExitDate: sale.exitDate,
    },
  });

  return result;
}

// ─────────── رفّ المراجعة ───────────

/**
 * المرتجعات المستنية قرار.
 *
 * صاحب المحل بيشوف كل فروعه. غيره فرعه هو بس — fail-closed:
 * مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله.
 */
export async function listQuarantine(
  deps: ReturnDeps,
  actor: AuthenticatedUser,
): Promise<QuarantineRow[]> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_VIEW);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  const branchId = actor.roleKey === 'SUPER_ADMIN' ? null : (actor.branchId ?? '__none__');
  return deps.returns.quarantineList(actor.tenantId, branchId);
}

/**
 * القرار: سليم ولا تالف.
 *
 * ══ ليه `inventory.adjust` مش `sales.refund`؟ ══
 * دول فعلين مختلفين. الاسترجاع قرار **مالي** — فلوس بتطلع من
 * الدرج. المراجعة قرار **مخزني** — بضاعة بترجع للرفّ أو تتشطب.
 *
 * والمندوب عنده `inventory.adjust` فعلاً، فيقدر يفحص المرتجع
 * ويقول رأيه — لكنه عمره ما يقدر يعمل الاسترجاع نفسه.
 * فصل المهام: اللي بيدفع مش اللي بيستلم.
 *
 * ══ والشطب ما بيعدّلش تكلفة ══
 * البضاعة اتدفع تمنها وقت الشراء، والخسارة اتحققت وقت الاسترجاع.
 * تعديل التكلفة هنا كان هيغيّر أرقام فواتير قديمة **بأثر رجعي**،
 * وده أخطر بكتير من خسارة ظاهرة في مكانها وتاريخها.
 */
export async function reviewQuarantine(
  deps: ReturnDeps,
  actor: AuthenticatedUser,
  productId: string,
  quantity: number,
  decision: QuarantineDecision,
): Promise<QuarantineReviewResult> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  if (decision !== 'RELEASE' && decision !== 'SCRAP') {
    throw Errors.validation('القرار غير صحيح.');
  }
  if (!Number.isInteger(quantity) || quantity <= 0) {
    throw Errors.validation('الكمية غير صالحة.');
  }

  const result = await deps.returns.review(productId, actor.id, quantity, decision);

  await deps.audit.record({
    actorId: actor.id,
    action: decision === 'RELEASE' ? 'quarantine.release' : 'quarantine.scrap',
    entity: 'Product',
    entityId: productId,
    // ⚠ الشطب خسارة مخزون بقرار بشري. السجل لازم يقول مين قرّر
    // وكام — وإلا البضاعة بتختفي والدفتر ساكت.
    metadata: {
      productName: result.productName,
      quantity,
      decision,
      remainingHeld: result.remainingHeld,
      nowOnHand: result.nowOnHand,
    },
  });

  return result;
}

// ─────────── حراسة ───────────

/**
 * ⚠ `sales.refund` موجودة عند المندوب بقرار واعٍ (ملف 18).
 * الفحص هنا بيتكرّر مع الحارس عن قصد: لو حد نادى الدالة دي من
 * مكان تاني بكرة من غير ما يعدّي على الحارس، الحماية لسه موجودة.
 */
function assertRefundAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.SALES_REFUND)) {
    throw Errors.forbidden(PERMISSIONS.SALES_REFUND);
  }
}

/** حاجز المحل الأول، وبعدين الفرع */
function assertSaleScope(
  actor: AuthenticatedUser,
  saleTenantId: string,
  saleBranchId: string,
): void {
  // "غير موجودة" مش "ممنوع" — كلمة ممنوع بتأكّد إن الفاتورة
  // موجودة في مكان ما، ودي معلومة عن محل تاني.
  if (saleTenantId !== actor.tenantId) throw Errors.notFound('الفاتورة');

  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');
  if (saleBranchId !== actor.branchId) throw Errors.forbidden('branch scope');
}

function readReason(raw: string | null | undefined): string | null {
  const reason = String(raw ?? '').trim();
  if (!reason) return null;
  if (reason.length > 200) throw Errors.validation('سبب الاسترجاع طويل جدًا.');
  return reason;
}