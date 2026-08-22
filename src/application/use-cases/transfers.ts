/**
 * التحويل بين الفروع
 *
 * ══ خطوتين مش خطوة ══
 * الفرع المُرسِل بينشئ الطلب، والمستقبِل **لازم يأكّد** الاستلام
 * صراحةً قبل ما البضاعة تظهر في مخزونه.
 *
 * "بعتّها" و"وصلت" حاجتين مختلفتين. لو الخطوة واحدة، البضاعة
 * بتظهر في مخزون الفرع التاني وهي لسه في العربية — وهو بيبيع
 * حاجة مش عنده.
 *
 * ══ والكمية بتتخصم وقت الإرسال ══
 * البضاعة سابت الرفّ فعلاً. لو سبناها عند المُرسِل لحد التأكيد،
 * هو ممكن يبيعها وهي في الطريق.
 *
 * فبتبقى في حالة "طايرة" — مش عند حد. وده الوصف الصحيح للواقع
 * مش ثغرة. ولو التحويل اتلغى، بترجع مكانها.
 *
 * تشبيه محاسبي: بضاعة بالطريق (goods in transit) بند معروف في
 * أي ميزانية. مش بتبقى عند البايع ولا المشتري لحد ما تُستلم.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  PendingTransfer,
  TransferDecision,
  TransferRepository,
} from '../ports';

export interface TransferDeps {
  transfers: TransferRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface CreateTransferRequest {
  toBranchId: string;
  quantity: number;
  note?: string | null;
}

/**
 * ⚠ الصلاحية `inventory.adjust` — يعني المندوب كمان.
 *
 * منطقي إن اللي بيرزم الكرتونة هو اللي يسجّلها. والحماية مش في
 * منع الإنشاء — هي في **الخطوتين**: المندوب مش بيقدر يخلّص
 * التحويل لوحده، لأن الاستلام من الفرع التاني.
 */
function assertTransferAccess(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_ADJUST)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_ADJUST);
  }
}

export async function createTransfer(
  deps: TransferDeps,
  actor: AuthenticatedUser,
  productId: string,
  input: CreateTransferRequest,
): Promise<{ transferId: string; productName: string; moved: number }> {
  assertTransferAccess(actor);

  if (!input.toBranchId) throw Errors.validation('اختر الفرع المستقبِل.');

  const quantity = Number(input.quantity);
  if (!Number.isInteger(quantity) || quantity <= 0) {
    throw Errors.validation('الكمية غير صالحة.');
  }

  const note = String(input.note ?? '').trim() || null;
  if (note && note.length > 200) throw Errors.validation('الملاحظة طويلة جدًا.');

  // ⚠ باقي الحراسة (المحل · الفرع · الكمية المتاحة · الجهاز
  // قطعة واحدة) جوّه دالة قاعدة البيانات، جنب البيانات.
  const result = await deps.transfers.create({
    productId,
    actorId: actor.id,
    toBranchId: input.toBranchId,
    quantity,
    note,
  });

  await deps.audit.record({
    actorId: actor.id,
    action: 'transfer.create',
    entity: 'StockTransfer',
    entityId: result.transferId,
    metadata: {
      productId,
      productName: result.productName,
      quantity: result.moved,
      toBranchId: input.toBranchId,
      note,
    },
  });

  return result;
}

/**
 * استلام أو إلغاء.
 *
 * ⚠ الاستلام من الفرع المستقبِل، والإلغاء من المُرسِل — والفحص
 * ده جوّه دالة القاعدة. **اللي بعت مش هو اللي يقول "وصلت".**
 *
 * وبما إن كل مستخدم ليه فرع واحد، الشرط ده بيضمن لوحده إن
 * شخصين مختلفين لمسوا العملية. صاحب المحل استثناء لأن الفرعين
 * بتوعه.
 */
export async function resolveTransfer(
  deps: TransferDeps,
  actor: AuthenticatedUser,
  transferId: string,
  decision: TransferDecision,
): Promise<{ productName: string; moved: number; finalStatus: string }> {
  assertTransferAccess(actor);

  if (decision !== 'RECEIVE' && decision !== 'CANCEL') {
    throw Errors.validation('القرار غير صحيح.');
  }

  const result = await deps.transfers.resolve(transferId, actor.id, decision);

  await deps.audit.record({
    actorId: actor.id,
    action: decision === 'RECEIVE' ? 'transfer.receive' : 'transfer.cancel',
    entity: 'StockTransfer',
    entityId: transferId,
    metadata: {
      productName: result.productName,
      quantity: result.moved,
      status: result.finalStatus,
    },
  });

  return result;
}

/**
 * التحويلات المعلّقة في نطاق المستخدم.
 *
 * صاحب المحل بيشوف كل فروعه. غيره بيشوف الجاي له والرايح منه —
 * fail-closed: مدير بلا فرع ما يشوفش حاجة.
 */
export async function listPendingTransfers(
  deps: TransferDeps,
  actor: AuthenticatedUser,
): Promise<PendingTransfer[]> {
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_VIEW);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  const branchId = actor.roleKey === 'SUPER_ADMIN' ? null : (actor.branchId ?? '__none__');
  return deps.transfers.listPending(actor.tenantId, branchId);
}
