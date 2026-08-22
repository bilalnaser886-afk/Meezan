/**
 * التنبيهات
 *
 * ══ التنبيه حالة مش حدث ══
 * كل التنبيهات هنا بتوصف الوضع **دلوقتي**: "باقي ٢" · "مرتجع
 * في الرفّ من ٤ أيام". فبتتحسب لحظة الطلب، ومفيش جدول بتتخزّن
 * فيه.
 *
 * لو خزّنّاها، كان هيحصل ده: تنبيه "مخزون منخفض" يتكتب الساعة ٣،
 * إنت توّرد الساعة ٤، والتنبيه يفضل معلّق لحد ٥. الشاشة بتقول
 * حاجة والمخزن بيقول حاجة تانية.
 *
 * تشبيه: عدّاد الوزن مش بيخزّن وزنك امبارح ويوريهولك. بيقيس
 * لما تقف عليه.
 *
 * ⚠ نفس مبدأ رصيد الخزينة بالظبط: ناتج جمع، مش رقم مخزّن.
 *
 * ══ ومفيش زرار إخفاء ══
 * الحد الأدنى نفسه هو زرار الإطفاء. زرار "إخفاء" كان هيبقى
 * مفتاح تاني لنفس اللمبة — والمفتاحين بيختلفوا يوم ما.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type { AlertRepository, AlertRow, AuthenticatedUser, Clock } from '../ports';

export interface AlertDeps {
  alerts: AlertRepository;
  clock: Clock;
}

export interface AlertSummary {
  rows: AlertRow[];
  highCount: number;
  totalCount: number;
}

/**
 * التنبيهات في نطاق المستخدم.
 *
 * صاحب المحل بيشوف كل فروعه. غيره فرعه هو بس — fail-closed:
 * مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل كله.
 */
export async function listAlerts(
  deps: AlertDeps,
  actor: AuthenticatedUser,
): Promise<AlertSummary> {
  // التنبيهات كلها عن المخزون، فالصلاحية هي صلاحية رؤيته
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_VIEW)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_VIEW);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  const branchId = actor.roleKey === 'SUPER_ADMIN' ? null : (actor.branchId ?? '__none__');
  const rows = await deps.alerts.list(actor.tenantId, branchId);

  return {
    rows,
    highCount: rows.filter((r) => r.severity === 'HIGH').length,
    totalCount: rows.length,
  };
}
