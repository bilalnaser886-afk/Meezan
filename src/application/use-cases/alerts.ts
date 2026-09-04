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
 *
 * ══ ⚠ ومصدرين للتنبيهات دلوقتي مش واحد ══
 * تنبيهات المخزون والرفّ بتتحسب في **قاعدة البيانات**
 * (`fn_alerts`). وتنبيه حدّ السحب بيتحسب **هنا**.
 *
 * ليه الاختلاف؟ عشان حدّ السحب عمود على جدول الخزن، وحسابه
 * مقارنة بسيطة برصيد الدالة بترجّعه أصلاً. تعديل `fn_alerts`
 * كان معناه استبدال دالة شغّالة عشان مقارنة سطرين — وفخ ٧
 * بيقول: قبل أي تعديل على دالة، دوّر على كل نسخها الأول.
 *
 * ⚠ التمن: مصدرين لازم يفضلوا متطابقين في الشكل. الحماية إنهم
 * بيخرجوا من **مخرج واحد** هو الدالة دي، وبنفس النوع `AlertRow`.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AlertRepository,
  AlertRow,
  AuthenticatedUser,
  Clock,
  TreasuryRepository,
} from '../ports';
import { overdraftMessage, overdraftView, treasuryLabel } from './treasury';

export interface AlertDeps {
  alerts: AlertRepository;
  /**
   * ⚠ اتضافت لتنبيه حدّ السحب.
   *
   * التنبيهات كانت بتقرا من مصدر واحد، وده أنضف. لكن البديل
   * كان تعديل `fn_alerts` — دالة شغّالة مش شايفينها.
   */
  treasuries: TreasuryRepository;
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

  const stockRows = await deps.alerts.list(actor.tenantId, branchId);
  const treasuryRows = await overdraftAlerts(deps, actor, branchId);

  // ⚠ الخزنة الأول. اللي رصيده تحت الحد مسألة النهاردة، والمخزون
  // المنخفض مسألة الأسبوع — والترتيب هو اللي بيقول ده.
  const rows = [...treasuryRows, ...stockRows];

  return {
    rows,
    highCount: rows.filter((r) => r.severity === 'HIGH').length,
    totalCount: rows.length,
  };
}

/**
 * تنبيهات حدّ السحب على المكشوف.
 *
 * ⚠ الخزنة اللي مالهاش حد **ما بترجعش أي تنبيه**، حتى لو رصيدها
 * سالب بمليون. عدم وضع حد قرار صريح من المالك، والنظام ما
 * بيفترضش حد نيابةً عنه — كان هيبقى تنبيه محدش طلبه.
 *
 * ⚠ ومفيش أي مقارنة هنا. الحالة كلها من `overdraftView`، ونص
 * الرسالة من `overdraftMessage`. الدالة دي بتلمّ وبس.
 */
async function overdraftAlerts(
  deps: AlertDeps,
  actor: AuthenticatedUser,
  branchId: string | null,
): Promise<AlertRow[]> {
  // ⚠ فشل التنبيه ما يوقّعش الشاشة كلها.
  //
  // لوحة الرئيسية بتعرض المخزون والمرتجعات كمان. لو استعلام
  // الخزن وقع، الأولى نعرض الباقي على أن نعرض صفحة خطأ.
  //
  // ⚠ وده **مش** فشل صامت: الرصيد الحقيقي لسه ظاهر في شاشة
  // الخزينة، والتنبيه تكرار ليه مش المصدر الوحيد.
  let rows;
  let limits;
  try {
    [rows, limits] = await Promise.all([
      deps.treasuries.summary(actor.tenantId, branchId),
      deps.treasuries.listOverdraftLimits(actor.tenantId),
    ]);
  } catch {
    return [];
  }

  const limitMap = new Map(limits.map((l) => [l.treasuryId, l.limitPiastres]));
  const out: AlertRow[] = [];

  for (const row of rows) {
    if (!limitMap.has(row.treasuryId)) continue;

    const view = overdraftView(row.balancePiastres, limitMap.get(row.treasuryId) as number);
    if (view.state !== 'NEAR' && view.state !== 'BREACHED') continue;

    const name = treasuryLabel(row);
    const message = overdraftMessage(name, view);
    if (!message) continue;

    out.push({
      alertType: 'TREASURY_OVERDRAFT',
      // العدّي مسألة دلوقتي، والقرب مسألة الأيام الجاية
      severity: view.state === 'BREACHED' ? 'HIGH' : 'MEDIUM',
      entityId: row.treasuryId,
      title: view.state === 'BREACHED' ? 'خزنة عدّت حدّ السحب' : 'خزنة قرّبت من حدّ السحب',
      detail: message,
      // ⚠ المتري هو المساحة الفاضلة بالقرش. سالب = عدّى بكام.
      metric: view.roomPiastres ?? 0,
    });
  }

  // الأخطر الأول: الأقل مساحة فوق
  out.sort((a, b) => a.metric - b.metric);
  return out;
}
