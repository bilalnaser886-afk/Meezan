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
 * ⚠⚠ **ولتذكير التكلفة استثناء واحد، اقرا الفرق:**
 *
 *   الإخفاء المرفوض  →  بيطفي التنبيه للأبد. حالة تانية
 *                        مستقلة عن الواقع وبتتناقض معاه.
 *   التخطّي المسموح  →  بيأجّل تلات أيام و**بيرجع لوحده**.
 *                        المفتاح الوحيد اللي بيطفيه نهائيًا
 *                        لسه هو الشرط نفسه: اكتب التكلفة.
 *
 * يعني حد أجّل ونسي؟ التنبيه بيرجع من غير ما حد يعمل حاجة.
 * التمن إن فيه **حالة مخزّنة** (تاريخ التأجيل) في العمود
 * `cost_alert_snoozed_until` — مقبول لأن التأجيل قرار بشري
 * وما ينفعش يتحسب من البيانات.
 *
 * ══ ⚠ وتلات مصادر للتنبيهات دلوقتي مش واحد ══
 * تنبيهات المخزون والرفّ بتتحسب في **قاعدة البيانات**
 * (`fn_alerts`). وحدّ السحب بيتحسب **هنا**. وتكلفة التذاكر
 * الناقصة بتتحسب في دالة مستقلة (`fn_ticket_cost_alerts`).
 *
 * ليه التفريق؟ نفس السبب في كل مرة — فخ ٧: قبل أي تعديل على
 * دالة، دوّر على كل نسخها الأول. `fn_alerts` شغّالة، وتعديلها
 * عشان استعلام مختلف تمامًا مخاطرة بلا عائد.
 *
 * ⚠ التمن: تلات مصادر لازم يفضلوا متطابقين في الشكل. الحماية
 * إنهم بيخرجوا من **مخرج واحد** هو الدالة دي، وبنفس النوع
 * `AlertRow`.
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
  const costRows = await ticketCostAlertRows(deps, actor.tenantId, branchId);

  // ⚠ الترتيب هو الرسالة.
  //
  //   الخزنة    مسألة النهاردة — رصيد تحت الحد
  //   التكلفة   مسألة فلوس ضايعة — الورشة طالبة ومحدش فاكر كام
  //   المخزون   مسألة الأسبوع
  const rows = [...treasuryRows, ...costRows, ...stockRows];

  return {
    rows,
    highCount: rows.filter((r) => r.severity === 'HIGH').length,
    totalCount: rows.length,
  };
}

/**
 * تذاكر رجعت من الورشة والتكلفة فيها ما اتكتبتش.
 *
 * ⚠ الشرط كله جوّه `fn_ticket_cost_alerts` — بما فيه التأجيل
 * والحالة والمحل. الدالة دي بتحوّل الشكل وبس، ومفيش فيها ولا
 * مقارنة.
 *
 * السبب إن الشرط لازم يفضل متطابق مع شرط توليد الدين في
 * مايجريشن ٥٧. لو اتكتب في مكانين، هيختلفوا يوم ما — وساعتها
 * هيبقى فيه تذاكر بتولّد دين وما بتنبّهش، أو العكس.
 */
async function ticketCostAlertRows(
  deps: AlertDeps,
  tenantId: string,
  branchId: string | null,
): Promise<AlertRow[]> {
  // ⚠ فشل التنبيه ما يوقّعش الشاشة كلها — نفس منطق الخزنة تحت.
  let rows;
  try {
    rows = await deps.alerts.ticketCostAlerts(tenantId, branchId);
  } catch {
    return [];
  }

  return rows.map((r) => ({
    alertType: 'TICKET_COST_MISSING' as const,
    severity: r.severity,
    entityId: r.ticketId,
    title: r.title,
    detail: r.detail,
    // ⚠ المتري هو عدد الأيام. بيستخدمه الترتيب في الشاشة،
    // والأقدم بيطلع فوق.
    metric: r.daysSince,
  }));
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
