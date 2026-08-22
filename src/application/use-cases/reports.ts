/**
 * التقارير — قائمة الدخل
 *
 * ══ الخزينة مش الربح ══
 * رصيد الدرج بيقولك **كام فلوس عندك دلوقتي**.
 * قائمة الدخل بتقولك **كسبت كام**.
 *
 * ودول رقمين مختلفين تمامًا. الدرج ممكن يكون مليان وإنت خسران:
 * لو البضاعة اللي بعتها كانت مشتراها بأغلى من اللي قبضته، الفلوس
 * في إيدك النهاردة — والخسارة هتبان لما تروح تشتري بدلها.
 *
 * تشبيه: عدّاد الوزن بيقولك وزنك النهاردة. مش بيقولك إنت بتخس
 * ولا بتتخن. محتاج تقارن بفترة عشان تعرف الاتجاه.
 *
 * ══ قائمتين مش قائمة واحدة ══
 * صاحب المحل بيشوف التكلفة والربح. مدير الفرع **لأ**.
 *
 * ودي مش بخل — دي نفس القاعدة اللي النظام كله مبني عليها:
 * التكلفة الحقيقية = هامش الربح = قرار ملكية. مدير الفرع بيشوف
 * حركة فرعه كاملة (باع كام، رجّع كام، صرف كام) من غير الهامش.
 *
 * والفرق بيتنفّذ في **قاعدة البيانات**: الرقم ما بيتحسبش أصلاً
 * لمن مالوش الصلاحية، فمفيش حاجة تتخبّى في الواجهة.
 */

import { DateError, parseDateInput, todayInCairo } from '../../domain/dates';
import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AuditLogger,
  AuthenticatedUser,
  Clock,
  ExpenseLine,
  IncomeStatement,
  ReportRepository,
} from '../ports';

export interface ReportDeps {
  reports: ReportRepository;
  clock: Clock;
  audit: AuditLogger;
}

export interface ReportPeriod {
  from: string;
  to: string;
}

export interface IncomeReport extends ReportPeriod {
  statement: IncomeStatement;
  expenses: ExpenseLine[];
  /** هل الأرقام دي بتشمل التكلفة والربح؟ الواجهة بتتغيّر على أساسها */
  includesCost: boolean;
  /** نطاق التقرير — بيتعرض في العنوان عشان محدش يلخبط فرع بمحل */
  scopeLabel: 'كل الفروع' | 'فرعك';
}

/** أقصى مدى للتقرير: سنتين. حارس ضد استعلام بيقرا كل تاريخ المحل */
const MAX_DAYS = 730;

export async function getIncomeReport(
  deps: ReportDeps,
  actor: AuthenticatedUser,
  rawFrom?: string | null,
  rawTo?: string | null,
): Promise<IncomeReport> {
  // ⚠ مندوب المبيعات مالوش `report.view_branch` في الأدوار
  // الافتراضية — فالشاشة دي مش بتفتح عنده أصلاً.
  if (!actor.permissions.includes(PERMISSIONS.REPORT_VIEW_BRANCH)) {
    throw Errors.forbidden(PERMISSIONS.REPORT_VIEW_BRANCH);
  }
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }

  const { from, to } = readPeriod(rawFrom, rawTo);

  // ─── النطاق ───
  //
  // ⚠ fail-closed: مدير بلا فرع ما يشوفش حاجة بدل ما يشوف المحل
  // كله. النوع هنا مش بيحمي زي ListScope، فالحارس صريح.
  const isOwner = actor.roleKey === 'SUPER_ADMIN';
  const branchId = isOwner ? null : (actor.branchId ?? '__none__');

  // التكلفة بالصلاحية مش بالدور — عشان أي استثناء فردي يشتغل
  const includesCost = actor.permissions.includes(PERMISSIONS.PROFIT_VIEW_REAL);

  const [statement, expenses] = await Promise.all([
    deps.reports.incomeStatement(actor.tenantId, branchId, from, to, includesCost),
    deps.reports.expenseBreakdown(actor.tenantId, branchId, from, to),
  ]);

  return {
    from,
    to,
    statement,
    expenses,
    includesCost,
    scopeLabel: isOwner ? 'كل الفروع' : 'فرعك',
  };
}

/**
 * قراءة الفترة.
 * فاضية = الشهر الحالي بتوقيت القاهرة.
 */
function readPeriod(rawFrom?: string | null, rawTo?: string | null): ReportPeriod {
  const today = todayInCairo();

  let from: string;
  let to: string;

  try {
    from = parseDateInput(rawFrom) ?? `${today.slice(0, 7)}-01`;
    to = parseDateInput(rawTo) ?? today;
  } catch (error) {
    throw Errors.validation(error instanceof DateError ? error.message : 'تاريخ غير صالح.');
  }

  if (from > to) throw Errors.validation('تاريخ البداية بعد تاريخ النهاية.');

  // المقارنة بالنص شغّالة لأن الصيغة سنة-شهر-يوم بتترتّب صح أبجديًا
  const days = Math.round(
    (Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000,
  );
  if (days > MAX_DAYS) throw Errors.validation('المدة أطول من سنتين. قسّمها لفترات.');

  return { from, to };
}
