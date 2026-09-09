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
 * ⚠⚠ **وفيه استثناء واحد جديد، اقرا سببه:**
 * الرقم القياسي للموديل (`peakQuantity`) **مخزّن**، لأنه
 * مستحيل يتحسب — النظام بيعرف الكمية دلوقتي بس ومفيش تاريخ
 * كميات. الرقم لازم يتكتب لحظة ما يتحقق وإلا يضيع للأبد.
 *
 * والحماية: الكمية الحالية بتتحسب حيّة في كل نداء، والرقم
 * المخزّن بيتقرا وبس.
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
 * ⚠ **و«موديل متوقّف» نفس العيلة دي.** بيسكّت التنبيه، بس
 * بيلغي نفسه لوحده أول ما بضاعة جديدة تدخل المجموعة. يعني
 * الواقع لسه هو الحَكَم، والعلامة بتوصف قرار مش بتناقض بيانات.
 *
 * ══ ⚠ وأربع مصادر للتنبيهات دلوقتي مش واحد ══
 * تنبيهات الرفّ بتتحسب في **قاعدة البيانات** (`fn_alerts`).
 * وحدّ السحب بيتحسب **هنا**. وتكلفة التذاكر الناقصة في دالة
 * مستقلة (`fn_ticket_cost_alerts`). ومخزون الموديلات **هنا**
 * كمان من أرقام خام بترجع من `fn_model_stock_groups`.
 *
 * ليه التفريق؟ نفس السبب في كل مرة — فخ ٧: قبل أي تعديل على
 * دالة، دوّر على كل نسخها الأول. `fn_alerts` شغّالة، وتعديلها
 * عشان استعلام مختلف تمامًا مخاطرة بلا عائد.
 *
 * ⚠ التمن: أربع مصادر لازم يفضلوا متطابقين في الشكل. الحماية
 * إنهم بيخرجوا من **مخرج واحد** هو الدالة دي، وبنفس النوع
 * `AlertRow`.
 */

import { Errors } from '../../domain/errors';
import { PERMISSIONS } from '../../domain/permissions';
import type {
  AlertRepository,
  AlertRow,
  AlertSeverity,
  AuditLogger,
  AuthenticatedUser,
  Clock,
  ModelStockAlert,
  ModelStockGroup,
  ModelStockRepository,
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
  /** ⚠ اتضافت لتنبيه المخزون بالموديل — مايجريشن ٦١ */
  modelStock: ModelStockRepository;
  clock: Clock;
  /**
   * ⚠ اتضاف عشان أزرار التصفير والإيقاف.
   *
   * القراءة مش محتاجة سجل، لكن الاتنين دول **قرارات** بتغيّر
   * سلوك التنبيه. قرار بلا سجل معناه إن حد سكّت تنبيه ومحدش
   * يعرف مين ولا إمتى.
   */
  audit?: AuditLogger;
}

// ═══════════════════ قاعدة النسبة ═══════════════════

/**
 * النسبة اللي تحتها التنبيه بيرنّ.
 *
 * ══ ⚠ الرقم ده مكتوب هنا **بس** ══
 * لا في SQL ولا في الشاشة ولا في الشرح. الدالة الوحيدة اللي
 * بتقارن هي `modelStockView` تحت، وكل حاجة تانية بتقرا منها.
 *
 * لو اتكتب في مكانين، هيختلفوا يوم ما — وساعتها الشاشة تقول
 * "قرّب" والتنبيه ساكت، أو العكس.
 *
 * ⚠ نفس ترتيب حدّ السحب في `treasury.ts` بالحرف. النسبة هناك
 * ٢٠٪ كمان وبالصدفة — مش نفس القرار، فما تربطهمش.
 */
const LOW_MODEL_RATIO = 0.2;

/**
 * حالة مجموعة مخزون.
 *
 * ══ الحالات التلاتة ══
 *   'OK'     الكمية فوق النسبة — مفيش تنبيه
 *   'NEAR'   الكمية عند النسبة أو تحتها، وأكبر من صفر
 *   'EMPTY'  صفر — خلص خالص
 *
 * ⚠ **الصفر حالة مستقلة مش أقصى درجة من NEAR.** "باقي واحد"
 * تصرّف، و"مفيش خالص" واقع تاني: الزبون بيدخل ويطلع.
 *
 * ══ ⚠ والرقم القياسي صفر معناه "لسه مافيش تاريخ" ══
 * مجموعة اتعملت لسه وما دخلهاش بضاعة. مفيش مقام، فمفيش نسبة،
 * فمفيش تنبيه. تنبيه على مجموعة عمرها ما شافت بضاعة كان هيبقى
 * ضجيج من أول يوم.
 *
 * ⚠ لاحظ إن الدالة دي **مفيهاش أي وصول لقاعدة بيانات**. حساب
 * صافي على رقمين — فممكن تتجرّب بالورقة والقلم.
 */
export function modelStockView(
  currentQuantity: number,
  peakQuantity: number,
): { state: 'OK' | 'NEAR' | 'EMPTY'; threshold: number } {
  // ⚠ العتبة بتتقرّب لفوق: ٢٠٪ من ٣ = ٠.٦، والتقريب لتحت كان
  // هيدّي صفر — يعني التنبيه ما يرنّش أبدًا على موديل قليل.
  // القاعدة: على الأقل قطعة واحدة طول ما فيه رقم قياسي.
  const threshold = peakQuantity > 0 ? Math.max(1, Math.ceil(peakQuantity * LOW_MODEL_RATIO)) : 0;

  if (peakQuantity <= 0) return { state: 'OK', threshold };
  if (currentQuantity <= 0) return { state: 'EMPTY', threshold };
  if (currentQuantity <= threshold) return { state: 'NEAR', threshold };

  return { state: 'OK', threshold };
}

/**
 * اسم الدرج المعروض.
 *
 * ══ 🔴 ليه ده موجود أصلاً ══
 * «درج الآيفون» و«درج الأندرويد» **مش أدراج مخزّنة** في
 * القاعدة. الجهاز مالوش `category_id` خالص — درجه محسوب من
 * عيلة موديله.
 *
 * ملف ٦١ ما كانش عارف ده وجمّع بالدرج المخزّن، فكل الأجهزة
 * وقعت برّه التنبيه. الملف ده والمايجريشن ٦٣ بيصلّحوا ده.
 *
 * ⚠ والتركيب هنا **مكان واحد**: الشاشة والتنبيه والإشعار كلهم
 * بيقروا منه. لو اتكرر، «درج الآيفون» تبقى «الآيفون» في مكان
 * و«أجهزة آيفون» في مكان.
 */
export function drawerLabel(group: ModelStockGroup): string {
  if (group.drawerKey === 'DEVICE') {
    if (group.modelFamily === 'IPHONE') return 'درج الآيفون';
    if (group.modelFamily === 'ANDROID') return 'درج الأندرويد';
    // ⚠ موديل بلا عيلة: موجود وبيتجمّع، بس مالوش درج معروف.
    // اسم صريح أحسن من حشره في درج غلط.
    return 'أجهزة بلا عيلة';
  }

  if (group.drawerKey === 'NOCAT') return 'إكسسوار بلا درج';

  // ⚠ الدرج اتمسح بعد ما المجموعة اتكوّنت. بنقول كده صراحةً
  // بدل ما نسيب الاسم فاضي — السطر الفاضي بيبان كعطل عرض.
  return group.drawerName ?? 'درج محذوف';
}

/** نص التنبيه. مكان واحد عشان الشاشة والإشعار يقولوا نفس الكلام. */
export function modelStockMessage(group: ModelStockGroup, state: 'NEAR' | 'EMPTY'): string {
  const place = `${drawerLabel(group)} · ${group.modelName}`;

  if (state === 'EMPTY') {
    return `${place} — خلص خالص في ${group.branchName}.`;
  }

  return `${place} — باقي ${group.currentQuantity} من ${group.peakQuantity} في ${group.branchName}.`;
}

/**
 * ⚠ المفتاح المركّب.
 *
 * `AlertRow.entityId` حقل واحد، والمجموعة تلات معرّفات. الشريط
 * وسكربت الإشعارات بيميّزوا التنبيه بـ`alertType + ':' + entityId`
 * — فالمفتاح لازم يكون فريد ومستقر.
 *
 * ⚠ ولو حد احتاج المعرّفات مفكوكة، ما يفكّش النص ده. `modelStock`
 * في الرد فيه الحقول جاهزة.
 */
function groupKey(group: ModelStockGroup): string {
  return `${group.branchId}|${group.drawerKey}|${group.modelId}`;
}

export interface AlertSummary {
  rows: AlertRow[];
  highCount: number;
  totalCount: number;
  /**
   * ⚠ نفس بيانات صفوف `MODEL_LOW_STOCK` بالظبط، بشكل تاني.
   *
   * الشاشة محتاجة معرّفات المجموعة عشان أزرار التصفير
   * والإيقاف، و`AlertRow` مالوش مكان ليها. والاتنين بيتولدوا
   * من **نفس النداء** فمستحيل يختلفوا.
   */
  modelStock: ModelStockAlert[];
  /**
   * أصناف بلا درج أو بلا موديل — بره الحساب تمامًا.
   *
   * ⚠ الرقم ده لازم يوصل للشاشة. البضاعة دي مستحيل تتجمّع
   * فمستحيل تتنبّه، والصمت هنا كان هيخلّي المستخدم فاكر إن كل
   * حاجة محروسة.
   */
  unassignedCount: number;
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

  const rawStockRows = await deps.alerts.list(actor.tenantId, branchId);

  // ══ ⚠ فلترة `LOW_STOCK` — اقرا ده قبل ما تشيلها ══
  //
  // `fn_alerts` لسه بترجّع تنبيه المخزون القديم، اللي بيبصّ على
  // **السطر الواحد**. الجهاز كميته ١ وبتبقى صفر بعد البيع، فكان
  // بيرنّ على كل بيعة ناجحة.
  //
  // ⚠ والدالة **ما اتلمستش** عن قصد — فخ ٧: `create or replace`
  // بمعاملات مختلفة بيعمل دالة تانية، والتطبيق ينادي القديمة.
  // ودي دالة شغّالة بتحسب حاجات تانية كمان (الرفّ).
  //
  // فالإيقاف بقى سطر واحد هنا، والرجوع عنه شيل السطر ده.
  //
  // ⚠ التمن: استعلام بيرجّع صفوف بنرميها. مقبول — المكسب إننا
  // ما لمسناش دالة مش شايفينها عشان قرار قابل للرجوع.
  const stockRows = rawStockRows.filter((r) => r.alertType !== 'LOW_STOCK');

  const treasuryRows = await overdraftAlerts(deps, actor, branchId);
  const costRows = await ticketCostAlertRows(deps, actor.tenantId, branchId);
  const model = await modelStockAlerts(deps, actor.tenantId, branchId);

  // ⚠ الترتيب هو الرسالة.
  //
  //   الخزنة    مسألة النهاردة — رصيد تحت الحد
  //   التكلفة   مسألة فلوس ضايعة — الورشة طالبة ومحدش فاكر كام
  //   الموديل   مسألة البيع — موديل قرّب يخلص أو خلص
  //   الرفّ     مسألة الأسبوع
  const rows = [...treasuryRows, ...costRows, ...model.rows, ...stockRows];

  return {
    rows,
    highCount: rows.filter((r) => r.severity === 'HIGH').length,
    totalCount: rows.length,
    modelStock: model.detail,
    unassignedCount: model.unassignedCount,
  };
}

/**
 * تنبيهات مخزون الموديلات.
 *
 * ⚠ الدالة دي بتاخد **أرقام خام** من القاعدة وبتقرر هنا. مفيش
 * أي نسبة ولا مقارنة في SQL — كلها في `modelStockView`.
 *
 * ⚠ والمجموعة المتوقّفة بتتشال من التنبيه بس **مش** من الرد:
 * الشاشة محتاجة تعرضها عشان تقدر ترجّعها. الفرق بين "مش
 * موجودة" و"موجودة وساكتة" هو الفرق بين قرار تقدر تلغيه وقرار
 * ضاع.
 */
async function modelStockAlerts(
  deps: AlertDeps,
  tenantId: string,
  branchId: string | null,
): Promise<{ rows: AlertRow[]; detail: ModelStockAlert[]; unassignedCount: number }> {
  // ⚠ فشل التنبيه ما يوقّعش الشاشة كلها — نفس منطق الخزنة تحت.
  let groups: ModelStockGroup[];
  let unassignedCount: number;
  try {
    [groups, unassignedCount] = await Promise.all([
      deps.modelStock.groups(tenantId, branchId),
      deps.modelStock.unassignedCount(tenantId, branchId),
    ]);
  } catch {
    return { rows: [], detail: [], unassignedCount: 0 };
  }

  const rows: AlertRow[] = [];
  const detail: ModelStockAlert[] = [];

  for (const group of groups) {
    if (group.discontinued) continue;

    const view = modelStockView(group.currentQuantity, group.peakQuantity);
    if (view.state === 'OK') continue;

    // خلص خالص مسألة دلوقتي، وقرّب مسألة الأيام الجاية
    const severity: AlertSeverity = view.state === 'EMPTY' ? 'HIGH' : 'MEDIUM';
    const message = modelStockMessage(group, view.state);

    rows.push({
      alertType: 'MODEL_LOW_STOCK',
      severity,
      entityId: groupKey(group),
      title: view.state === 'EMPTY' ? 'موديل خلص' : 'موديل قرّب يخلص',
      detail: message,
      // ⚠ المتري هو الكمية الباقية. الترتيب بيخلّي الفاضي فوق.
      metric: group.currentQuantity,
    });

    detail.push({
      branchId: group.branchId,
      branchName: group.branchName,
      drawerKey: group.drawerKey,
      drawerLabel: drawerLabel(group),
      modelId: group.modelId,
      modelName: group.modelName,
      currentQuantity: group.currentQuantity,
      peakQuantity: group.peakQuantity,
      state: view.state,
      severity,
    });
  }

  // الأقل أول: الفاضي فوق، وبعده الأقرب للفضا
  rows.sort((a, b) => a.metric - b.metric);
  detail.sort((a, b) => a.currentQuantity - b.currentQuantity);

  return { rows, detail, unassignedCount };
}

// ═══════════════════ قرارات المستخدم ═══════════════════

/**
 * صلاحية تغيير سلوك التنبيه.
 *
 * ⚠ `inventory.reorder_point` — صاحب المحل وحده.
 *
 * السبب مكتوب في كتالوج الصلاحيات: تعديل **الكمية** عملية
 * يومية، لكن تحديد **الحد** قرار سياسة. وتصفير الرقم القياسي
 * أو إيقاف موديل هما بالظبط تحديد حد.
 *
 * ⚠ ولو المندوب قدر يسكّت تنبيه، التنبيه بيبقى بلا معنى:
 * اللي بيتضايق من الرنّة هو اللي هيطفيها.
 */
function assertStockPolicy(actor: AuthenticatedUser): void {
  if (actor.roleKey === 'PLATFORM_ADMIN') {
    throw Errors.forbidden('platform admin has no shop data access');
  }
  if (!actor.permissions.includes(PERMISSIONS.INVENTORY_REORDER_POINT)) {
    throw Errors.forbidden(PERMISSIONS.INVENTORY_REORDER_POINT);
  }
}

/**
 * ⚠ حاجز الفرع.
 *
 * صاحب المحل عنده الصلاحية دي، وهو اللي مالوش فرع — فبيعدّي.
 * أي حد تاني معاه الصلاحية باستثناء فردي محبوس في فرعه.
 *
 * fail-closed: مالوش فرع؟ ما يعملش حاجة.
 */
function assertGroupScope(actor: AuthenticatedUser, branchId: string): void {
  if (actor.roleKey === 'SUPER_ADMIN') return;
  if (!actor.branchId) throw Errors.forbidden('branch scope');
  if (branchId !== actor.branchId) throw Errors.forbidden('branch scope');
}

export interface ModelStockTarget {
  branchId: string;
  /**
   * ⚠ مفتاح الدرج مش معرّف درج: 'DEVICE' للأجهزة، 'NOCAT'
   * للإكسسوار بلا درج، وغير كده معرّف حقيقي.
   */
  drawerKey: string;
  modelId: string;
}

function readTarget(input: Partial<ModelStockTarget>): ModelStockTarget {
  const branchId = String(input.branchId ?? '').trim();
  const drawerKey = String(input.drawerKey ?? '').trim();
  const modelId = String(input.modelId ?? '').trim();

  // ⚠ رسالة صريحة لكل واحد. "بيانات ناقصة" بتخلّيك تدوّر.
  if (!branchId) throw Errors.validation('الفرع مفقود.');
  if (!drawerKey) throw Errors.validation('الدرج مفقود.');
  if (!modelId) throw Errors.validation('الموديل مفقود.');

  return { branchId, drawerKey, modelId };
}

/**
 * تصفير الرقم القياسي على الكمية الحالية.
 *
 * ══ إمتى تستخدمه؟ ══
 * لما تكون غيّرت سياستك: كنت بتشيل ٥٠ جراب وقرّرت تشيل ٥ بس.
 * الرقم القياسي ٥٠ هيفضل يرنّ عند ١٠ للأبد، والرنّة دي غلط —
 * إنت مش ناقص، إنت غيّرت رأيك.
 *
 * ⚠ التصفير التلقائي (عند أول توريد بعد الصفر) بيمسك الغالبية
 * لوحده. الزرار ده للحالة اللي هو أعمى عنها: الموديل اللي عمره
 * ما بيوصل صفر.
 */
export async function resetModelPeak(
  deps: AlertDeps,
  actor: AuthenticatedUser,
  input: Partial<ModelStockTarget>,
): Promise<{ peakQuantity: number }> {
  assertStockPolicy(actor);
  const target = readTarget(input);
  assertGroupScope(actor, target.branchId);

  const peakQuantity = await deps.modelStock.resetPeak(
    actor.tenantId,
    target.branchId,
    target.drawerKey,
    target.modelId,
  );

  await deps.audit?.record({
    actorId: actor.id,
    action: 'model_stock.reset_peak',
    entity: 'ModelStockPeak',
    entityId: `${target.branchId}|${target.drawerKey}|${target.modelId}`,
    metadata: { ...target, peakQuantity, tenantId: actor.tenantId },
  });

  return { peakQuantity };
}

/**
 * إيقاف أو تشغيل موديل.
 *
 * ⚠ الوحدة هي **المجموعة** مش الموديل. توقيف «جرابات ١٥ برو
 * ماكس» مش بيوقّف «أجهزة ١٥ برو ماكس» — دول درجين مختلفين
 * وقرارين مختلفين.
 *
 * ⚠ اللي بتخسره: بطّلت الموديل خالص؟ هتضغط الزرار مرة لكل درج.
 * والمكسب إن قرار الجرابات ما بيسكّتش تنبيه الأجهزة بالغلط.
 *
 * ⚠ والعلامة بتلغي نفسها في القاعدة أول ما بضاعة تدخل المجموعة
 * (مايجريشن ٦١، القسم ٣). فمفيش موديل ساكت وهو موجود.
 */
export async function setModelDiscontinued(
  deps: AlertDeps,
  actor: AuthenticatedUser,
  input: Partial<ModelStockTarget>,
  value: boolean,
): Promise<void> {
  assertStockPolicy(actor);
  const target = readTarget(input);
  assertGroupScope(actor, target.branchId);

  await deps.modelStock.setDiscontinued(
    actor.tenantId,
    target.branchId,
    target.drawerKey,
    target.modelId,
    value,
    deps.clock.now(),
  );

  await deps.audit?.record({
    actorId: actor.id,
    action: value ? 'model_stock.discontinue' : 'model_stock.resume',
    entity: 'ModelStockPeak',
    entityId: `${target.branchId}|${target.drawerKey}|${target.modelId}`,
    metadata: { ...target, tenantId: actor.tenantId },
  });
}

// ═══════════════════ المصادر التانية ═══════════════════

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
