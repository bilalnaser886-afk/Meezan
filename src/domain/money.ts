/**
 * الفلوس
 *
 * ══ القاعدة ══
 * كل مبلغ في النظام **رقم صحيح بالقرش**. مفيش كسور عشرية خالص
 * في أي حساب. القسمة على 100 بتحصل وقت العرض بس.
 *
 *     150.75 جنيه  →  15075 قرش
 *
 * ══ ليه؟ ══
 * الكمبيوتر ما بيعرفش يمثّل 0.1 بدقة. جرّب تجمع 0.1 ألف مرة
 * وهتطلعلك 99.9999999999986 بدل 100.
 *
 * مرة واحدة مش مشكلة. لكن بعد ألف فاتورة الفروق بتتراكم،
 * وتقعد تدوّر على قرش مش موجود أصلاً — وميزانيتك ما بتقفلش.
 *
 * تشبيه: بدل ما تقيس بالمتر وتقرّب لأقرب سنتيمتر كل مرة، بتقيس
 * بالسنتيمتر من الأول. الرقم صحيح والتقريب مالوش مكان.
 */

/** أقصى مبلغ مسموح في حركة واحدة: 100 مليون جنيه. حارس ضد صفر زيادة بالغلط. */
const MAX_PIASTRES = 10_000_000_000;

/** أقصى عدد وحدات في خانة واحدة. حارس زي اللي فوق بالظبط. */
const MAX_COUNT = 1_000_000;

/**
 * تحويل الأرقام العربية الهندية (٠١٢٣) لأرقام إنجليزية.
 * لوحة المفاتيح العربية على الموبايل بتكتب بيها افتراضيًا، ولو
 * مرجّعناهاش المستخدم هيكتب رقم صح والنظام يقوله "غير صالح".
 *
 * ⚠ مُصدَّرة عشان أي حقل رقمي في النظام يستخدم نفس التطبيع.
 * لو اتكررت في مكان تاني، هيبقى عندنا شاشة بتقبل ٥ وشاشة بترفضها.
 */
export function normalizeDigits(input: string): string {
  return input
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0))
    .replace(/[٫،]/g, '.'); // الفاصلة العشرية العربية
}

export class MoneyError extends Error {}

/**
 * تحويل ما كتبه المستخدم إلى قروش.
 * بترمي MoneyError برسالة عربية جاهزة للعرض لو المدخل غلط.
 */
export function parseMoneyToPiastres(raw: string): number {
  const cleaned = normalizeDigits(String(raw ?? ''))
    .replace(/[\s,_]/g, '') // مسافات وفواصل الآلاف
    .trim();

  if (!cleaned) throw new MoneyError('اكتب المبلغ.');

  // رقم موجب، بحد أقصى منزلتين عشريتين
  const match = /^(\d+)(?:\.(\d{1,2}))?$/.exec(cleaned);
  if (!match) {
    if (/^-/.test(cleaned)) {
      // المبلغ السالب مرفوض عن قصد: الاتجاه (دخل/خرج) هو اللي
      // بيحمل الإشارة، مش المبلغ. ده بيمنع مصروف بمبلغ سالب
      // بيزوّد الرصيد بالغلط.
      throw new MoneyError('يجب أن يكون المبلغ موجبًا. حدّد نوع الحركة لتعيين الدخل أو الخرج.');
    }
    if (/\.\d{3,}$/.test(cleaned)) {
      throw new MoneyError('المبلغ بمنزلتين عشريتين كحد أقصى. مثال: 150.75');
    }
    throw new MoneyError('صيغة المبلغ غير صحيحة. اكتب رقمًا مثل 150 أو 150.75');
  }

  const pounds = Number.parseInt(match[1], 10);
  // "150.5" معناها 50 قرش مش 5 — فبنكمّل الخانة الناقصة
  const piastres = Number.parseInt((match[2] ?? '0').padEnd(2, '0'), 10);

  const total = pounds * 100 + piastres;

  if (total <= 0) throw new MoneyError('يجب أن يكون المبلغ أكبر من صفر.');
  if (total > MAX_PIASTRES) throw new MoneyError('المبلغ أكبر من الحد المسموح.');

  return total;
}

/**
 * التكلفة — زي المبلغ بالظبط، بس **الصفر مقبول**.
 *
 * ══ ليه دالة منفصلة؟ ══
 * `parseMoneyToPiastres` بترفض الصفر عن قصد، لأنها متعمّلة
 * للحركات المالية اللي مبلغها لازم يكون موجب (مفيش مصروف بصفر).
 *
 * لكن تكلفة المنتج ممكن تكون صفر فعلاً: عيّنة، هدية من المورّد،
 * أو حاجة لسه ما اتسعّرتش. ولو أجبرنا المستخدم يكتب رقم موجب،
 * هيكتب قرش واحد عشان يعدّي — وده تلويث للبيانات أسوأ من الصفر.
 *
 * تشبيه: خانة "المبلغ المدفوع" في إيصال لازم تكون موجبة.
 * خانة "الخصم" ممكن تكون صفر بشكل طبيعي تمامًا.
 */
export function parseCostToPiastres(raw: string | null | undefined): number {
  const text = String(raw ?? '').trim();
  if (!text) return 0; // فاضية = صفر، من غير ما نزعّق للمستخدم

  const cleaned = normalizeDigits(text)
    .replace(/[\s,_]/g, '')
    .trim();

  // بنمسك الصفر بكل أشكاله (0 · 0.0 · 00.00) قبل الدالة العامة
  if (/^0*(?:\.0{1,2})?$/.test(cleaned)) return 0;

  return parseMoneyToPiastres(text);
}

/**
 * قراءة عدد صحيح من مدخل المستخدم (كمية، عدد وحدات).
 *
 * `allowNegative` بتتفتح للجرد بس: المدير ممكن يخصم كمية تالفة،
 * لكن الكاشير عمره ما يبيع كمية سالبة.
 */
export function parseCount(raw: unknown, options: { allowNegative?: boolean } = {}): number {
  const cleaned = normalizeDigits(String(raw ?? ''))
    .replace(/[\s,_]/g, '')
    .trim();

  if (!cleaned) throw new MoneyError('اكتب الكمية.');

  const pattern = options.allowNegative ? /^-?\d+$/ : /^\d+$/;
  if (!pattern.test(cleaned)) {
    throw new MoneyError(
      options.allowNegative
        ? 'يجب أن تكون الكمية رقمًا صحيحًا، والسالب للخصم.'
        : 'يجب أن تكون الكمية رقمًا صحيحًا غير سالب.',
    );
  }

  const value = Number.parseInt(cleaned, 10);
  if (!Number.isSafeInteger(value)) throw new MoneyError('الكمية غير صالحة.');
  if (Math.abs(value) > MAX_COUNT) throw new MoneyError('الكمية أكبر من الحد المسموح.');

  return value;
}

/** عرض القروش كنص للمستخدم: 15075 → "150.75" */
export function formatPiastres(piastres: number): string {
  const negative = piastres < 0;
  const abs = Math.abs(Math.trunc(piastres));

  const pounds = Math.floor(abs / 100);
  const rest = abs % 100;

  const grouped = pounds.toLocaleString('en-US'); // فواصل الآلاف
  return `${negative ? '-' : ''}${grouped}.${String(rest).padStart(2, '0')}`;
}

/** عرض مع العملة: 15075 → "150.75 ج.م" */
export function formatMoney(piastres: number): string {
  return `${formatPiastres(piastres)} ج.م`;
}
