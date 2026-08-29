/**
 * صفحات الواجهة
 *
 * ══ ليه من غير JSX؟ ══
 * JSX محتاج إعدادات تحويل في خطوة البناء. على Cloudflare Pages
 * البناء بيحصل على سيرفرهم، ولو الإعداد ده ما اتقراش صح، البناء
 * بيقع — وإنت على الموبايل مش هتقدر تصلّحه.
 *
 * فبنستخدم قوالب نصّية عادية. صفر إعدادات، مستحيل تقع.
 * تشبيه: بدل جهاز محتاج معايرة قبل كل استخدام، بنستخدم دمبل.
 *
 * ══ حاجة مهمة عن الأمان ══
 * الدالة `html` بتهرّب أي قيمة بتحطّها جوّه ${...} تلقائياً.
 * يعني لو مالك كتب في إعلان <script>...</script>، هيظهر كنص
 * مش هيتنفّذ. ده بيقفل ثغرة XSS.
 * و `raw()` بتلغي الحماية دي — فمش بنستخدمها إلا مع كود إحنا
 * كاتبينه بإيدينا (الـ CSS والـ JS تحت).
 */

import { html, raw } from 'hono/html';
import type { HtmlEscapedString } from 'hono/utils/html';
import { BASE_CSS } from './styles';
import { formatDate } from '../domain/dates';
import { PWA_REGISTER_JS } from './icons';
import { formatPiastres } from '../domain/money';
import {
  TREASURY_TYPE_LABELS,
  treasuryLabel,
} from '../application/use-cases/treasury';


/**
 * كود الخمول وقفل الشاشة — مشترك بين لوحة التحكم والخزينة.
 *
 * ليه مستخرج؟ لأنه كان هيتكرر في صفحتين. ولو اتكرر، أول تعديل
 * على واحدة وهنسيان التانية بيعمل سلوك مختلف بين شاشتين في نفس
 * النظام — وده أسوأ من كود أطول.
 *
 * العلامات __IDLE__ و __WARN__ و __ACTION__ بتتبدّل وقت التوليد.
 */
/**
 * الطباعة والباركود — مشترك بين كل الصفحات
 *
 * ══ ليه مفيش مكتبة؟ ══
 * المشروع مفيهوش خطوة بناء للمتصفح: الصفحات نصوص في `pages.ts`
 * والجافاسكربت جوّاها كما هو. أي مكتبة معناها وسم `<script>`
 * من CDN — يعني **اعتماد خارجي وقت التشغيل**.
 *
 * ولو الـCDN وقع أو نت المحل تعب، الكاشير ما يقدرش يطبع فاتورة.
 * ده تمن غالي لحاجة نقدر نكتبها في ٤٠ سطر.
 *
 * ══ Code 39 ══
 * كل حرف = ٩ عناصر (٥ خطوط و٤ مسافات)، تلاتة منهم عريضة.
 * الجدول تحت هو المعيار نفسه، و`n` ضيّق و`w` عريض.
 *
 * اخترناه على Code 128 لأن جدوله ٤٤ مدخل بدل ١٠٧، وكل ماسح في
 * الدنيا بيقراه. الوحيد اللي بيخسره إن الملصق بيطلع أعرض شوية.
 *
 * ══ والطباعة بحاوية مخفية مش نافذة جديدة ══
 * `window.open` بيتمنع في سفاري على الأيفون وفي وضع التطبيق
 * المثبّت. الحاوية المخفية بتشتغل في كل مكان.
 */
const PRINT_SHARED_JS = `
(function () {
  var C39 = {
    '0':'nnnwwnwnn','1':'wnnwnnnnw','2':'nnwwnnnnw','3':'wnwwnnnnn',
    '4':'nnnwwnnnw','5':'wnnwwnnnn','6':'nnwwwnnnn','7':'nnnwnnwnw',
    '8':'wnnwnnwnn','9':'nnwwnnwnn','A':'wnnnnwnnw','B':'nnwnnwnnw',
    'C':'wnwnnwnnn','D':'nnnnwwnnw','E':'wnnnwwnnn','F':'nnwnwwnnn',
    'G':'nnnnnwwnw','H':'wnnnnwwnn','I':'nnwnnwwnn','J':'nnnnwwwnn',
    'K':'wnnnnnnww','L':'nnwnnnnww','M':'wnwnnnnwn','N':'nnnnwnnww',
    'O':'wnnnwnnwn','P':'nnwnwnnwn','Q':'nnnnnnwww','R':'wnnnnnwwn',
    'S':'nnwnnnwwn','T':'nnnnwnwwn','U':'wwnnnnnnw','V':'nwwnnnnnw',
    'W':'wwwnnnnnn','X':'nwnnwnnnw','Y':'wwnnwnnnn','Z':'nwwnwnnnn',
    '-':'nwnnnnwnw','.':'wwnnnnwnn',' ':'nwwnnnwnn','$':'nwnwnwnnn',
    '/':'nwnwnnnwn','+':'nwnnnwnwn','%':'nnnwnwnwn','*':'nwnnwnwnn'
  };

  // بيرسم الباركود كـ SVG. مفيش صور ولا طلبات شبكة.
  window.barcodeSvg = function (value, height) {
    var text = String(value || '').toUpperCase().replace(/[^0-9A-Z\-. $/+%]/g, '');
    if (!text) return '';

    var NARROW = 2, WIDE = 5, GAP = 2;
    height = height || 56;

    var seq = ('*' + text + '*').split('');
    var x = 0, rects = '';

    for (var i = 0; i < seq.length; i++) {
      var pat = C39[seq[i]];
      if (!pat) continue;
      for (var j = 0; j < pat.length; j++) {
        var w = pat[j] === 'w' ? WIDE : NARROW;
        // العناصر الزوجية خطوط والفردية مسافات
        if (j % 2 === 0) {
          rects += '<rect x="' + x + '" y="0" width="' + w + '" height="' + height + '"/>';
        }
        x += w;
      }
      x += GAP;
    }

    return '<svg xmlns="http://www.w3.org/2000/svg" width="100%" viewBox="0 0 ' +
      x + ' ' + height + '" preserveAspectRatio="xMidYMid meet" fill="#000">' +
      rects + '</svg>';
  };

  /**
   * الطباعة: بنحط المحتوى في الحاوية المخفية وننادي print.
   * الـCSS بيخفي باقي الصفحة وقت الطباعة بس.
   */
  window.printHtml = function (inner) {
    var root = document.getElementById('print-root');
    if (!root) return;
    root.innerHTML = inner;
    // مهلة قصيرة عشان المتصفح يرسم المحتوى قبل ما يفتح الحوار
    setTimeout(function () {
      window.print();
      setTimeout(function () { root.innerHTML = ''; }, 400);
    }, 60);
  };

  /**
   * الماسح بالكاميرا.
   *
   * ══ ليه على مرحلتين؟ ══
   * كروم على أندرويد فيه BarcodeDetector مدمج — صفر تحميل.
   * سفاري على الأيفون مالوش، فبنجيب مكتبة **وقت الطلب بس**.
   *
   * يعني اللي على أندرويد ما بيحمّلش حاجة خالص، واللي على
   * الأيفون بيحمّل مرة واحدة أول ما يضغط "مسح" — مش مع كل
   * فتحة صفحة.
   *
   * ⚠ التمن: أول مسحة على الأيفون محتاجة نت. بعدها المتصفح
   * بيخزّن المكتبة بنفسه.
   */
  var zxingReady = null;

  function loadZxing() {
    if (zxingReady) return zxingReady;
    zxingReady = new Promise(function (resolve, reject) {
      var tag = document.createElement('script');
      tag.src = 'https://cdn.jsdelivr.net/npm/@zxing/library@0.21.3/umd/index.min.js';
      tag.onload = function () { resolve(window.ZXing); };
      tag.onerror = function () { reject(new Error('cdn')); };
      document.head.appendChild(tag);
    });
    return zxingReady;
  }

  /**
   * بيفتح الكاميرا ويرجّع الكود المقروء.
   * بيرمي رسالة عربية جاهزة لو فشل.
   */
  window.scanBarcode = async function () {
    var overlay = document.createElement('div');
    overlay.className = 'scan-wrap';
    overlay.innerHTML =
      '<div class="scan-box">' +
        '<video class="scan-video" playsinline muted></video>' +
        '<p class="scan-hint">صوّب الكاميرا على الباركود</p>' +
        '<button class="btn-mini" type="button" data-scan-cancel>إلغاء</button>' +
      '</div>';
    document.body.appendChild(overlay);

    var video = overlay.querySelector('video');
    var stream = null;
    var stopped = false;

    function cleanup() {
      stopped = true;
      if (stream) stream.getTracks().forEach(function (t) { t.stop(); });
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }

    overlay.querySelector('[data-scan-cancel]').addEventListener('click', cleanup);

    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      video.srcObject = stream;
      await video.play();
    } catch (err) {
      cleanup();
      throw new Error('تعذّر فتح الكاميرا. تأكّد من السماح بالوصول إليها.');
    }

    // ─── الطريق الأول: المدمج في المتصفح ───
    if ('BarcodeDetector' in window) {
      try {
        var det = new window.BarcodeDetector({
          formats: ['code_39', 'code_128', 'ean_13', 'ean_8', 'upc_a', 'qr_code']
        });
        return await new Promise(function (resolve, reject) {
          var timer = setInterval(async function () {
            if (stopped) { clearInterval(timer); reject(new Error('أُلغي المسح.')); return; }
            try {
              var found = await det.detect(video);
              if (found && found.length) {
                clearInterval(timer);
                var value = found[0].rawValue;
                cleanup();
                resolve(value);
              }
            } catch (e) { /* إطار مش واضح — نكمّل */ }
          }, 220);
        });
      } catch (e) { /* الصيغ مش مدعومة — بنكمّل للمكتبة */ }
    }

    // ─── الطريق التاني: المكتبة ───
    var ZX;
    try {
      ZX = await loadZxing();
    } catch (e) {
      cleanup();
      throw new Error('تعذّر تحميل الماسح. تأكّد من الاتصال بالإنترنت.');
    }

    return await new Promise(function (resolve, reject) {
      var reader = new ZX.BrowserMultiFormatReader();
      reader.decodeFromVideoElement(video, function (result) {
        if (stopped) { reader.reset(); reject(new Error('أُلغي المسح.')); return; }
        if (result) {
          reader.reset();
          var value = result.getText();
          cleanup();
          resolve(value);
        }
      });
    });
  };

  /**
   * تصدير إكسيل ملوّن — بلا مكتبة.
   *
   * ══ ⚠ ليه مفيش مكتبة؟ ══
   * SheetJS أو ExcelJS حوالي ٩٠٠ كيلو، ومحتاجين CDN — يعني
   * اعتماد خارجي وقت التشغيل زي الباركود بالظبط.
   *
   * ══ والبديل ══
   * إكسل بيفتح **HTML بامتداد .xls** ويقرا التنسيق منه: ألوان
   * وحدود وعرض أعمدة وخطوط. فبنبني جدول HTML عادي ونسمّيه
   * .xls، وإكسل بيفتحه ملوّن ومنظّم.
   *
   * ⚠ التمن الحقيقي: الملف ده **مش xlsx أصلي**. لو فتحته في
   * جوجل شيتس هيشتغل، وفي بعض النسخ القديمة من إكسل بيطلّع
   * تحذير "الامتداد لا يطابق المحتوى" — بتدوس فتح وبيشتغل.
   *
   * ولو احتجت xlsx حقيقي بعدين (معادلات أو تبويبات متعددة)،
   * ساعتها المكتبة تبقى مبرَّرة.
   */
  window.exportXls = function (opts) {
    var G = '#16211D', B = '#B08D3D', L = '#E6E4D8';

    var head = '';
    for (var i = 0; i < opts.columns.length; i++) {
      head += '<th style="background:' + G + ';color:#fff;padding:8px;' +
        'border:1px solid ' + G + ';font-weight:bold">' + opts.columns[i] + '</th>';
    }

    var body = '';
    for (var r = 0; r < opts.rows.length; r++) {
      // تظليل الصفوف الفردية — بيخلّي القراءة أسهل في جدول طويل
      var bg = r % 2 ? '#F7F6EF' : '#FFFFFF';
      body += '<tr>';
      for (var c = 0; c < opts.rows[r].length; c++) {
        var v = opts.rows[r][c];
        var num = typeof v === 'number';
        body += '<td style="background:' + bg + ';padding:6px;border:1px solid ' + L +
          ';text-align:' + (num ? 'left' : 'right') + '">' +
          (v === null || v === undefined ? '' : String(v)) + '</td>';
      }
      body += '</tr>';
    }

    var totalRow = '';
    if (opts.totals) {
      totalRow = '<tr>';
      for (var t = 0; t < opts.totals.length; t++) {
        totalRow += '<td style="background:' + B + ';color:#fff;padding:8px;' +
          'border:1px solid ' + B + ';font-weight:bold">' +
          (opts.totals[t] === null ? '' : String(opts.totals[t])) + '</td>';
      }
      totalRow += '</tr>';
    }

    var html =
      '<html xmlns:x="urn:schemas-microsoft-com:office:excel"><head>' +
      '<meta charset="UTF-8">' +
      '<style>table{border-collapse:collapse;font-family:Arial;font-size:12px}' +
      'td,th{white-space:nowrap}</style></head>' +
      '<body dir="rtl">' +
      '<h3 style="font-family:Arial">' + (opts.title || '') + '</h3>' +
      (opts.subtitle ? '<p style="font-family:Arial;font-size:11px;color:#555">' +
        opts.subtitle + '</p>' : '') +
      '<table><thead><tr>' + head + '</tr></thead>' +
      '<tbody>' + body + totalRow + '</tbody></table></body></html>';

    // ⚠ BOM في أول الملف — من غيره إكسل بيقرا العربي رموز
    var blob = new Blob(['\ufeff' + html], { type: 'application/vnd.ms-excel' });
    var url = URL.createObjectURL(blob);

    var a = document.createElement('a');
    a.href = url;
    a.download = (opts.filename || 'meezan') + '.xls';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };

  /**
   * تصدير PDF ملوّن — بلا مكتبة كمان.
   *
   * بيستخدم نفس حاوية الطباعة، والمستخدم بيختار "حفظ كـPDF"
   * من نافذة الطباعة.
   *
   * ⚠ ودي **أنضف** من أي مكتبة PDF: التنسيق CSS عادي بخطوطك
   * وألوانك، والمتصفح بيرسمه زي ما بيرسم الصفحة بالظبط. مكتبات
   * الـPDF بتحتاج تعيد بناء التنسيق من الأول وبتكسر العربي غالبًا.
   */
  window.exportPdf = function (opts) {
    var head = '';
    for (var i = 0; i < opts.columns.length; i++) {
      head += '<th style="background:#16211D;color:#fff;padding:6px;text-align:right">' +
        opts.columns[i] + '</th>';
    }

    var body = '';
    for (var r = 0; r < opts.rows.length; r++) {
      body += '<tr style="background:' + (r % 2 ? '#F7F6EF' : '#fff') + '">';
      for (var c = 0; c < opts.rows[r].length; c++) {
        var v = opts.rows[r][c];
        body += '<td style="padding:5px;border-bottom:1px solid #E6E4D8">' +
          (v === null || v === undefined ? '' : String(v)) + '</td>';
      }
      body += '</tr>';
    }

    var totals = '';
    if (opts.totals) {
      totals = '<tr style="background:#B08D3D;color:#fff;font-weight:600">';
      for (var t = 0; t < opts.totals.length; t++) {
        totals += '<td style="padding:7px">' +
          (opts.totals[t] === null ? '' : String(opts.totals[t])) + '</td>';
      }
      totals += '</tr>';
    }

    window.printHtml(
      '<div class="pr-doc">' +
        '<div class="pr-head">' +
          '<span class="pr-shop">' + (opts.title || '') + '</span>' +
          '<span>' + (opts.subtitle || '') + '</span>' +
        '</div>' +
        '<table style="width:100%;border-collapse:collapse;font-size:12px">' +
          '<thead><tr>' + head + '</tr></thead>' +
          '<tbody>' + body + totals + '</tbody>' +
        '</table>' +
      '</div>'
    );
  };

  window.printMoney = function (p) {
    var abs = Math.abs(Math.trunc(p || 0));
    return (p < 0 ? '-' : '') + Math.floor(abs / 100).toLocaleString('en-US') +
      '.' + String(abs % 100).padStart(2, '0');
  };
})();
`;

/**
 * الإشعارات
 *
 * ══ ⚠ القرار المعماري — اقراه قبل ما تحكم على الميزة ══
 *
 * الإشعارات دي بتشتغل **والتطبيق مفتوح**. مش وهو مقفول.
 *
 * ══ ليه؟ ══
 * الإشعار وقت الإغلاق (Web Push) محتاج تلات حاجات مالناش عليها:
 *   1) مفاتيح VAPID وجدول اشتراكات
 *   2) **خادم بيبعت** — وكلاودفلير Pages مالهاش مهام دورية،
 *      وpg_cron في سوبابيز ما بيعملش طلبات HTTP إلا بإضافة تانية
 *   3) على الأيفون بيشتغل للتطبيق المثبّت بس (iOS 16.4+)
 *
 * تلات نقط فشل جديدة، عشان إشعار.
 *
 * ══ والحاجة اللي بتخلّي ده كافي ══
 * ده نظام محل: الشاشة مفتوحة على الكاونتر طول اليوم. الإشعار
 * وقت الإغلاق كان هيفيد في المساء بس — واللي بيحصل في المساء
 * هتشوفه الصبح على أي حال.
 *
 * ولو احتجناه بجد بعدين، اللي مبني هنا **بيتوسّع** مش بيتشال:
 * نفس مصدر التنبيهات ونفس الإذن ونفس عامل الخدمة.
 *
 * ══ إذن حقيقي مش خانة تفعيل ══
 * الزرار بيطلب إذن المتصفح فعلاً. لو المستخدم رفض، النظام
 * بيقول له كده صراحةً بدل ما يفضل شكله مفعّل وهو ميّت.
 */
const NOTIFY_SHARED_JS = `
(function () {
  var KEY = 'meezan.notify';
  var SEEN = null;          // أول تحميل ما بينبّهش — بيزرع بس
  var TIMER = null;

  function enabled() {
    try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; }
  }

  window.notifyState = function () {
    if (!('Notification' in window)) return 'UNSUPPORTED';
    if (Notification.permission === 'denied') return 'DENIED';
    if (Notification.permission !== 'granted') return 'ASK';
    return enabled() ? 'ON' : 'OFF';
  };

  /** بيطلب الإذن الحقيقي من المتصفح ويرجّع الحالة الجديدة */
  window.notifyEnable = async function () {
    if (!('Notification' in window)) return 'UNSUPPORTED';

    if (Notification.permission !== 'granted') {
      var res = await Notification.requestPermission();
      if (res !== 'granted') return res === 'denied' ? 'DENIED' : 'ASK';
    }
    try { localStorage.setItem(KEY, '1'); } catch (e) {}
    start();
    return 'ON';
  };

  window.notifyDisable = function () {
    try { localStorage.setItem(KEY, '0'); } catch (e) {}
    if (TIMER) { clearInterval(TIMER); TIMER = null; }
    return 'OFF';
  };

  /**
   * ⚠ بنستخدم عامل الخدمة مش الطريقة المباشرة.
   * كروم على أندرويد بيرفض الطريقة التانية تمامًا.
   */
  async function show(title, body) {
    try {
      var reg = await navigator.serviceWorker.getRegistration();
      if (reg && reg.showNotification) {
        await reg.showNotification(title, {
          body: body,
          icon: '/icons/icon-192.png',
          badge: '/icons/icon-192.png',
          tag: 'meezan-alerts',
          data: { url: '/products' }
        });
        return;
      }
      new Notification(title, { body: body });
    } catch (e) { /* الإشعار مش ضروري لتشغيل النظام */ }
  }

  async function poll() {
    if (!enabled() || Notification.permission !== 'granted') return;

    try {
      var res = await fetch('/api/reports/alerts', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) return;

      var keys = (data.rows || []).map(function (r) {
        return r.alertType + ':' + r.entityId;
      });

      // ⚠ أول تحميل بيزرع القايمة بلا إشعار. من غير كده، أول
      // ما تفتح الشاشة هتاخد إشعار بكل تنبيه قديم عندك.
      if (SEEN === null) { SEEN = keys; return; }

      var fresh = (data.rows || []).filter(function (r) {
        return SEEN.indexOf(r.alertType + ':' + r.entityId) === -1;
      });
      SEEN = keys;
      if (fresh.length === 0) return;

      // إشعار واحد مجمّع مش إشعار لكل صنف — عشرة إشعارات ورا
      // بعض بتتقفل من غير ما تتقرا
      var head = fresh.length === 1
        ? fresh[0].title
        : fresh.length + ' أصناف تحتاج انتباهك';
      var body = fresh.slice(0, 3).map(function (r) { return r.detail; }).join(' · ');

      show(head, body);
    } catch (e) { /* صامت: فشل الإشعار ما يصحّش يظهر للمستخدم */ }
  }

  function start() {
    if (TIMER) return;
    // دقيقتين: أقل من كده ضغط بلا فايدة، وأكتر بيخلّي التنبيه
    // متأخر عن الواقع
    TIMER = setInterval(poll, 120000);
    poll();
  }

  if (enabled()) start();
})();
`;

const IDLE_SHARED_JS = `
(function () {
  var IDLE = __IDLE__, WARN = __WARN__, ACTION = '__ACTION__';

  // ⚠ صفر معناه "ما تقفلش أبدًا" — مش "اقفل حالًا".
  //
  // من غير السطر ده، الحسبة تحت بتبقى:
  //     المتبقّي = 0 − الوقت المنقضي   ←  سالب من أول ثانية
  // فالشاشة بتتقفل فورًا، وكل ما تفتحها تتقفل تاني بعد ثانيتين.
  //
  // الخروج المبكر أوضح من إني أحط شرط جوّه العدّاد: الآلية كلها
  // ما بتشتغلش أصلاً، مش بتشتغل وتتجاهل نفسها كل ثانية.
  if (!IDLE || IDLE <= 0) return;

  var lastActivity = Date.now();
  var locked = false;
  var lockRoot = document.getElementById('lock-root');

  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function (evt) {
    window.addEventListener(evt, function () {
      lastActivity = Date.now();
      if (!locked && idleRoot && idleRoot.innerHTML) idleRoot.innerHTML = '';
    }, { passive: true });
  });

  async function endSession() {
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) {}
    window.location.href = '/login?expired=1';
  }

  function showLock() {
    if (locked || !lockRoot) return;
    locked = true;
    document.body.style.overflow = 'hidden';

    lockRoot.innerHTML =
      '<div class="lock-screen"><div class="lock-card">' +
        '<p class="lock-eyebrow">SCREEN LOCKED</p>' +
        '<h1 class="lock-title">الشاشة مقفولة</h1>' +
        '<p class="lock-who">عملك محفوظ. أدخل كلمة المرور للمتابعة.</p>' +
        '<form id="lkf"><input class="lock-input" id="lkpw" type="password" dir="ltr" ' +
          'autocomplete="current-password" required>' +
          '<button class="lock-btn" id="lkbtn" type="submit">فتح</button></form>' +
        '<p class="lock-error" id="lkerr" role="alert" aria-live="assertive"></p>' +
        '<button class="lock-exit" id="lkout" type="button">تسجيل الخروج بدلًا من ذلك</button>' +
      '</div></div>';

    var pw = document.getElementById('lkpw');
    if (pw) pw.focus();

    document.getElementById('lkf').addEventListener('submit', async function (e) {
      e.preventDefault();
      var b = document.getElementById('lkbtn');
      var er = document.getElementById('lkerr');
      er.textContent = '';
      b.disabled = true;
      b.textContent = 'جارٍ الفتح…';

      try {
        var res = await fetch('/api/auth/unlock', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ password: pw.value })
        });
        var data = await res.json().catch(function () { return null; });

        if (res.ok) {
          // الستارة بتتشال والصفحة زي ما هي — مفيش reload
          locked = false;
          lockRoot.innerHTML = '';
          document.body.style.overflow = '';
          lastActivity = Date.now();
          return;
        }
        er.textContent = (data && data.error && data.error.message) || 'كلمة المرور غير صحيحة.';
        pw.value = '';
        pw.focus();
      } catch (err) {
        er.textContent = 'تعذّر الاتصال بالخادم.';
      } finally {
        b.disabled = false;
        b.textContent = 'فتح';
      }
    });

    document.getElementById('lkout').addEventListener('click', endSession);
  }

  async function lockScreen() {
    try { await fetch('/api/auth/lock', { method: 'POST', credentials: 'same-origin' }); } catch (e) {}
    showLock();
  }

  setInterval(function () {
    if (locked) return;
    var remaining = Math.ceil(IDLE - (Date.now() - lastActivity) / 1000);

    if (remaining <= 0) {
      if (ACTION === 'LOCK') lockScreen(); else endSession();
      return;
    }

    if (!idleRoot) return;
    if (remaining <= WARN) {
      idleRoot.innerHTML =
        '<div class="idle-bar" role="alert" aria-live="assertive">' +
          '<span>' + (ACTION === 'LOCK' ? 'تُغلق الشاشة خلال' : 'يُسجَّل خروجك خلال') + '</span>' +
          '<span class="idle-count">' + remaining + '</span><span>ثانية</span>' +
          '<button class="idle-btn" id="stay" type="button">ما زلت هنا</button>' +
        '</div>';
      var stay = document.getElementById('stay');
      if (stay) stay.addEventListener('click', function () {
        lastActivity = Date.now();
        idleRoot.innerHTML = '';
        fetch('/api/auth/session', { credentials: 'same-origin' });
      });
    } else if (idleRoot.innerHTML) {
      idleRoot.innerHTML = '';
    }
  }, 1000);

  setInterval(async function () {
    if (locked) return;
    if ((Date.now() - lastActivity) / 1000 > IDLE / 2) return;

    try {
      var res = await fetch('/api/auth/session', { credentials: 'same-origin' });
      if (res.status === 423) { showLock(); return; }
      if (res.status === 401) {
        var again = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin' });
        if (!again.ok) window.location.href = '/login?expired=1';
      }
    } catch (e) {}
  }, 60000);

  var out = document.getElementById('logout');
  if (out) out.addEventListener('click', endSession);
})();
`;


/**
 * الخطوط.
 *
 * ⚠ الأوزان المطلوبة هنا لازم تطابق اللي مستخدم فعلاً في
 * ملف الأنماط. كل وزن زيادة = ملف بيتحمّل بلا استخدام.
 *
 *   Reem Kufi      الشعار وحده — وزن واحد
 *   El Messiri     العناوين والأزرار والمبالغ (لمسة الخطاط)
 *   Alexandria     كل النص العادي
 *   JetBrains Mono الأرقام والسريالات وكلمات المرور
 *
 * ⚠ و display=swap مقصودة: النص بيتكتب بخط الجهاز فورًا،
 * وبيتبدّل أول ما الخط يوصل. من غيرها الشاشة بتفضل بيضا مستنية
 * الشبكة — وده أسوأ إحساس ممكن في نظام كاشير.
 */
const FONTS =
  'https://fonts.googleapis.com/css2?family=Reem+Kufi:wght@600&family=El+Messiri:wght@500;600;700&family=Alexandria:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap';

type Html = HtmlEscapedString | Promise<HtmlEscapedString>;

/**
 * ⚠ `tenantName` **إلزامي مش اختياري**، وده مقصود.
 *
 * لو خلّيناه اختياري، أي صفحة جديدة تنساه هتشتغل عادي وعنوانها
 * يطلع ناقص — ومحدش هيلاحظ. وهو إلزامي دلوقتي، فالمترجم بيرفض
 * الصفحة قبل ما تتنشر أصلاً.
 *
 * القيمة `null` معناها "الصفحة دي **فعلاً** مالهاش محل" — الدخول
 * والتأسيس وشاشة المنصّة. يعني قرار مكتوب، مش سهو.
 */
function shell(opts: {
  title: string;
  tenantName: string | null;
  noIndex?: boolean;
  body: Html;
  script: string;
}): Html {
  return html`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<!-- ═══ عنوان التبويب ═══
     اسم المحل جنب اسم الشاشة: "الرئيسية · محل النور".

     ⚠ ودي مش تفصيلة شكلية. لما النظام يتثبّت كتطبيق على
     الكمبيوتر، **عنوان النافذة نفسها** بياخد النص ده — يعني
     العميل بيشوف اسم محله على شريط النافذة زي أي برنامج
     اشتراه. وده اللي بيخلّيه يحس إنه برنامجه هو مش موقع
     بيدخل عليه. -->
<title>${opts.tenantName ? `${opts.title} · ${opts.tenantName}` : opts.title}</title>
${opts.noIndex ? raw('<meta name="robots" content="noindex, nofollow, noarchive">') : ''}

<!-- ═══ التثبيت كتطبيق ═══
     البيان بيخدم أندرويد وويندوز وماك. سفاري على iOS ما بيقراش
     البيان للأيقونة، فبيحتاج apple-touch-icon صراحةً. -->
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#16211D">
<link rel="icon" href="/favicon.png" type="image/png" sizes="64x64">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="ميزان">
<!-- black-translucent بيخلّي الهيدر الأخضر يمتد تحت شريط الحالة
     في iPhone بدل الشريط الأبيض المقطوع -->
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">

<!-- ═══ الإضاءة — قبل أي رسم ═══
     ⚠ السكربت ده لازم يفضل هنا في الرأس ومتزامن.
     لو اتأخر لآخر الصفحة، المتصفح بيرسم الوضع الفاتح الأول
     وبعدين يقلبه — وميض أبيض في وش المستخدم كل تحميل.
     ولو كان في وضع ليلي في أوضة ضلمة، الوميض ده بيوجع فعلاً.

     ⚠ ومكانه بعد وسم theme-color مقصود: بيعدّل لونه، فلازم
     الوسم يكون اتقرا قبله. لسه في الرأس، فلسه قبل أي رسم.

     ══ تلات أوضاع مش اتنين ══
       تلقائي  ← نهاري من 6 الصبح لـ 6 المسا، وليلي غير كده
       نهاري   ← ثابت باختيار المستخدم
       ليلي    ← ثابت باختيار المستخدم

     والتلقائي هو الافتراضي: أي حد ما اختارش حاجة بيمشي عليه.
     أول ما يدوس على الزرار، اختياره بيتسجّل وبيغلب الساعة.

     ══ ⚠ الساعة بتاعة الجهاز مش القاهرة ══
     باقي النظام بيحسب التواريخ بتوقيت القاهرة عشان الفواتير
     تتحط على اليوم الصح. لكن الإضاءة حاجة تانية خالص: لو
     الموبايل بيقول إنها 11 بالليل، يبقى الدنيا ليل **عند اللي
     ماسك الموبايل**. الحكم هنا لساعته هو.

     ══ ⚠ وإعداد النظام (الوضع الليلي في الموبايل) اتشال من
     الحساب عن قصد ══
     كان هو الافتراضي القديم. المشكلة إن ناس كتير بتخلّي
     موبايلها ليلي طول الوقت — وساعتها "التلقائي" ما كانش
     هيوري نهاري أبدًا، وكلمة "تلقائي" تبقى كذب.
     الساعة وحدها هي الحَكَم، وده اللي بيخلّي الوضع متوقّع.

     ⚠ وفيه try حوالين التخزين لأن بعض المتصفحات بتمنعه في
     التصفح الخاص — والإضاءة ما يصحّش تمنع الصفحة من الفتح. -->
<script>
(function(){
  var KEY = 'mz-theme';

  /* ⚠ مقبض التوقيت. عايز الليلي يبدأ بدري في الشتا؟ نزّل
     الرقم التاني. القيم بالساعة على مدار 24. */
  var DAY_FROM = 6, DAY_TO = 18;

  /* الاختيار المسجّل. أي حاجة غير light/dark = تلقائي —
     يعني حتى لو التخزين اتلغى أو القيمة اتلخبطت، بنقع على
     التلقائي مش على شاشة بيضا في نص الليل. */
  function stored(){
    try{
      var v = localStorage.getItem(KEY);
      return (v === 'light' || v === 'dark') ? v : 'auto';
    }catch(e){ return 'auto'; }
  }

  function byClock(){
    var h = new Date().getHours();
    return (h >= DAY_FROM && h < DAY_TO) ? 'light' : 'dark';
  }

  /* اللي معروض فعلاً دلوقتي */
  function effective(){
    var m = stored();
    return m === 'auto' ? byClock() : m;
  }

  function label(){
    var m = stored();
    if(m === 'light') return 'نهاري';
    if(m === 'dark')  return 'ليلي';
    /* ⚠ في التلقائي بنكتب الاتنين: الوضع **والحالة**.
       "تلقائي" لوحدها بتسيب السؤال "طب هو ليه ضلمة دلوقتي؟" */
    return effective() === 'dark' ? 'تلقائي · ليلي' : 'تلقائي · نهاري';
  }

  function paint(){
    var el = document.getElementById('theme-label');
    if(el) el.textContent = label();
  }

  function apply(){
    var e = effective();
    if(e === 'dark') document.documentElement.setAttribute('data-theme','dark');
    else document.documentElement.removeAttribute('data-theme');

    /* ⚠ لون شريط المتصفح بيتغيّر معاه، وإلا هيفضل أخضر فاتح
       فوق شاشة غامقة في أندرويد */
    var meta = document.querySelector('meta[name="theme-color"]');
    if(meta) meta.setAttribute('content', e === 'dark' ? '#0E1613' : '#16211D');

    paint();
  }

  /* الدورة: تلقائي ← نهاري ← ليلي ← تلقائي.
     ⚠ التلقائي جزء من الدورة مش إعداد مدفون في شاشة تانية —
     عشان اللي جرّب يثبّت وضع يقدر يرجّع بضغطتين. */
  function cycle(){
    var m = stored();
    var next = m === 'auto' ? 'light' : (m === 'light' ? 'dark' : 'auto');
    try{ localStorage.setItem(KEY, next); }catch(e){}
    apply();
  }

  apply();

  /* اللافتة بتتكتب تاني لما الصفحة تخلص، لأن الزرار نفسه
     لسه ما اتولدش وقت ما السكربت ده اشتغل */
  document.addEventListener('DOMContentLoaded', paint);

  /* ⚠ الزرار بيتمسك من هنا مش من سكربت القائمة.
     السبب: صفحة المنصّة قائمتها مبنية بشكل تاني خالص، وزرار
     الإضاءة فيها كان **ميّت** لأن سكربت القائمة بيخرج بدري لو
     ما لقاش عنصر اسمه menu. المستمع العام هنا بيخدم أي قائمة
     في أي صفحة، الموجودة والجاية. */
  document.addEventListener('click', function(ev){
    var b = (ev.target && ev.target.closest)
      ? ev.target.closest('[data-action="theme"]') : null;
    if(b) cycle();
  });

  /* ══ الانتقال وإنت فاتح الشاشة ══
     الموظّف ممكن يسيب النظام مفتوح من 5:50 لـ 6:10. من غير
     الفحص ده، الشاشة تفضل نهاري لحد ما يعمل تحديث.
     ⚠ الفحص بيشتغل في التلقائي بس، ولو الوضع ما اتغيّرش
     الدالة ما بتلمسش الصفحة أصلاً. */
  setInterval(function(){ if(stored() === 'auto') apply(); }, 60000);

  /* والموبايل بيوقّف المؤقّتات وهو في الجيب. فأول ما ترجع
     تفتحه، بنفحص فورًا بدل ما تستنى دقيقة. */
  document.addEventListener('visibilitychange', function(){
    if(!document.hidden && stored() === 'auto') apply();
  });
})();
</script>

<!-- ═══ تسخين الاتصال قبل الطلب ═══
     تحميل الخطوط بيمر على سيرفرين: واحد بيدّي ملف التعليمات
     (googleapis) وواحد بيدّي الخطوط نفسها (gstatic).

     كان مفتوح للتاني بس، فالمتصفح كان بيقف يفتح اتصال جديد
     للأول وقت ما يوصله — وفتح الاتصال ده بياخد وقت حقيقي على
     شبكة موبايل.

     تشبيه: بترنّ على الجيم قبل ما تنزل عشان تتأكد إنه فاتح،
     بدل ما تركب وتنزل وتستنى قدّام الباب. -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<style>${raw(BASE_CSS)}</style>
</head>
<body>
${opts.body}
<!-- حاوية الطباعة. مخفية بـ CSS مش بخاصية hidden، لأن القاعدة
     العامة للإخفاء كانت هتمنعها من الظهور وقت الطباعة نفسها. -->
<div id="print-root"></div>
<script>${raw(PRINT_SHARED_JS)}</script>
<script>${raw(NOTIFY_SHARED_JS)}</script>
<script>${raw(opts.script)}</script>
<script>${raw(PWA_REGISTER_JS)}</script>
</body>
</html>`;
}

/** حافّة تمزيق الفاتورة — العنصر المميّز لشاشة الكاشير */
function receiptEdge(): string {
  let path = 'M0 12 L0 6';
  for (let x = 0; x <= 420; x += 10) path += ` L${x} ${x % 20 === 0 ? 0 : 6}`;
  path += ' L420 12 Z';

  return `<svg class="receipt-edge" viewBox="0 0 420 12" preserveAspectRatio="none" aria-hidden="true"><path d="${path}" fill="currentColor"/></svg>`;
}


// ═══════════════════ مكوّنات مشتركة ═══════════════════

/**
 * الشعار — ميزان بخط رفيع.
 *
 * ══ ليه ميزان مرسوم مش حرف أو أيقونة جاهزة؟ ══
 * اسم النظام "ميزان"، ووظيفته الحقيقية إن الأرقام تتوازن: المخزون
 * مع المبيعات، الخزينة مع الحركات، الراتب مع السُلف. الرمز نفسه
 * هو الوعد اللي النظام بيقدّمه.
 *
 * ══ الحركة ══
 * الكفة بتتزن مرة واحدة عند فتح صفحة الدخول، وبعدها تسكن نهائيًا.
 * مفيش أي حركة تانية في النظام كله — الموظّف بيفتح الشاشة دي مرة
 * في اليوم، فالحركة تبقى تحية صباح مش زينة بتتكرر.
 *
 * `animate` بتتفعّل في صفحة الدخول بس. النسخة المصغّرة في الهيدر
 * ساكنة، لأنها بتظهر في كل صفحة والحركة فيها هتبقى إزعاج.
 */
function meezanMark(size: number): string {
  return (
    `<svg class="mark" viewBox="0 0 40 40" width="${size}" height="${size}" ` +
    `aria-hidden="true" focusable="false">` +
    `<g fill="none" stroke="currentColor" stroke-width="1.6" ` +
    `stroke-linecap="round" stroke-linejoin="round">` +
    // العمود والقاعدة — ثابتين
    `<circle cx="20" cy="6.6" r="1.9"/>` +
    `<path d="M20 8.5V31"/>` +
    `<path d="M13.5 31.5h13"/>` +
    // الذراع والكفّتين — دول اللي بيتزنوا
    `<g class="mark-beam">` +
    `<path d="M6 12.5h28"/>` +
    `<path d="M6 12.5v3.4M34 12.5v3.4"/>` +
    `<path d="M1.8 15.9q4.2 6.4 8.4 0M29.8 15.9q4.2 6.4 8.4 0"/>` +
    `</g></g></svg>`
  );
}

/** الشعار الكامل: الرمز + الاسم. لصفحة الدخول. */
function brandLockup(animate: boolean): string {
  return (
    `<span class="brandmark" data-size="lg" data-animate="${animate ? 'true' : 'false'}">` +
    meezanMark(40) +
    `<span class="brandmark-word">ميزان</span>` +
    `</span>`
  );
}

/** الرمز وحده. للهيدر الداخلي — من غير حركة ومن غير اسم. */
function brandGlyph(): string {
  return `<span class="brandmark" data-size="sm">${meezanMark(24)}</span>`;
}

/**
 * ختم الصانع.
 *
 * ══ ليه موجود أصلاً؟ ══
 * الشركات اللي بتبني منتجات لغيرها بتسيب توقيعها **جوّه** المنتج،
 * مش على البوّابة بس. العميل بيشوف اسم محله فوق وبيشوف مين بنى
 * النظام في القدم — والاتنين ما بيتنافسوش لأنهم في مكانين
 * مختلفين وبخطّين مختلفين.
 *
 * ══ ⚠ ومكانه بيتغيّر بالشاشة ══
 * قدم الكعب على الكمبيوتر، وقدم قائمة النقط الثلاث على الموبايل.
 * نفس المكوّن بالحرف، غلاف مختلف — والغلاف هو اللي بيتخفي في
 * الأنماط حسب عرض الشاشة.
 *
 * ⚠ `aria-hidden` مقصودة: ده توقيع بصري، وقارئ الشاشة اللي
 * بيقراه في كل صفحة بيتحوّل لضجيج.
 */
function makerStamp(): string {
  return (
    `<div class="stamp-by" aria-hidden="true">` +
    meezanMark(18) +
    `<span class="stamp-by-word">ميزان</span>` +
    `<span class="stamp-by-note">by Meazan</span>` +
    `</div>`
  );
}

const ROLE_STAMP: Record<string, string> = {
  SUPER_ADMIN: 'المالك',
  BRANCH_MANAGER: 'مدير فرع',
  STAFF: 'مندوب مبيعات',
};

/**
 * الشريط العلوي + قائمة النقط الثلاث.
 *
 * القائمة مبنية على <details> — بتفتح وتقفل بالكيبورد ومن غير
 * أي JavaScript. أبسط حاجة ممكن تقع.
 */
function appBar(opts: {
  fullName: string;
  username: string;
  roleKey: string;
  branchLabel: string | null;
  /**
   * اسم المحل.
   *
   * ⚠ على الكمبيوتر ده بقى **السطر الكبير** في الشريط، واسم
   * الموظّف نزل تحته صغير. السبب: صاحب المحل لما يفتح النظام على
   * مكتبه، أول حاجة تقع عليها عينه المفروض تكون محله هو — مش
   * اسم المستخدم اللي هو عارفه أصلاً.
   *
   * على الموبايل مخفي زي ما كان، والاسم فوق زي ما هو.
   * `null` معناها صفحة مالهاش محل (شاشة المنصّة).
   */
  tenantName?: string | null;
}): Html {
  return html`<header class="app-bar">
  <div class="who" ${opts.tenantName ? raw('data-shop') : ''}>
    ${raw(brandGlyph())}
    <span class="who-stack">
      ${opts.tenantName ? html`<span class="who-shop">${opts.tenantName}</span>` : ''}
      <span class="who-line">
        <span class="who-name">${opts.fullName}</span>
        <span class="stamp" data-role="${opts.roleKey}">${ROLE_STAMP[opts.roleKey] ?? opts.roleKey}</span>
      </span>
    </span>
  </div>

  <details class="menu" id="menu">
    <summary aria-label="القائمة" title="القائمة">⋮</summary>
    <div class="menu-sheet">
      <div class="menu-info">
        <div class="menu-row"><span>اسم المستخدم</span><b>${opts.username}</b></div>
        ${opts.tenantName
          ? html`<div class="menu-row"><span>المحل</span><b>${opts.tenantName}</b></div>`
          : ''}
        ${opts.branchLabel
          ? html`<div class="menu-row"><span>الفرع</span><b>${opts.branchLabel}</b></div>`
          : ''}
      </div>
      <a class="menu-item" href="/customers">بيانات العملاء</a>
      <a class="menu-item" href="/password">تغيير كلمة المرور</a>
      <button class="menu-item" type="button" data-action="theme">
        الإضاءة<span class="menu-note" id="theme-label"></span>
      </button>
      <!-- ⚠ الإشعارات هنا مش على اللوحة، وبنفس شكل الإضاءة بالظبط.

           السبب إنهم **نفس نوع الحاجة**: إعداد بيخصّ الجهاز ده
           وحده، بيتظبط مرة وبعدين بيتنسي. حاجة زي دي مالهاش
           مكان على شاشة بتتفتح كل وردية.

           ⚠ واتشال معاها سطرين الشرح اللي كانوا في اللوحة.
           المكان هنا ما بيستحملهمش، والحالة جنب الاسم بتكفي —
           زي الإضاءة بالظبط. -->
      <button class="menu-item" type="button" id="ntf-btn">
        الإشعارات<span class="menu-note" id="ntf-note"></span>
      </button>
      <button class="menu-item" type="button" data-action="lock">قفل الشاشة</button>
      <button class="menu-item" type="button" data-action="logout" data-danger>تسجيل الخروج</button>
      <div class="menu-stamp">${raw(makerStamp())}</div>
    </div>
  </details>
</header>`;
}

/**
 * الوصول للتبويبات — بيتحسب من الصلاحيات مرة واحدة وبيتمرّر.
 *
 * ⚠ إخفاء التبويب **راحة مش حماية**. أي حد يقدر يكتب /pos في
 * المتصفح. الحراسة الحقيقية في requireAuth على المسار نفسه.
 * إحنا بنخفي عشان الموظّف ما يدوسش على باب مقفول، مش عشان نقفله.
 */
export interface NavAccess {
  showPos: boolean;
  showProducts: boolean;
  showTreasury: boolean;
}

/** الشريط السفلي — إبهامك بيوصله من غير ما تمد إيدك */
function tabBar(active: 'app' | 'pos' | 'products' | 'treasury', access: NavAccess): Html {
  return html`<nav class="tabbar">
  <a href="/app" ${active === 'app' ? raw('aria-current="page"') : ''}>
    <span class="tabbar-icon" aria-hidden="true">▣</span>الرئيسية
  </a>
  ${access.showPos
    ? html`<a href="/pos" ${active === 'pos' ? raw('aria-current="page"') : ''}>
        <span class="tabbar-icon" aria-hidden="true">▤</span>البيع
      </a>`
    : ''}
  ${access.showProducts
    ? html`<a href="/products" ${active === 'products' ? raw('aria-current="page"') : ''}>
        <span class="tabbar-icon" aria-hidden="true">▦</span>المنتجات
      </a>`
    : ''}
  ${access.showTreasury
    ? html`<a href="/treasury" ${active === 'treasury' ? raw('aria-current="page"') : ''}>
        <span class="tabbar-icon" aria-hidden="true">₤</span>الخزينة
      </a>`
    : ''}
  <div class="rail-stamp">${raw(makerStamp())}</div>
</nav>`;
}

/**
 * تحويل أختام الوقت لتوقيت المستخدم **في المتصفح**.
 *
 * ══ ليه مش على الخادم؟ ══
 * كلاودفلير بتشغّل الكود بتوقيت UTC. لو نسّقنا الوقت هناك، الموظّف
 * هيشوف بيعة الساعة 5 مكتوب عليها 3 — وهيفتكر النظام بايظ.
 * المتصفح عارف توقيت الجهاز، فبنبعتله الختم الخام وهو ينسّقه.
 */
const TIME_JS = `
(function () {
  var nodes = document.querySelectorAll('[data-time]');
  for (var i = 0; i < nodes.length; i++) {
    var raw = nodes[i].getAttribute('data-time');
    if (!raw) continue;
    var d = new Date(raw);
    if (isNaN(d.getTime())) continue;
    try {
      nodes[i].textContent = d.toLocaleString('ar-EG', {
        hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short'
      });
    } catch (e) {
      nodes[i].textContent = d.toISOString().slice(11, 16);
    }
  }
})();
`;

/** سكربت القائمة: قفلها لما تدوس بره + أزرار القفل والخروج */
const MENU_JS = `
(function () {
  var menu = document.getElementById('menu');
  if (!menu) return;

  document.addEventListener('click', function (e) {
    if (menu.open && !menu.contains(e.target)) menu.open = false;
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && menu.open) menu.open = false;
  });

  // ══════════ الإضاءة ══════════
  //
  // ⚠ مفيش منطق إضاءة هنا خالص. كله في مبدّل الإضاءة العام
  // في رأس الصفحة — بيمسك الزرار بنفسه، وبيكتب اللافتة،
  // وبيتابع الساعة في الوضع التلقائي.
  //
  // ══ ليه اتنقل من هنا؟ ══
  // كان مكتوب مرتين فعليًا: التطبيق في الرأس والتبديل هنا.
  // والنتيجة إن صفحة المنصّة — اللي قائمتها مبنية بشكل تاني
  // ومالهاش عنصر اسمه menu — كان زرار الإضاءة فيها **ميّت**،
  // لأن السكربت ده بيخرج بدري فوق.
  //
  // مصدر واحد للحقيقة، وبيخدم كل الصفحات.

  menu.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-action]') : null;
    if (!btn) return;

    // ⚠ القايمة بتفضل مفتوحة مع الإضاءة عن قصد — عشان تشوف
    // الفرق وإنت شايف الزرار، وتقدر ترجع بضغطة تانية لو ما
    // عجبكش. التبديل نفسه بيحصل في الرأس.
    if (btn.getAttribute('data-action') === 'theme') return;

    menu.open = false;

    if (btn.getAttribute('data-action') === 'logout') {
      try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (err) {}
      window.location.href = '/login';
      return;
    }

    // قفل يدوي — نفس مسار القفل التلقائي بالظبط
    try { await fetch('/api/auth/lock', { method: 'POST', credentials: 'same-origin' }); } catch (err) {}
    window.location.href = '/locked';
  });

  // ══════════ الإشعارات ══════════
  //
  // ⚠ اتنقل هنا من سكربت اللوحة، والسبب مش تنظيم:
  // اللوحة شاشة واحدة، والقائمة موجودة في **كل** الصفحات. لما
  // العنصر بقى في القائمة، منطقه لازم يبقى في القائمة كمان —
  // وإلا الزرار يظهر في تسع صفحات ويشتغل في واحدة.
  //
  // ⚠ والحالة بتتقرا من المتصفح مش من إعداد عندنا. لو المستخدم
  // رفض الإذن، بنقول له كده صراحةً — بدل ما الزرار يفضل شكله
  // مفعّل وهو ميّت.
  //
  // ⚠ ونص الحالة اتقصّر عن اللوحة القديمة. الجملة الطويلة كانت
  // بتلف في سطرين جنب اسم العنصر وتكسر القائمة.
  (function () {
    var btn  = document.getElementById('ntf-btn');
    var note = document.getElementById('ntf-note');
    if (!btn || !note || typeof window.notifyState !== 'function') return;

    // [نص الحالة, هل الزرار يشتغل؟]
    var TEXT = {
      UNSUPPORTED: ['غير مدعومة', false],
      DENIED: ['مرفوضة من المتصفح', false],
      ASK: ['غير مفعّلة', true],
      OFF: ['موقوفة', true],
      ON: ['تعمل', true]
    };

    function paint() {
      var st = window.notifyState();
      note.textContent = TEXT[st][0];
      btn.disabled = !TEXT[st][1];
      btn.setAttribute('data-st', st);
    }

    // ⚠ القايمة بتفضل مفتوحة زي الإضاءة بالظبط — عشان تشوف
    // الحالة اتغيّرت وإنت شايف الزرار.
    btn.addEventListener('click', async function () {
      if (btn.disabled) return;
      if (btn.getAttribute('data-st') === 'ON') window.notifyDisable();
      else await window.notifyEnable();
      paint();
    });

    paint();
  })();
})();
`;

// ═══════════════════ 1) دخول الموظفين ═══════════════════

/**
 * قرارات التصميم مش زينة — كل واحدة ليها سبب من واقع الكاشير:
 *  - ارتفاع الحقول 56 بكسل: بتتضغط بالإبهام على شاشة لمس قدّام طابور
 *  - تركيز تلقائي على أول حقل: أول حاجة بيعملها الموظف في الوردية
 *  - رسالة خطأ واحدة فوق: مش هنشتّت انتباهه بخمس رسايل
 */
export function loginPage(opts: { expired: boolean }): Html {
  return shell({
    title: 'تسجيل الدخول',
    tenantName: null,
    script: LOGIN_SCRIPT,
    body: html`<main class="counter"><div>
${raw(receiptEdge())}
<div class="counter-card">
  <div class="counter-brand">${raw(brandLockup(true))}</div>
  <h1 class="counter-title">تسجيل الدخول</h1>
  <p class="counter-sub">استخدم بيانات الدخول التي زوّدك بها مدير الفرع.</p>

  ${opts.expired
    ? raw(
        '<div class="alert-box" role="status"><span aria-hidden="true">⏱</span><span>انتهت الجلسة لعدم النشاط. سجّل الدخول للمتابعة.</span></div>',
      )
    : ''}

  <div class="alert-box" id="err" role="alert" hidden>
    <span aria-hidden="true">⚠</span><span id="err-text"></span>
  </div>

  <form id="f" novalidate>
    <div class="field">
      <label class="field-label" for="tenant">كود المحل</label>
      <input class="field-input" id="tenant" type="text" dir="ltr" autocomplete="organization"
        autocapitalize="characters" spellcheck="false" maxlength="32" required autofocus>
      <p class="field-hint">
        كود <b>المحل</b> الذي زوّدتك به الإدارة — وليس كود الفرع.
        هو نفسه لكل فروع المحل وكل موظّفيه.
      </p>
    </div>
    <div class="field">
      <label class="field-label" for="username">اسم المستخدم</label>
      <input class="field-input" id="username" type="text" dir="ltr" autocomplete="username"
        autocapitalize="none" spellcheck="false" maxlength="64" required>
    </div>
    <div class="field">
      <label class="field-label" for="password">كلمة المرور</label>
      <input class="field-input" id="password" type="password" dir="ltr"
        autocomplete="current-password" maxlength="1024" required>
    </div>

    <!-- ⚠ المفتاح التاني لحساب إدارة المنصّة وحده.
         مخفي في قسم قابل للفتح عشان ما يزحمش شاشة بيدخل منها
         عشرات الموظّفين كل يوم ومحدش فيهم محتاجه. -->
    <details class="advanced">
      <summary>دخول الإدارة</summary>
      <div class="field">
        <label class="field-label" for="passkey">المفتاح الثاني</label>
        <input class="field-input" id="passkey" type="password" dir="ltr"
          autocomplete="off" maxlength="512">
        <p class="field-hint">لحساب إدارة المنصّة فقط. اتركه فارغًا في الاستخدام العادي.</p>
      </div>
    </details>

    <button class="btn-primary" id="btn" type="submit">دخول</button>
  </form>

  <div class="counter-foot"><span>الإصدار</span><span>1.0.0</span></div>
</div>
</div></main>`,
  });
}

const LOGIN_SCRIPT = `
(function () {
  var form = document.getElementById('f');
  var btn = document.getElementById('btn');
  var box = document.getElementById('err');
  var text = document.getElementById('err-text');

  function fail(message) {
    text.textContent = message;
    box.hidden = false;
    document.getElementById('password').value = '';
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    box.hidden = true;
    btn.disabled = true;
    btn.textContent = 'جارٍ التحقّق…';

    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          tenantCode: document.getElementById('tenant').value,
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
          adminPasskey: document.getElementById('passkey').value || undefined
        })
      });
      var data = await res.json().catch(function () { return null; });

      if (!res.ok) {
        fail((data && data.error && data.error.message) || 'تعذّر تسجيل الدخول.');
        return;
      }
      window.location.href = (data && data.redirectTo) || '/app';
      return;
    } catch (e) {
      // فشل الشبكة غير رفض الخادم — والرسالة لازم تفرّق بينهم
      fail('تعذّر الاتصال بالخادم. تأكّد من اتصال الجهاز بالشبكة.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'دخول';
    }
  });
})();
`;

// ═══════════════════ 2) بوّابة المالك ═══════════════════

/**
 * لاحظ اللي **مش موجود** هنا عمداً:
 *  - لا شعار ولا اسم نظام (ما نقولش للزائر إيه اللي ورا الباب)
 *  - لا "نسيت كلمة المرور" (مفيش استرجاع ذاتي لحساب المالك)
 *  - لا تلميح لسبب الفشل (كل الأخطاء برسالة واحدة موحّدة)
 *  - لا autocomplete (مفيش حاجة بتتحفظ في المتصفح)
 * الغياب هنا هو الميزة الأمنية نفسها.
 */


// ═══════════════════ 3) الإعداد لمرّة واحدة ═══════════════════

export function setupPage(): Html {
  return shell({
    title: 'الإعداد الأوّلي',
    tenantName: null,
    noIndex: true,
    script: SETUP_SCRIPT,
    body: html`<main class="counter"><div>
${raw(receiptEdge())}
<div class="counter-card">
  <p class="counter-eyebrow">FIRST RUN</p>
  <h1 class="counter-title">إنشاء حساب المالك</h1>
  <p class="counter-sub">
    تعمل هذه الصفحة مرة واحدة فقط. بعد الانتهاء، احذف <code>SETUP_SECRET</code>
    من إعدادات كلاودفلير لتُغلق نفسها تلقائيًا.
  </p>

  <div class="alert-box" id="msg" role="alert" hidden><span id="msg-text"></span></div>

  <form id="f" novalidate>
    <div class="field">
      <label class="field-label" for="setupSecret">سرّ الإعداد</label>
      <input class="field-input" id="setupSecret" name="setupSecret" type="password"
        dir="ltr" autocomplete="off" required>
      <p class="field-hint">القيمة نفسها التي وضعتها في SETUP_SECRET.</p>
    </div>
    <div class="field">
      <label class="field-label" for="username">اسم المستخدم</label>
      <input class="field-input" id="username" name="username" type="text" dir="ltr"
        autocomplete="off" spellcheck="false" maxlength="32" required>
      <p class="field-hint">حروف إنجليزية صغيرة وأرقام، من 3 إلى 32 حرفًا.</p>
    </div>
    <div class="field">
      <label class="field-label" for="fullName">الاسم الكامل</label>
      <input class="field-input" id="fullName" name="fullName" type="text" maxlength="80" required>
    </div>
    <div class="field">
      <label class="field-label" for="password">كلمة المرور</label>
      <input class="field-input" id="password" name="password" type="password" dir="ltr"
        autocomplete="new-password" required>
      <p class="field-hint">12 حرفًا على الأقل.</p>
    </div>
    <div class="field">
      <label class="field-label" for="passkey">المفتاح السرّي الثاني</label>
      <input class="field-input" id="passkey" name="passkey" type="password" dir="ltr"
        autocomplete="new-password" required>
      <p class="field-hint">
        16 حرفًا على الأقل، ويجب أن يختلف تمامًا عن كلمة المرور.
        هذا القفل الثاني على بوّابتك السرّية.
      </p>
    </div>
    <button class="btn-primary" id="btn" type="submit">إنشاء الحساب</button>
  </form>
</div>
</div></main>`,
  });
}

const SETUP_SCRIPT = `
(function () {
  var form = document.getElementById('f');
  var btn = document.getElementById('btn');
  var box = document.getElementById('msg');
  var text = document.getElementById('msg-text');

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    btn.disabled = true;
    btn.textContent = 'جارٍ الإنشاء…';

    try {
      var res = await fetch('/api/setup', { method: 'POST', body: new FormData(form) });
      var data = await res.json().catch(function () { return null; });

      box.hidden = false;
      if (res.ok) {
        box.setAttribute('data-tone', 'ok');
        text.textContent = (data && data.message) || 'تم الإنشاء.';
        form.reset();
      } else {
        box.removeAttribute('data-tone');
        text.textContent = (data && data.error && data.error.message) || 'فشل الإنشاء.';
      }
    } catch (e) {
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'إنشاء الحساب';
    }
  });
})();
`;

// ═══════════════════ 4) لوحة التحكم ═══════════════════

export interface DashboardTeamMember {
  id: string;
  username: string;
  fullName: string;
  roleKey: string;
  isActive: boolean;
}

export interface DashboardBranch {
  id: string;
  name: string;
}

export interface DashboardBranchFull {
  id: string;
  code: string;
  name: string;
  isActive: boolean;
}

export interface DashboardData {
  currentUserId: string;
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleLabel: string;
  roleKey: string;
  permissions: string[];
  pendingApprovals: number;
  canApproveExpenses: boolean;
  /** report.view_branch — صاحب المحل ومدير الفرع */
  canViewReport: boolean;
  /**
   * سجل اليوميات.
   *
   * ⚠ ده **مش** نفس `canViewReport`. التقرير محاسبي وبيتفتح مرة
   * في الشهر؛ اليومية تشغيلية وبتتفتح كل وردية. والمندوب بيشوف
   * التانية ومش بيشوف الأولى.
   */
  canViewClosings: boolean;
  /** profit.view_real — صاحب المحل وحده */
  canSeeCost: boolean;
  /** supplier.manage — صاحب المحل ومدير الفرع */
  canManageSuppliers: boolean;
  /** maintenance.view — الكل */
  canViewMaintenance: boolean;
  canBroadcast: boolean;
  canViewUsers: boolean;
  canCreateUsers: boolean;
  canEditUsers: boolean;
  canManageBranches: boolean;
  team: DashboardTeamMember[];
  branches: DashboardBranch[];
  tenantBranches: DashboardBranchFull[];
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  /** LOGOUT = خروج كامل · LOCK = قفل شاشة والجلسة تفضل حيّة */
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * صفحة القفل المستقلة.
 *
 * دي مسار احتياطي: بتظهر لو المستخدم فتح رابط محمي وجلسته مقفولة
 * أصلاً. المسار الأساسي هو الغطاء اللي بيظهر فوق اللوحة من غير
 * انتقال — لأن الانتقال بيضيّع حالة الصفحة (والسلة لما نبنيها).
 */
export function lockedPage(): Html {
  return shell({
    title: 'الشاشة مقفولة',
    tenantName: null,
    noIndex: true,
    script: LOCKED_PAGE_SCRIPT,
    body: html`<main class="lock-screen">
  <div class="lock-card">
    <p class="lock-eyebrow">SCREEN LOCKED</p>
    <h1 class="lock-title">الشاشة مقفولة</h1>
    <p class="lock-who">الجلسة ما زالت قائمة. أدخل كلمة المرور للمتابعة.</p>

    <form id="lf" novalidate>
      <label class="sr-only" for="lpw">كلمة المرور</label>
      <input class="lock-input" id="lpw" type="password" dir="ltr"
        autocomplete="current-password" required autofocus>
      <button class="lock-btn" id="lbtn" type="submit">فتح</button>
    </form>

    <p class="lock-error" id="lerr" role="alert" aria-live="assertive"></p>
    <button class="lock-exit" id="lout" type="button">تسجيل الخروج بدلًا من ذلك</button>
  </div>
</main>`,
  });
}

const LOCKED_PAGE_SCRIPT = `
(function () {
  var form = document.getElementById('lf');
  var btn = document.getElementById('lbtn');
  var err = document.getElementById('lerr');

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'جارٍ الفتح…';

    try {
      var res = await fetch('/api/auth/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ password: document.getElementById('lpw').value })
      });
      var data = await res.json().catch(function () { return null; });

      if (res.ok) { window.location.href = '/app'; return; }

      // 401 هنا معناه كلمة مرور غلط، مش انتهاء جلسة
      err.textContent = (data && data.error && data.error.message) || 'كلمة المرور غير صحيحة.';
      document.getElementById('lpw').value = '';
      document.getElementById('lpw').focus();
    } catch (e) {
      err.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'فتح';
    }
  });

  document.getElementById('lout').addEventListener('click', async function () {
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) {}
    window.location.href = '/login';
  });
})();
`;

const BROADCAST_PANEL = `
<details class="panel" id="broadcast">
  <summary>بثّ إعلان</summary>
  <div class="panel-body">
  <p class="muted">
    يظهر كنافذة إلزامية لكل من يعنيه الأمر عند أول دخول، ولا يمكنه المتابعة
    قبل الضغط على «قرأت وفهمت» — ويُسجَّل الإقرار باسمه ووقته.
  </p>
  <div class="alert-box" id="bmsg" role="alert" hidden><span id="bmsg-text"></span></div>
  <form id="bf" novalidate>
    <div class="field">
      <label class="field-label" for="title">العنوان</label>
      <input class="field-input" id="title" type="text" maxlength="140" required>
    </div>
    <div class="field">
      <label class="field-label" for="body">النص</label>
      <textarea class="field-area" id="body" maxlength="4000" required></textarea>
    </div>
    <div class="field">
      <label class="field-label" for="audience">الجمهور</label>
      <select class="field-input" id="audience">
        <option value="ALL">الكل</option>
        <option value="MANAGERS_ONLY">مديرو الفروع فقط</option>
        <option value="STAFF_ONLY">مندوبو المبيعات فقط</option>
      </select>
    </div>
    <div class="field">
      <label class="field-label" for="severity">الأهمية</label>
      <select class="field-input" id="severity">
        <option value="INFO">تعميم</option>
        <option value="WARNING">تنبيه</option>
        <option value="CRITICAL">عاجل</option>
      </select>
    </div>
    <button class="btn-primary" id="bbtn" type="submit">إرسال الإعلان</button>
  </form>
  </div>
</details>`;

const ROLE_BADGE: Record<string, string> = {
  SUPER_ADMIN: 'مالك',
  BRANCH_MANAGER: 'مدير فرع',
  STAFF: 'مندوب مبيعات',
};

/**
 * قائمة الفريق.
 *
 * كل اسم و username بييجي من قاعدة البيانات، وممكن يحتوي حروف
 * حسّاسة لو كتبها حد بسوء نية. لهذا بنستخدم html`` (بتهرّب تلقائيًا)
 * مش raw() هنا — على عكس BROADCAST_PANEL اللي هو HTML ثابت كتبناه إحنا.
 *
 * زرار التعطيل بيختفي في تلات حالات، وكلها منطقية:
 *   - حسابك إنت (منع القفل الذاتي)
 *   - حساب المالك (محصّن)
 *   - لو مالكش صلاحية USER_EDIT
 * والخادم بيرفض التلاتة برضه — الإخفاء هنا راحة مش حماية.
 */
function teamListHtml(data: DashboardData): Html {
  if (data.team.length === 0) {
    return html`<p class="muted">لا توجد حسابات بعد. ابدأ بإضافة حساب من النموذج أعلاه.</p>`;
  }

  const rows = data.team.map((m) => {
    const canToggle =
      data.canEditUsers && m.id !== data.currentUserId && m.roleKey !== 'SUPER_ADMIN';

    const action = canToggle
      ? html`<button
          class="btn-mini"
          type="button"
          data-toggle-user="${m.id}"
          data-next="${m.isActive ? 'off' : 'on'}"
          data-danger="${m.isActive ? 'true' : 'false'}"
        >${m.isActive ? 'تعطيل' : 'تفعيل'}</button>`
      : '';

    return html`<li class="roster-row" data-inactive="${m.isActive ? 'false' : 'true'}">
      <div class="roster-main">
        <span class="roster-name">${m.fullName}</span>
        <span class="roster-id">${m.username}</span>
      </div>
      <div class="roster-side">
        ${m.isActive ? '' : html`<span class="tag" data-variant="off">معطّل</span>`}
        <span class="tag">${ROLE_BADGE[m.roleKey] ?? m.roleKey}</span>
        ${action}
      </div>
    </li>`;
  });

  return html`<ul class="roster">${rows}</ul>`;
}

function teamPanel(data: DashboardData): Html {
  return html`<details class="panel" id="team" open>
    <summary>الفريق</summary>
    <div class="panel-body">
      <p class="muted">
        ${data.roleKey === 'SUPER_ADMIN' ? 'كل الحسابات في كل الفروع.' : 'حسابات فرعك.'}
        يقطع التعطيل جلسة المستخدم فورًا ويمنعه من الدخول، مع الاحتفاظ بكامل سجلّه ومبيعاته.
      </p>
      <div class="alert-box" id="tmsg" role="alert" hidden><span id="tmsg-text"></span></div>
      ${teamListHtml(data)}
    </div>
  </details>`;
}

/**
 * إدارة الفروع — المالك فقط.
 *
 * كود الفرع بيتعرض بخط الآلة الكاتبة لأنه معرّف بيتكتب في الفواتير
 * والتقارير، مش اسم بشري.
 */
function branchesPanel(data: DashboardData): Html {
  const list =
    data.tenantBranches.length === 0
      ? html`<p class="muted">لا توجد فروع بعد.</p>`
      : html`<ul class="roster">
          ${data.tenantBranches.map(
            (b) => html`<li class="roster-row" data-inactive="${b.isActive ? 'false' : 'true'}">
              <div class="roster-main">
                <span class="roster-name">${b.name}</span>
                <span class="roster-id">${b.code}</span>
              </div>
              <div class="roster-side">
                ${b.isActive ? '' : html`<span class="tag" data-variant="off">معطّل</span>`}
              </div>
            </li>`,
          )}
        </ul>`;

  return html`<details class="panel" id="branches">
    <summary>الفروع</summary>
    <div class="panel-body">
    <p class="muted">
      يجب إنشاء الفرع قبل إضافة حسابات إليه. يظهر الكود في الفواتير
      والتقارير، فاجعله قصيرًا وثابتًا.
    </p>

    <div class="alert-box" id="brmsg" role="alert" hidden><span id="brmsg-text"></span></div>

    <form id="brf" novalidate>
      <div class="field">
        <label class="field-label" for="br-code">كود الفرع</label>
        <input class="field-input" id="br-code" type="text" dir="ltr" autocomplete="off"
          spellcheck="false" maxlength="16" required>
        <p class="field-hint">حروف إنجليزية كبيرة وأرقام وشرطة. مثال: RYD-01</p>
      </div>
      <div class="field">
        <label class="field-label" for="br-name">اسم الفرع</label>
        <input class="field-input" id="br-name" type="text" maxlength="80" required>
      </div>
      <div class="field">
        <label class="field-label" for="br-address">العنوان (اختياري)</label>
        <input class="field-input" id="br-address" type="text" maxlength="200">
      </div>
      <div class="field">
        <label class="field-label" for="br-phone">الهاتف (اختياري)</label>
        <input class="field-input" id="br-phone" type="tel" dir="ltr" maxlength="32">
      </div>
      <button class="btn-primary" id="brbtn" type="submit">إضافة الفرع</button>
    </form>

    <div style="margin-top:22px">${list}</div>
    </div>
  </details>`;
}

/**
 * نموذج إضافة حساب.
 *
 * القائمة المنسدلة للفرع بتظهر بس لو data.branches فيها عناصر —
 * وهي مش بتتملى أصلاً إلا للمالك (شوف listBranchesForActor في
 * application/use-cases/users.ts). مدير الفرع مش بيشوف الحقل ده
 * خالص، لأن فرعه مفروض تلقائياً من هويته في الخادم، مش من الفورم.
 */
function createUserPanel(data: DashboardData): Html {
  const isOwner = data.roleKey === 'SUPER_ADMIN';

  const branchField =
    data.branches.length > 0
      ? html`<div class="field">
          <label class="field-label" for="u-branch">الفرع</label>
          <select class="field-input" id="u-branch">
            ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
          </select>
        </div>`
      : '';

  return html`<details class="panel">
    <summary>إضافة حساب</summary>
    <div class="panel-body">
    <p class="muted">
      ${isOwner
        ? 'اختر الفرع والدور. يدخل صاحب الحساب باسم المستخدم وكلمة المرور اللذين تكتبهما.'
        : 'يُربط الحساب بفرعك تلقائيًا. إذا اخترت «مدير فرع»، تكون صلاحياته مطابقة لصلاحياتك داخل هذا الفرع.'}
    </p>

    <div class="alert-box" id="umsg" role="alert" hidden><span id="umsg-text"></span></div>

    <form id="uf" novalidate>
      <div class="field">
        <label class="field-label" for="u-fullname">الاسم الكامل</label>
        <input class="field-input" id="u-fullname" type="text" maxlength="80" required>
      </div>
      <div class="field">
        <label class="field-label" for="u-username">اسم المستخدم</label>
        <input class="field-input" id="u-username" type="text" dir="ltr" autocomplete="off"
          spellcheck="false" maxlength="32" required>
        <p class="field-hint">حروف إنجليزية صغيرة وأرقام فقط، من 3 إلى 32 حرفًا.</p>
      </div>
      <div class="field">
        <label class="field-label" for="u-password">كلمة المرور المبدئية</label>
        <input class="field-input" id="u-password" type="text" dir="ltr" autocomplete="off" required>
        <p class="field-hint">12 حرفًا على الأقل. سلّمها لصاحب الحساب بنفسك بعد الإنشاء.</p>
      </div>
      <div class="field">
        <label class="field-label" for="u-role">الدور</label>
        <select class="field-input" id="u-role">
          <option value="STAFF">مندوب مبيعات</option>
          <option value="BRANCH_MANAGER">مدير فرع</option>
        </select>
      </div>
      ${branchField}
      <button class="btn-primary" id="ubtn" type="submit">إنشاء الحساب</button>
    </form>
    </div>
  </details>`;
}

export function dashboardPage(data: DashboardData): Html {
  const canUseTreasury = data.permissions.includes('expense.create');
  const canSell = data.permissions.includes('sales.create');
  const canViewProducts = data.permissions.includes('inventory.view');
  const isStaff = data.roleKey === 'STAFF';

  // ── شريط الانتباه: حاجة واحدة محتاجة قرارك دلوقتي ──
  const strip =
    data.pendingApprovals > 0
      ? html`<section class="strip" data-tone="wait">
          <span class="strip-count">${String(data.pendingApprovals)}</span>
          <span class="strip-text"><b>طلبات صرف تنتظر اعتمادك.</b> لا تدخل في الرصيد قبل أن تعتمدها.</span>
          <a class="strip-go" href="/treasury">مراجعة</a>
        </section>`
      : html`<section class="strip" data-tone="calm">
          <span class="strip-text">لا يوجد ما ينتظر قرارك الآن.</span>
        </section>`;

  // ⚠ شريط التنبيهات بيتملا بالجافاسكربت بعد ما الصفحة تفتح،
  // مش مع الصفحة. السبب: التنبيه حالة لحظية، ولو اتحسب على
  // الخادم مع باقي اللوحة هيتأخّر تحميلها من غير داعي.
  //
  // ومخفي لحد ما يبقى فيه حاجة فعلاً — شريط فاضي دايم بيتحوّل
  // لأثاث، والعين بتبطّل تشوفه.
  const alertStrip = html`<section class="strip" id="alert-strip" data-tone="wait" hidden>
    <span class="strip-count" id="alert-count"></span>
    <span class="strip-text" id="alert-text"></span>
    <a class="strip-go" href="/products">عرض</a>
  </section>`;

  // ── البلاطات: اللي تقدر تعمله، بكلام مفهوم مش أكواد نظام ──
  //
  // ══ ⚠ البيع والمنتجات والخزينة **مش هنا** عن قصد ══
  // التلاتة دول في الشريط السفلي على الموبايل وفي الكعب على
  // الكمبيوتر، وكانوا مكررين هنا كمان.
  //
  // والتكرار مش مجرد زحمة: لما نفس الوجهة يبقى ليها بابين في
  // شاشة واحدة، الموظّف بيقعد يفكّر أنهي واحد "الصح" — وده
  // تردد بيتدفع كل مرة يفتح الشاشة.
  //
  // ⚠ ومفيش حاجة ضاعت بالشيل: شروط الشريط السفلي تحت هي **نفس**
  // الشروط بالحرف (canSell · canViewProducts · canUseTreasury).
  // اللي كان بيشوف البلاطة بيشوف التبويب.
  //
  // فاللوحة دي بقت للوجهات اللي **مالهاش** تبويب وبس.
  const tiles: Html[] = [];

  // ⚠ التقرير بعد الخزينة عن قصد: الخزينة بتتفتح كل يوم،
  // والتقرير مرة في الأسبوع أو الشهر. الترتيب بيتبع الاستخدام.
  if (data.canViewReport) {
    tiles.push(html`<a class="tile" data-wide href="/report">
      <span class="tile-label">قائمة الدخل</span>
      <span class="tile-note">
        ${data.canSeeCost ? 'كسبت كام هذا الشهر' : 'حركة فرعك هذا الشهر'}
      </span>
    </a>`);
  }

  // ⚠ اليومية قبل الصيانة وبعد التقرير: دي بتتفتح كل وردية،
  // والصيانة لما جهاز يدخل. الترتيب بيتبع الاستخدام زي البقية.
  if (data.canViewClosings) {
    tiles.push(html`<a class="tile" href="/closings">
      <span class="tile-label">سجل اليوميات</span>
      <span class="tile-note">تقفيل الوردية ومراجعتها</span>
    </a>`);
  }

  if (data.canViewMaintenance) {
    tiles.push(html`<a class="tile" href="/maintenance">
      <span class="tile-label">الصيانة</span>
      <span class="tile-note">أجهزة العملاء والورش</span>
    </a>`);
  }

  if (data.canManageSuppliers) {
    tiles.push(html`<a class="tile" href="/suppliers">
      <span class="tile-label">الموردين</span>
      <span class="tile-note">ديون وسداد</span>
    </a>`);
  }

  if (data.canViewUsers) {
    tiles.push(html`<a class="tile" href="#team">
      <span class="tile-label">الفريق</span>
      <span class="tile-num">${String(data.team.length)}</span>
    </a>`);
  }

  if (data.canManageBranches) {
    tiles.push(html`<a class="tile" href="#branches">
      <span class="tile-label">الفروع</span>
      <span class="tile-num">${String(data.tenantBranches.length)}</span>
    </a>`);
  }

  if (data.canBroadcast) {
    tiles.push(html`<a class="tile" data-wide href="#broadcast">
      <span class="tile-label">بثّ إعلان</span>
      <span class="tile-note">نافذة إلزامية لكل من يعنيه الأمر</span>
    </a>`);
  }

  // ── شاشة الموظّف: بتقول له إيه اللي جاي بدل ما تسيبه في فراغ ──
  const staffEmpty = html`<section class="panel" open>
    <div class="empty">
      <p class="empty-title">يبدأ يومك من شاشة البيع</p>
      <p class="empty-note">
        اختر المنتجات، وحدّد الخزينة، وأتمم الفاتورة.<br>
        تُتاح المرتجعات وتسجيل العملاء في تحديث قادم.
      </p>
    </div>
  </section>`;

  return shell({
    title: 'الرئيسية',
    tenantName: data.tenantName,
    script: dashboardScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  ${strip}
  ${alertStrip}

  ${tiles.length > 0 ? html`<div class="tiles">${tiles}</div>` : ''}

  ${isStaff && !data.canViewUsers ? staffEmpty : ''}

  ${data.canBroadcast ? raw(BROADCAST_PANEL) : ''}
  ${data.canManageBranches ? branchesPanel(data) : ''}
  ${data.canCreateUsers ? createUserPanel(data) : ''}
  ${data.canViewUsers ? teamPanel(data) : ''}
</main>

${tabBar('app', {
  showPos: canSell,
  showProducts: canViewProducts,
  showTreasury: canUseTreasury,
})}

<div id="gate-root"></div>
<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

/**
 * سكربت اللوحة: نافذة الإعلانات + مراقب الخمول + البثّ.
 *
 * ⚠ تنبيه جوهري: كل ده **راحة للمستخدم، مش حراسة**.
 * أي حد يقدر يقفل JavaScript. الحكم النهائي دايماً في الخادم عبر
 * ختم last_seen_at. تشبيه: ساعة الحيطة بتنبّهك إن الجولة قربت
 * تخلص، لكن **الحكم** هو اللي بيوقف النزال.
 */
function dashboardScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var queue = [];
  var busy = false;

  var LABEL = { INFO: 'تعميم', WARNING: 'تنبيه', CRITICAL: 'عاجل' };
  var gateRoot = document.getElementById('gate-root');

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
  }

  // ── نافذة الإعلان الإلزامي ──
  function renderGate() {
    var item = queue[0];
    if (!item) { gateRoot.innerHTML = ''; document.body.style.overflow = ''; return; }

    document.body.style.overflow = 'hidden';
    gateRoot.innerHTML =
      '<div class="gate-backdrop"><div class="gate-panel" role="alertdialog" aria-modal="true" tabindex="-1">' +
        '<div class="gate-head">' +
          '<span class="gate-tag" data-severity="' + esc(item.severity) + '">' + (LABEL[item.severity] || '') + '</span>' +
          '<h2 class="gate-title">' + esc(item.title) + '</h2>' +
        '</div>' +
        '<div class="gate-body">' + esc(item.body) + '</div>' +
        '<div class="gate-foot">' +
          (queue.length > 1 ? '<p class="gate-count">' + (queue.length - 1) + ' / ' + queue.length + '</p>' : '') +
          '<button class="btn-primary" id="ack" type="button">قرأت وفهمت</button>' +
        '</div>' +
      '</div></div>';

    var panel = gateRoot.querySelector('.gate-panel');
    if (panel) panel.focus();

    document.getElementById('ack').addEventListener('click', async function () {
      if (busy) return;
      busy = true;
      try {
        var res = await fetch('/api/announcements/' + encodeURIComponent(item.id) + '/ack', {
          method: 'POST', credentials: 'same-origin'
        });
        if (!res.ok) throw new Error('ack failed');
        queue.shift();
        renderGate();
      } catch (e) {
        // ما اتسجّلش في الخادم — ما نخفيش النافذة، وإلا يبقى عندنا
        // موظف فاكر إنه وقّع والسجل بيقول العكس.
        alert('تعذّر تسجيل الإقرار. تحقّق من الاتصال ثم أعد المحاولة.');
      } finally {
        busy = false;
      }
    });
  }

  async function loadAnnouncements() {
    try {
      var res = await fetch('/api/announcements/pending', { credentials: 'same-origin' });
      if (!res.ok) return; // فشل صامت: تعطّل الإعلانات ما يصحّش يوقف البيع
      var data = await res.json();
      queue = Array.isArray(data.items) ? data.items : [];
      renderGate();
    } catch (e) {}
  }

  // Escape مقفول عمداً في الإعلان الإلزامي: مفيش مخرج غير الإقرار
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && queue.length) e.preventDefault();
  });

  // ── مراقب الخمول ──


  // ── البثّ ──
  var bf = document.getElementById('bf');
  if (bf) {
    bf.addEventListener('submit', async function (event) {
      event.preventDefault();
      var btn = document.getElementById('bbtn');
      var box = document.getElementById('bmsg');
      var text = document.getElementById('bmsg-text');
      btn.disabled = true;
      btn.textContent = 'جارٍ الإرسال…';

      try {
        var res = await fetch('/api/announcements', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            title: document.getElementById('title').value,
            body: document.getElementById('body').value,
            audience: document.getElementById('audience').value,
            severity: document.getElementById('severity').value,
            isMandatory: true
          })
        });
        var data = await res.json().catch(function () { return null; });

        box.hidden = false;
        if (res.ok) {
          box.setAttribute('data-tone', 'ok');
          text.textContent = 'تم بثّ الإعلان.';
          bf.reset();
        } else {
          box.removeAttribute('data-tone');
          text.textContent = (data && data.error && data.error.message) || 'فشل الإرسال.';
        }
      } catch (e) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = 'تعذّر الاتصال بالخادم.';
      } finally {
        btn.disabled = false;
        btn.textContent = 'إرسال';
      }
    });
  }

  loadAnnouncements();

  // ── إضافة حساب ──
  var uf = document.getElementById('uf');
  if (uf) {
    uf.addEventListener('submit', async function (event) {
      event.preventDefault();
      var btn = document.getElementById('ubtn');
      var box = document.getElementById('umsg');
      var text = document.getElementById('umsg-text');
      var branchEl = document.getElementById('u-branch');

      btn.disabled = true;
      btn.textContent = 'جارٍ الإنشاء…';

      try {
        var res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            fullName: document.getElementById('u-fullname').value,
            username: document.getElementById('u-username').value,
            password: document.getElementById('u-password').value,
            roleKey: document.getElementById('u-role').value,
            branchId: branchEl ? branchEl.value : null
          })
        });
        var data = await res.json().catch(function () { return null; });

        box.hidden = false;
        if (res.ok) {
          box.setAttribute('data-tone', 'ok');
          text.textContent = 'تم إنشاء الحساب. يجري تحديث الصفحة…';
          // إعادة تحميل عشان الحساب الجديد يظهر في قائمة الفريق
          // (القائمة مبنية من الخادم وقت فتح الصفحة، مش حيّة).
          setTimeout(function () { window.location.reload(); }, 1000);
        } else {
          box.removeAttribute('data-tone');
          text.textContent = (data && data.error && data.error.message) || 'فشل الإنشاء.';
          btn.disabled = false;
          btn.textContent = 'إنشاء الحساب';
        }
      } catch (e) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = 'تعذّر الاتصال بالخادم.';
        btn.disabled = false;
        btn.textContent = 'إنشاء الحساب';
      }
    });
  }

  // ── تعطيل / تفعيل حساب ──
  // تفويض الحدث من المستند بدل ربط كل زرار على حدة — أبسط، ومش
  // بيتكسر لو القائمة اتغيّرت
  document.addEventListener('click', async function (event) {
    var btn = event.target.closest ? event.target.closest('[data-toggle-user]') : null;
    if (!btn) return;

    var userId = btn.getAttribute('data-toggle-user');
    var turnOn = btn.getAttribute('data-next') === 'on';
    var box = document.getElementById('tmsg');
    var text = document.getElementById('tmsg-text');

    if (!turnOn && !confirm('تعطيل هذا الحساب؟ ينقطع عن النظام فورًا.')) return;

    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/users/' + encodeURIComponent(userId) + '/active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ isActive: turnOn })
      });
      var data = await res.json().catch(function () { return null; });

      if (res.ok) { window.location.reload(); return; }

      if (box) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = (data && data.error && data.error.message) || 'فشل التنفيذ.';
      }
    } catch (e) {
      if (box) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = 'تعذّر الاتصال بالخادم.';
      }
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  // ── إضافة فرع ──
  var brf = document.getElementById('brf');
  if (brf) {
    brf.addEventListener('submit', async function (event) {
      event.preventDefault();
      var btn = document.getElementById('brbtn');
      var box = document.getElementById('brmsg');
      var text = document.getElementById('brmsg-text');

      btn.disabled = true;
      btn.textContent = 'جارٍ الإضافة…';

      try {
        var res = await fetch('/api/branches', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            code: document.getElementById('br-code').value,
            name: document.getElementById('br-name').value,
            address: document.getElementById('br-address').value,
            phone: document.getElementById('br-phone').value
          })
        });
        var data = await res.json().catch(function () { return null; });

        box.hidden = false;
        if (res.ok) {
          box.setAttribute('data-tone', 'ok');
          text.textContent = 'تمت إضافة الفرع. يجري تحديث الصفحة…';
          setTimeout(function () { window.location.reload(); }, 1000);
        } else {
          box.removeAttribute('data-tone');
          text.textContent = (data && data.error && data.error.message) || 'فشلت الإضافة.';
          btn.disabled = false;
          btn.textContent = 'إضافة الفرع';
        }
      } catch (e) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = 'تعذّر الاتصال بالخادم.';
        btn.disabled = false;
        btn.textContent = 'إضافة الفرع';
      }
    });
  }

  // ══════════ التنبيهات ══════════
  //
  // ⚠ بتتجاب بعد ما الصفحة تفتح، مش معها. لو فشلت، اللوحة
  // بتفضل شغّالة عادي — التنبيه إضافة مش شرط لتشغيل الشاشة.
  (async function () {
    var stripEl = document.getElementById('alert-strip');
    if (!stripEl) return;

    try {
      var res = await fetch('/api/reports/alerts', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok || data.totalCount === 0) return;

      var countEl = document.getElementById('alert-count');
      var textEl  = document.getElementById('alert-text');

      if (countEl) countEl.textContent = String(data.totalCount);

      // أول تنبيهين بالاسم، والباقي عدد. القايمة الكاملة في
      // شاشة المنتجات — الشريط تنبيه مش تقرير.
      var names = data.rows.slice(0, 2).map(function (r) { return r.title; }).join(' · ');
      var extra = data.totalCount > 2 ? ' وغيرهم' : '';

      if (textEl) {
        var head = data.highCount > 0
          ? '<b>' + data.highCount + ' صنف خلص أو شارف.</b> '
          : '<b>أصناف تحتاج انتباهك.</b> ';
        textEl.innerHTML = head + names + extra;
      }

      stripEl.hidden = false;
    } catch (err) {
      // صامت عن قصد: فشل التنبيه ما يصحّش يوقّع اللوحة
    }
  })();
})();
`;
}

// ═══════════════════ 5) الخزينة ═══════════════════

export interface TreasuryPageData {
  currentUserId: string;
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canApprove: boolean;
  /** للتبويبات السفلية — بتتحسب من الصلاحيات في app.ts */
  canSell: boolean;
  canViewProducts: boolean;
  balances: Array<{
    treasuryId: string;
    name: string;
    type: string;
    balancePiastres: number;
    movementCount: number;
    provider?: string | null;
  }>;

  /**
   * الملخّص المالي — فلوسك فين.
   *
   * ⚠ المجاميع جاية **محسوبة** من حالة الاستخدام مش بتتحسب هنا.
   * لو الشاشة حسبتها بنفسها، كان ممكن تختلف مع اللي الـAPI
   * بيرجّعه لأي حد تاني بيقرا نفس البيانات.
   */
  summary: {
    rows: Array<{
      treasuryId: string;
      name: string;
      type: string;
      provider: string | null;
      branchId: string | null;
      branchName: string | null;
      isActive: boolean;
      balancePiastres: number;
      movementCount: number;
    }>;
    branches: Array<{
      branchId: string | null;
      branchName: string;
      totalPiastres: number;
      rows: Array<{
        treasuryId: string;
        name: string;
        type: string;
        provider: string | null;
        balancePiastres: number;
      }>;
    }>;
    byType: Array<{ type: string; label: string; totalPiastres: number; count: number }>;
    totalPiastres: number;
    scopeLabel: string;
  };

  transfers: Array<{
    id: string;
    fromName: string;
    toName: string;
    sentPiastres: number;
    receivedPiastres: number;
    feePiastres: number;
    transferDate: string;
    createdByName: string | null;
  }>;

  /** صاحب المحل — بيضيف خزائن ويختار الفرع */
  isOwner: boolean;
  /** expense.approve — نفس صلاحية الإيداع والسحب */
  canTransfer: boolean;
  branches: Array<{ id: string; name: string }>;
  movements: TreasuryMovementView[];
  pending: TreasuryMovementView[];
  /**
   * ⚠ `isInventory` بيخلّي سبب "شراء بضاعة" **يختفي** من قائمة
   * أسباب المصروف، لأن له نوع حركة خاص بيه بيكتب بيان معاه.
   *
   * من غير الإخفاء، هيبقى فيه طريقتين لتسجيل نفس الحاجة —
   * واحدة ببيان وواحدة من غير — والتانية بتلغي الميزة.
   */
  reasons: Array<{ id: string; name: string; isAdvance: boolean; isInventory?: boolean }>;
  team: Array<{ id: string; fullName: string }>;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

export interface TreasuryMovementView {
  id: string;
  type: string;
  direction: string;
  status: string;
  amountPiastres: number;
  treasuryName: string;
  reasonName: string | null;
  relatedUserName: string | null;
  createdByName: string | null;
  note: string | null;
  occurredAt: Date;
  createdById: string;
}

const TYPE_LABEL: Record<string, string> = {
  SALE: 'بيع',
  REFUND: 'استرجاع',
  DEPOSIT: 'إيداع',
  WITHDRAWAL: 'سحب',
  EXPENSE: 'مصروف',
  ADVANCE: 'سُلفة',
  ADJUSTMENT: 'تسوية',
};

/**
 * ⚠ الأسماء بتتقرا من حالة الاستخدام مش مكتوبة هنا.
 *
 * كانت مكتوبة في المكانين، والنسخة اللي هنا كانت بتقول "كاش"
 * للنقدي — وهي دلوقتي اسم نوع تاني تمامًا (المحفظة). يعني
 * الشاشة كانت هتقول "كاش" للدرج و"محفظة" لفودافون، والموظّف
 * يختار غلط.
 *
 * ده بالظبط اللي بيحصل لما نفس المعلومة تتكتب مرتين: بتتغيّر
 * في واحدة وتفضل القديمة في التانية.
 */
const TREASURY_TYPE_LABEL: Record<string, string> = TREASURY_TYPE_LABELS;

function movementRowsHtml(items: TreasuryMovementView[], currentUserId: string, canApprove: boolean): Html {
  if (items.length === 0) return html`<p class="muted">لا توجد حركات.</p>`;

  return html`${items.map((m) => {
    // زرار المراجعة بيظهر بس لو معلّقة، وعندك صلاحية، ومش إنت
    // اللي كتبتها. الخادم بيرفض التلاتة برضه — الإخفاء راحة مش حماية.
    const canReview = canApprove && m.status === 'PENDING' && m.createdById !== currentUserId;

    const subParts = [
      m.treasuryName,
      m.reasonName,
      m.relatedUserName ? `لـ ${m.relatedUserName}` : null,
      m.createdByName ? `بواسطة ${m.createdByName}` : null,
      m.note,
    ].filter(Boolean);

    return html`<div class="mv-row" data-status="${m.status}">
      <div class="mv-main">
        <span class="mv-title">${TYPE_LABEL[m.type] ?? m.type}</span>
        <span class="mv-sub">${subParts.join(' · ')}</span>
      </div>
      <div class="mv-side">
        <span class="mv-amount" data-dir="${m.direction}">
          ${m.direction === 'IN' ? '+' : '−'}${formatPiastres(m.amountPiastres)}
        </span>
        ${m.status === 'PENDING' ? html`<span class="tag">في انتظار الاعتماد</span>` : ''}
        ${m.status === 'REJECTED' ? html`<span class="tag" data-variant="off">مرفوضة</span>` : ''}
        ${canReview
          ? html`<div class="mv-actions">
              <button class="btn-mini" type="button" data-review="${m.id}" data-decision="APPROVED">اعتماد</button>
              <button class="btn-mini" type="button" data-danger="true" data-review="${m.id}" data-decision="REJECTED">رفض</button>
            </div>`
          : ''}
      </div>
    </div>`;
  })}`;
}

export function treasuryPage(data: TreasuryPageData): Html {
  // ⚠ الإجمالي من الملخّص مش محسوب هنا.
  //
  // الملخّص بيحسبه من نفس الصفوف اللي بيعرضها، فمستحيل الرقم
  // اللي فوق يخالف اللي تحته. لو حسبناه هنا من `balances`،
  // كان ممكن يبقى فيه مصدرين للرقم الواحد.
  const total = data.summary.totalPiastres;

  const balancesHtml =
    data.summary.rows.length === 0
      ? html`<p class="muted">لا توجد خزائن بعد.</p>`
      : html`<div class="balances">
          ${data.summary.rows.map(
            (b) => html`<div class="bal-card">
              <span class="bal-name">${treasuryLabel(b)}</span>
              <span class="bal-meta">
                ${TREASURY_TYPE_LABEL[b.type] ?? b.type} · ${b.movementCount} حركة${
                  b.isActive ? '' : ' · موقوفة'
                }
              </span>
              <span class="bal-amount" data-negative="${b.balancePiastres < 0 ? 'true' : 'false'}">
                ${formatPiastres(b.balancePiastres)}<span class="bal-cur">ج.م</span>
              </span>
            </div>`,
          )}
        </div>`;

  /**
   * الملخّص المالي: نفس الفلوس من تلات زوايا.
   *
   * ⚠ التلاتة مجموعهم واحد بالظبط — لأنهم متحسبين من نفس
   * الصفوف. الزاوية بتتغيّر، الرقم لأ.
   *
   *   بالنوع  → نقدي كام، محافظ كام، فيزا كام
   *   بالفرع  → كل فرع فيه كام، ومقسّمة على خزائنه
   *   الإجمالي → المجموع
   */
  const summaryHtml = html`
    <div class="balances">
      ${data.summary.byType.map(
        (t) => html`<div class="bal-card">
          <span class="bal-name">${t.label}</span>
          <span class="bal-meta">${t.count} خزينة</span>
          <span class="bal-amount" data-negative="${t.totalPiastres < 0 ? 'true' : 'false'}">
            ${formatPiastres(t.totalPiastres)}<span class="bal-cur">ج.م</span>
          </span>
        </div>`,
      )}
    </div>

    ${data.summary.branches.map(
      (br) => html`<details class="panel">
        <summary>${br.branchName} — ${formatPiastres(br.totalPiastres)} ج.م</summary>
        <div class="panel-body">
          ${br.rows.map(
            (r) => html`<div class="mv-row">
              <span class="mv-title">${treasuryLabel(r)}</span>
              <span class="mv-sub">${TREASURY_TYPE_LABEL[r.type] ?? r.type}</span>
              <span class="mv-amount" data-dir="${r.balancePiastres < 0 ? 'OUT' : 'IN'}">
                ${formatPiastres(r.balancePiastres)}
              </span>
            </div>`,
          )}
        </div>
      </details>`,
    )}
  `;

  return shell({
    title: 'الخزينة',
    tenantName: data.tenantName,
    script: treasuryScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="balances" style="margin-bottom:18px">
    ${balancesHtml}
    ${data.summary.rows.length > 1
      ? html`<div class="bal-card bal-total">
          <span class="bal-name">الإجمالي — ${data.summary.scopeLabel}</span>
          <span class="bal-amount" data-negative="${total < 0 ? 'true' : 'false'}">${formatPiastres(total)}<span class="bal-cur">ج.م</span></span>
        </div>`
      : ''}

    ${data.summary.branches.length > 1 || data.summary.byType.length > 1
      ? html`<details class="panel">
          <summary>فلوسك فين</summary>
          <div class="panel-body">${summaryHtml}</div>
        </details>`
      : ''}

    ${data.canTransfer
      ? html`<details class="panel">
          <summary>تحويل بين الخزائن</summary>
          <div class="panel-body">
            <p class="muted">
              اكتب المبلغ الذي خرج والمبلغ الذي وصل. الفرق بينهما يُحسب عمولة تلقائيًا.
            </p>

            <div class="field">
              <label class="field-label" for="tr-from">من خزينة</label>
              <select class="field-input" id="tr-from">
                ${data.summary.rows
                  .filter((r) => r.isActive)
                  .map((r) => html`<option value="${r.treasuryId}">${treasuryLabel(r)}</option>`)}
              </select>
            </div>

            <div class="field">
              <label class="field-label" for="tr-to">إلى خزينة</label>
              <select class="field-input" id="tr-to">
                ${data.summary.rows
                  .filter((r) => r.isActive)
                  .map((r) => html`<option value="${r.treasuryId}">${treasuryLabel(r)}</option>`)}
              </select>
              <p class="field-hint">لا بد أن تكون الخزينتان في نفس الفرع.</p>
            </div>

            <div class="field">
              <label class="field-label" for="tr-sent">المبلغ الذي خرج</label>
              <input class="field-input" id="tr-sent" type="text" inputmode="decimal" dir="ltr">
            </div>

            <div class="field">
              <label class="field-label" for="tr-recv">المبلغ الذي وصل</label>
              <input class="field-input" id="tr-recv" type="text" inputmode="decimal" dir="ltr">
              <p class="field-hint" id="tr-fee">العمولة تظهر هنا.</p>
            </div>

            <div class="field">
              <label class="field-label" for="tr-note">ملاحظة (اختياري)</label>
              <input class="field-input" id="tr-note" type="text" maxlength="500">
            </div>

            <button class="btn-primary" type="button" id="tr-go">تنفيذ التحويل</button>
          </div>
        </details>`
      : ''}

    ${data.transfers.length > 0
      ? html`<details class="panel">
          <summary>آخر التحويلات</summary>
          <div class="panel-body">
            ${data.transfers.map(
              (t) => html`<div class="mv-row">
                <span class="mv-title">${t.fromName} ← ${t.toName}</span>
                <span class="mv-sub">
                  ${formatDate(t.transferDate)} · خرج ${formatPiastres(t.sentPiastres)} ·
                  وصل ${formatPiastres(t.receivedPiastres)}${
                    t.feePiastres > 0 ? ` · عمولة ${formatPiastres(t.feePiastres)}` : ''
                  }${t.createdByName ? ` — ${t.createdByName}` : ''}
                </span>
              </div>`,
            )}
          </div>
        </details>`
      : ''}

    ${data.isOwner
      ? html`<details class="panel">
          <summary>إضافة خزينة</summary>
          <div class="panel-body">
            <p class="muted">
              كل وسيلة دفع خزينة مستقلة. يمكن إنشاء أكثر من واحدة من النوع نفسه —
              فيزا الأهلي وفيزا CIB، أو محفظتين تحت فودافون.
            </p>

            <div class="field">
              <label class="field-label" for="tz-branch">الفرع</label>
              <select class="field-input" id="tz-branch">
                ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
              </select>
            </div>

            <div class="field">
              <label class="field-label" for="tz-type">النوع</label>
              <select class="field-input" id="tz-type">
                <option value="CASH">نقدي</option>
                <option value="WALLET">محفظة</option>
                <option value="VISA">فيزا</option>
                <option value="INSTAPAY">إنستاباي</option>
              </select>
            </div>

            <div class="field">
              <label class="field-label" for="tz-name">اسم الخزينة</label>
              <input class="field-input" id="tz-name" type="text" maxlength="60"
                placeholder="مثال: محفظة فودافون — الكاشير">
            </div>

            <div class="field" id="tz-prov-field">
              <label class="field-label" for="tz-prov">الجهة</label>
              <input class="field-input" id="tz-prov" type="text" maxlength="60"
                placeholder="فودافون · الأهلي · CIB">
              <p class="field-hint">
                البنك للفيزا، وشركة الاتصالات للمحفظة. النقدي لا جهة له.
              </p>
            </div>

            <button class="btn-primary" type="button" id="tz-go">إضافة</button>
          </div>
        </details>`
      : ''}
  </div>

  <details class="panel" open>
    <summary>تسجيل حركة</summary>
    <div class="panel-body">
    <p class="muted">
      ${data.canApprove
        ? 'تُعتمد حركتك فورًا وتؤثّر على الرصيد مباشرة.'
        : 'تُسجَّل حركتك كطلب معلّق، ولا تؤثّر على الرصيد قبل اعتماد المدير.'}
    </p>

    <div class="alert-box" id="mvmsg" role="alert" hidden><span id="mvmsg-text"></span></div>

    <form id="mvf" novalidate>
      <!-- ══ الفرع — لصاحب المحل وحده ══

           ⚠ نفس عطل شاشة البيع بالظبط، ونفس الحلّ.

           صاحب المحل بيشوف خزائن **كل فروعه** في قايمة واحدة،
           وكلها اسمها "نقدي" بعد توحيد التسمية. فبيسجّل مصروف
           فرع على خزينة فرع تاني — والحركة بتعدي عادي، لأن
           صاحب المحل من حقه فعلاً يصرف من أي خزينة.

           ⚠ وده اللي بيخلّي العطل ده **أوحش** من بتاع البيع:
           هناك القاعدة بترفض وتزعّق. هنا مفيش حاجة بترفض —
           الرقم بيتحطّ في الفرع الغلط ويفضل صح شكلاً، ولحد ما
           تقفل يومية الفرعين وتلاقي رقم مش مفهوم.

           الفلتر بيقفل الغلطة قبل ما تحصل. -->
      ${data.branches.length > 1
        ? html`<div class="field">
            <label class="field-label" for="mv-branch">الفرع</label>
            <select class="field-input" id="mv-branch">
              ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
            </select>
            <p class="field-hint">تظهر لك خزائن هذا الفرع وحدها.</p>
          </div>`
        : ''}

      <div class="field">
        <label class="field-label" for="mv-treasury">الخزينة</label>
        <select class="field-input" id="mv-treasury" required>
          ${data.balances.map((b) => {
            // ⚠ الفرع بيتقرا من `summary.rows` مش من `balances`.
            // الاتنين بيوصفوا نفس الخزائن، بس الملخّص وحده اللي
            // شايل الفرع — فمفيش داعي نغيّر `app.ts` عشان حقل
            // موجود أصلاً في الصفحة.
            const branchId =
              data.summary.rows.find((r) => r.treasuryId === b.treasuryId)?.branchId ?? '';
            return html`<option value="${b.treasuryId}" data-branch="${branchId}">${b.name}</option>`;
          })}
        </select>
      </div>

      <div class="field">
        <label class="field-label" for="mv-type">نوع الحركة</label>
        <select class="field-input" id="mv-type">
          <option value="EXPENSE">مصروف</option>
          <option value="PURCHASE">شراء بضاعة</option>
          <option value="ADVANCE">سُلفة موظّف</option>
          ${data.canApprove
            ? html`<option value="DEPOSIT">إيداع</option>
                <option value="WITHDRAWAL">سحب</option>
                <option value="ADJUSTMENT">تسوية جرد</option>`
            : ''}
        </select>
      </div>

      <div class="field">
        <label class="field-label" for="mv-amount">المبلغ</label>
        <input class="field-input" id="mv-amount" type="text" inputmode="decimal"
          dir="ltr" autocomplete="off" required>
        <p class="field-hint">بالجنيه. مثال: 150 أو 150.75</p>
      </div>

      <div class="field" id="mv-reason-field">
        <label class="field-label" for="mv-reason">سبب الصرف</label>
        <select class="field-input" id="mv-reason">
          ${data.reasons
            .filter((r) => !r.isInventory)
            .map((r) => html`<option value="${r.id}">${r.name}</option>`)}
        </select>
      </div>

      <div class="field" id="mv-user-field" hidden>
        <label class="field-label" for="mv-user">الموظّف صاحب السُلفة</label>
        <select class="field-input" id="mv-user">
          ${data.team.length > 0
            ? data.team.map((t) => html`<option value="${t.id}">${t.fullName}</option>`)
            : html`<option value="${data.currentUserId}">${data.fullName}</option>`}
        </select>
        ${data.team.length === 0
          ? html`<p class="field-hint">السُلفة تُسجَّل باسمك، وتُخصم من راتبك عند التسوية.</p>`
          : ''}
      </div>

      <div class="field" id="mv-dir-field" hidden>
        <label class="field-label" for="mv-dir">اتجاه التسوية</label>
        <select class="field-input" id="mv-dir">
          <option value="IN">زيادة في الخزينة</option>
          <option value="OUT">نقص في الخزينة</option>
        </select>
      </div>

      <div class="field" id="mv-item-field" hidden>
        <label class="field-label" for="mv-item">الصنف المشترى</label>
        <input class="field-input" id="mv-item" type="text" maxlength="120" autocomplete="off">
        <p class="field-hint">
          اكتبه زي ما هتدوّر عليه بعدين. مثال: آيفون 13 برو ماكس، أو جراب سيليكون.
        </p>
      </div>

      <div class="field" id="mv-qty-field" hidden>
        <label class="field-label" for="mv-qty">الكمية</label>
        <input class="field-input" id="mv-qty" type="number" inputmode="numeric"
          dir="ltr" min="1" step="1" value="1">
      </div>

      <div class="field" id="mv-sup-field" hidden>
        <label class="field-label" for="mv-sup">المورّد (اختياري)</label>
        <select class="field-input" id="mv-sup">
          <option value="">— بدون —</option>
        </select>
        <p class="field-hint">
          اختره من القائمة ولا تكتبه — الاسم المكتوب بخط اليد يصنع
          تاجرين مختلفين من تاجر واحد، والدين لا يقفل.
        </p>
      </div>

      <div class="field">
        <label class="field-label" for="mv-note">ملاحظة (اختياري)</label>
        <input class="field-input" id="mv-note" type="text" maxlength="500">
      </div>

      <p class="field-hint" id="mv-purchase-note" hidden>
        ⚠ هذا يسجّل خروج المال ويكتب بيانه. لا يضيف الصنف إلى المخزون —
        التوريد يتم من شاشة المنتجات.
      </p>

      <button class="btn-primary" id="mvbtn" type="submit">تسجيل الحركة</button>
    </form>
    </div>
  </details>

  ${data.canApprove && data.pending.length > 0
    ? html`<details class="panel" open>
        <summary>في انتظار اعتمادك (${String(data.pending.length)})</summary>
        <div class="panel-body">
          <p class="muted">لا تدخل هذه الطلبات في الرصيد قبل أن تعتمدها.</p>
          <div class="alert-box" id="rvmsg" role="alert" hidden><span id="rvmsg-text"></span></div>
          ${movementRowsHtml(data.pending, data.currentUserId, data.canApprove)}
        </div>
      </details>`
    : ''}

  <details class="panel" open>
    <summary>آخر الحركات</summary>
    <div class="panel-body">
      ${movementRowsHtml(data.movements, data.currentUserId, data.canApprove)}
    </div>
  </details>
</main>

${tabBar('treasury', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: true,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function treasuryScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  // ── إظهار الحقول حسب نوع الحركة ──
  // الحقل اللي ملوش لازمة بيختفي بدل ما يفضل معروض ومربك
  var typeEl = document.getElementById('mv-type');
  var reasonField = document.getElementById('mv-reason-field');
  var userField = document.getElementById('mv-user-field');
  var dirField = document.getElementById('mv-dir-field');

  var itemField = document.getElementById('mv-item-field');
  var qtyField = document.getElementById('mv-qty-field');
  var supField = document.getElementById('mv-sup-field');
  var purchaseNote = document.getElementById('mv-purchase-note');
  var supLoaded = false;

  /**
   * أسماء الموردين — بتتحمّل **أول مرة** يختار شراء بس.
   *
   * ⚠ مش مع الصفحة: أغلب فتحات شاشة الخزينة مصروف أو سُلفة،
   * فتحميل القائمة في كل مرة = رحلة ضايعة على شبكة موبايل.
   */
  async function loadSuppliers() {
    if (supLoaded) return;
    supLoaded = true;
    try {
      var res = await fetch('/api/purchases/suppliers', { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) return;

      var sel = document.getElementById('mv-sup');
      for (var i = 0; i < (d.suppliers || []).length; i++) {
        var o = document.createElement('option');
        o.value = d.suppliers[i].id;
        o.textContent = d.suppliers[i].name;
        sel.appendChild(o);
      }
    } catch (err) {
      // ⚠ المورّد اختياري، فالفشل هنا ما يمنعش تسجيل الشرا.
      // بنسيب القائمة فيها "بدون" وخلاص.
      supLoaded = false;
    }
  }

  function syncFields() {
    var t = typeEl.value;
    // سبب الصرف للمصروف وحده. السُلفة سببها معروف من نوعها،
    // والمطلوب معاها اسم الموظّف مش سبب.
    reasonField.hidden = t !== 'EXPENSE';
    userField.hidden = t !== 'ADVANCE';
    dirField.hidden = t !== 'ADJUSTMENT';

    // ⚠ الشرا سببه معروف من نوعه — نفس منطق السُلفة بالظبط.
    // المطلوب معاه بيان (صنف · كمية · مورّد) مش سبب.
    var buying = t === 'PURCHASE';
    itemField.hidden = !buying;
    qtyField.hidden = !buying;
    supField.hidden = !buying;
    purchaseNote.hidden = !buying;
    if (buying) loadSuppliers();
  }
  typeEl.addEventListener('change', syncFields);
  syncFields();

  // ── الفرع يضيّق قايمة الخزائن ──
  //
  // ⚠ الخزائن بتتشال من القايمة مش بتتخبّى بس. «hidden» على
  // «option» مش مضمون في كل المتصفحات، وخزينة شكلها مختارة وهي
  // من فرع تاني بتخلّي الحركة تتسجّل في المكان الغلط.
  (function () {
    var branchEl = document.getElementById('mv-branch');
    var treasuryEl = document.getElementById('mv-treasury');
    if (!branchEl || !treasuryEl) return;

    function sync() {
      var branch = branchEl.value;
      var opts = treasuryEl.options;
      var first = null;

      for (var i = 0; i < opts.length; i++) {
        var same = opts[i].getAttribute('data-branch') === branch;
        opts[i].disabled = !same;
        opts[i].hidden = !same;
        if (same && first === null) first = i;
      }

      // لو المختار بقى من فرع تاني، ننقل لأول خزينة صالحة
      if (treasuryEl.selectedIndex < 0 || opts[treasuryEl.selectedIndex].disabled) {
        treasuryEl.selectedIndex = first === null ? -1 : first;
      }
    }

    branchEl.addEventListener('change', sync);
    sync();
  })();

  // ── تسجيل حركة ──
  document.getElementById('mvf').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = document.getElementById('mvbtn');
    var box = document.getElementById('mvmsg');
    var text = document.getElementById('mvmsg-text');
    var t = typeEl.value;

    btn.disabled = true;
    btn.textContent = 'جارٍ التسجيل…';

    // ⚠ الشرا ليه مسار مختلف لأنه بيكتب **صفّين** في معاملة
    // واحدة: حركة الخزينة وبيانها. لو بعتناه لمسار الحركات
    // العادي، البيان كان هيضيع والمصروف يتسجّل أعمى.
    var url = t === 'PURCHASE' ? '/api/purchases' : '/api/treasury/movements';
    var payload = t === 'PURCHASE'
      ? {
          treasuryId: document.getElementById('mv-treasury').value,
          amount: document.getElementById('mv-amount').value,
          itemName: document.getElementById('mv-item').value,
          quantity: document.getElementById('mv-qty').value,
          supplierId: document.getElementById('mv-sup').value || null,
          note: document.getElementById('mv-note').value || null
        }
      : null;

    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload || {
          treasuryId: document.getElementById('mv-treasury').value,
          type: t,
          amount: document.getElementById('mv-amount').value,
          expenseReasonId: t === 'EXPENSE' ? document.getElementById('mv-reason').value : null,
          relatedUserId: t === 'ADVANCE' ? document.getElementById('mv-user').value : null,
          adjustmentDirection: t === 'ADJUSTMENT' ? document.getElementById('mv-dir').value : null,
          note: document.getElementById('mv-note').value || null
        })
      });
      var data = await res.json().catch(function () { return null; });

      box.hidden = false;
      if (res.ok) {
        box.setAttribute('data-tone', 'ok');
        text.textContent = (data && data.message) || 'تم التسجيل.';
        setTimeout(function () { window.location.reload(); }, 1200);
      } else {
        box.removeAttribute('data-tone');
        text.textContent = (data && data.error && data.error.message) || 'فشل التسجيل.';
        btn.disabled = false;
        btn.textContent = 'تسجيل';
      }
    } catch (err) {
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'تعذّر الاتصال بالخادم.';
      btn.disabled = false;
      btn.textContent = 'تسجيل';
    }
  });

  // ── اعتماد / رفض ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-review]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-review');
    var decision = btn.getAttribute('data-decision');
    var box = document.getElementById('rvmsg');
    var text = document.getElementById('rvmsg-text');

    if (decision === 'REJECTED' && !confirm('رفض هذا الطلب؟')) return;

    btn.disabled = true;
    try {
      var res = await fetch('/api/treasury/movements/' + encodeURIComponent(id) + '/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ decision: decision })
      });
      if (res.ok) { window.location.reload(); return; }

      var data = await res.json().catch(function () { return null; });
      if (box) {
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = (data && data.error && data.error.message) || 'فشل التنفيذ.';
      }
    } catch (err) {
      if (box) { box.hidden = false; text.textContent = 'تعذّر الاتصال بالخادم.'; }
    } finally {
      btn.disabled = false;
    }
  });

  /**
   * رسالة للمستخدم في شريط الحركات.
   *
   * ⚠ اتعرّفت هنا لأن السكربت ده مالوش دالة رسايل مشتركة —
   * كل معالج بيجيب العناصر بنفسه. ونداء say من غير تعريف
   * بيرمي خطأ وقت التشغيل بس، والزرار بيسكت بلا أي رسالة.
   *
   * ده الفخ رقم ١٦ في وثيقة المشروع، ومسكه الفاحص.
   */
  function say(message, ok) {
    var el = document.getElementById('mvmsg');
    var txt = document.getElementById('mvmsg-text');
    if (!el || !txt) return;

    el.hidden = false;
    if (ok) el.setAttribute('data-tone', 'ok');
    else el.removeAttribute('data-tone');
    txt.textContent = message;
  }

  // ══════════ التحويل بين الخزائن ══════════
  //
  // ⚠ مفيش خانة للعمولة — هي الفرق بين اللي خرج واللي وصل،
  // وبتتعرض لحظيًا وإنت بتكتب.
  //
  // لو كانت خانة تالتة، كان ممكن تكتب أرقام متناقضة (خرج ١٠٠٠،
  // وصل ٩٨٠، عمولة ٥٠) — ودلوقتي التناقض ده مستحيل.
  var trSent = document.getElementById('tr-sent');
  var trRecv = document.getElementById('tr-recv');
  var trFee  = document.getElementById('tr-fee');

  function trNum(el) {
    if (!el) return NaN;
    var raw = String(el.value || '').trim()
      .replace(/[\u0660-\u0669]/g, function (d) {
        return String(d.charCodeAt(0) - 0x0660);
      })
      .replace(/[\s,_]/g, '');
    if (raw === '') return NaN;
    return parseFloat(raw);
  }

  function showFee() {
    if (!trFee) return;
    var a = trNum(trSent);
    var b = trNum(trRecv);

    if (isNaN(a) || isNaN(b)) { trFee.textContent = 'العمولة تظهر هنا.'; return; }
    if (b > a) { trFee.textContent = 'المبلغ الذي وصل أكبر من الذي خرج.'; return; }

    var fee = Math.round((a - b) * 100) / 100;
    trFee.textContent = fee === 0
      ? 'بلا عمولة.'
      : 'العمولة: ' + fee.toFixed(2) + ' ج.م';
  }

  if (trSent) trSent.addEventListener('input', showFee);
  if (trRecv) trRecv.addEventListener('input', showFee);

  var trGo = document.getElementById('tr-go');
  if (trGo) {
    trGo.addEventListener('click', async function () {
      var from = document.getElementById('tr-from');
      var to   = document.getElementById('tr-to');
      if (!from || !to) return;

      // الحارس ده قدّام الرد من الخادم: السبب المحدد أنفع من
      // رسالة عامة بعد رحلة شبكة
      if (from.value === to.value) {
        say('اختر خزينتين مختلفتين.', false);
        return;
      }

      trGo.disabled = true;
      try {
        var res = await fetch('/api/treasury/transfers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            fromTreasuryId: from.value,
            toTreasuryId: to.value,
            sent: trSent ? trSent.value : '',
            received: trRecv ? trRecv.value : '',
            note: (document.getElementById('tr-note') || {}).value || null
          })
        });
        var d = await res.json().catch(function () { return null; });

        if (res.ok && d && d.ok) {
          say(d.message || 'تم التحويل.', true);
          setTimeout(function () { location.reload(); }, 900);
          return;
        }
        say((d && d.error && d.error.message) || 'تعذّر التحويل.', false);
      } catch (err) {
        // ⚠ مش بنقول "ما اتحوّلش" — إحنا مش عارفين. الطلب ممكن
        // يكون وصل واتنفّذ والرد هو اللي ضاع.
        say('انقطع الاتصال. حدّث الصفحة وتأكّد قبل إعادة المحاولة.', false);
      } finally {
        trGo.disabled = false;
      }
    });
  }

  // ══════════ إضافة خزينة ══════════
  var tzType = document.getElementById('tz-type');
  var tzProv = document.getElementById('tz-prov-field');

  function syncProvider() {
    if (!tzType || !tzProv) return;
    // ⚠ النقدي مالوش جهة — الدرج مش بنك
    tzProv.hidden = tzType.value === 'CASH';
  }
  if (tzType) { tzType.addEventListener('change', syncProvider); syncProvider(); }

  var tzGo = document.getElementById('tz-go');
  if (tzGo) {
    tzGo.addEventListener('click', async function () {
      var branch = document.getElementById('tz-branch');
      var name   = document.getElementById('tz-name');
      if (!branch || !name) return;

      if (!branch.value) { say('اختر الفرع.', false); return; }
      if (String(name.value || '').trim().length < 2) {
        say('اكتب اسم الخزينة.', false);
        return;
      }

      tzGo.disabled = true;
      try {
        var res = await fetch('/api/treasury/treasuries', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            branchId: branch.value,
            name: name.value,
            type: tzType ? tzType.value : 'CASH',
            provider: (document.getElementById('tz-prov') || {}).value || null
          })
        });
        var d = await res.json().catch(function () { return null; });

        if (res.ok && d && d.ok) {
          say(d.message || 'تمت الإضافة.', true);
          setTimeout(function () { location.reload(); }, 900);
          return;
        }
        say((d && d.error && d.error.message) || 'تعذّرت الإضافة.', false);
      } catch (err) {
        say('تعذّر الاتصال بالخادم.', false);
      } finally {
        tzGo.disabled = false;
      }
    });
  }
})();
`;
}


// ═══════════════════ 5) شاشة الكاشير ═══════════════════

export interface PosPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  /** ⚠ مدير الفرع والمالك بس. المندوب بيبيع وما بيرجّعش. */
  canRefund: boolean;
  treasuries: Array<{ treasuryId: string; name: string; type: string; branchId: string }>;
  /**
   * فروع المحل — لصاحب المحل وحده.
   *
   * ⚠ فاضية لغير صاحب المحل، والخانة بتختفي ساعتها. مدير الفرع
   * والمندوب مقفولين على فرعهم في الخادم أصلاً، فخانة باختيار
   * واحد عندهم بتبقى أثاث بلا وظيفة.
   */
  branches: Array<{ id: string; name: string }>;
  products: Array<{
    id: string;
    name: string;
    productType: 'device' | 'accessory';
    serialNumber: string | null;
    /** null = يطلب النظام السعر يدويًا وقت البيع */
    pricePiastres: number | null;
    quantityOnHand: number;
    branchId: string;
  }>;
  recentSales: Array<{
    id: string;
    totalPiastres: number;
    customerName: string | null;
    staffName: string | null;
    createdAt: Date;
    exitDate: string;
    /** بيتحسب على الخادم: صاحب الفاتورة أو المالك */
    canEditExit: boolean;
  }>;
  /** تاريخ النهاردة بتوقيت القاهرة — افتراضي حقل تاريخ الخروج */
  today: string;
  /**
   * الضمان الافتراضي بالأيام — الخانة بتبدأ بيه.
   *
   * ⚠ الرقم جاي من `DEFAULT_WARRANTY_DAYS` في حالة الاستخدام،
   * مش مكتوب هنا. لو اتكتب في المكانين، هييجي يوم يتغيّر في
   * واحد ويفضل القديم في التاني.
   */
  defaultWarrantyDays: number;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * شاشة البيع.
 *
 * ══ قرارات التصميم، وكل واحدة من واقع الكاشير ══
 *
 * • السلة فوق مش تحت: الموظّف بيبصّ عليها بين كل ضغطة وضغطة،
 *   والزبون بيسأل "بقى كام؟" وهو واقف. لو تحت، هيحتاج يسكرول
 *   في كل مرة.
 *
 * • المنتجات مربّعات كبيرة مش قايمة: الضغط بالإبهام على شاشة
 *   لمس قدّام طابور، مش بالماوس على مكتب.
 *
 * • الكمية المتاحة مكتوبة على كل منتج: أحسن من إنه يضغط ويلاقي
 *   رسالة "مش متاح" بعد ما وعد الزبون.
 *
 * • مفيش زرار "إلغاء الفاتورة" كبير جنب "تم البيع": الاتنين جنب
 *   بعض على شاشة لمس = غلطة مستنية تحصل.
 *
 * • السلة في ذاكرة الصفحة. وسياسة الموظّف قفل شاشة مش تسجيل
 *   خروج (30 دقيقة)، فالسلة بتفضل موجودة ورا الستارة.
 */
export function posPage(data: PosPageData): Html {
  const hasTreasury = data.treasuries.length > 0;
  const hasProducts = data.products.length > 0;

  const productsHtml = !hasProducts
    ? html`<div class="empty">
        <p class="empty-title">لا توجد منتجات متاحة</p>
        <p class="empty-note">
          إمّا أن المنتجات لم تُضَف بعد، أو أن الكميات نفدت.<br>
          يضيفها المدير ويورّدها من شاشة المنتجات.
        </p>
      </div>`
    : html`<div class="prod-grid" id="prod-grid">
        ${data.products.map(
          (p) => html`<button class="prod-btn" type="button"
            data-add="${p.id}"
            data-name="${p.name}"
            data-branch="${p.branchId}"
            data-price="${p.pricePiastres === null ? '' : String(p.pricePiastres)}"
            data-max="${String(p.quantityOnHand)}">
            <span class="prod-btn-name">${p.name}</span>
            <span class="prod-btn-price">
              ${p.pricePiastres === null ? 'السعر عند البيع' : formatPiastres(p.pricePiastres)}
            </span>
            <span class="prod-btn-qty">
              ${p.productType === 'device'
                ? (p.serialNumber ? `SN ${p.serialNumber}` : 'جهاز')
                : `متاح ${String(p.quantityOnHand)}`}
            </span>
          </button>`,
        )}
      </div>`;

  return shell({
    title: 'البيع',
    tenantName: data.tenantName,
    script: posScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.tenantName,
    ),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="posmsg" role="alert" hidden><span id="posmsg-text"></span></div>

  <section class="cart">
    <div class="cart-head">
      <span class="cart-title">السلة</span>
      <button class="btn-mini" type="button" id="cart-clear" hidden>تفريغ</button>
    </div>

    <p class="cart-empty" id="cart-empty">السلة فارغة. اختر منتجًا من الأسفل.</p>
    <div id="cart-lines"></div>

    <div class="cart-total">
      <span class="cart-total-label">الإجمالي</span>
      <span class="cart-total-num" id="cart-total">0.00<span class="bal-cur">ج.م</span></span>
    </div>
  </section>

  ${!hasTreasury
    ? html`<div class="alert-box"><span>
        لا توجد خزينة متاحة لفرعك، ولا يمكن إتمام فاتورة من دونها. راجع المالك لإضافة خزينة للفرع.
      </span></div>`
    : ''}

  <details class="panel" open>
    <summary>إتمام البيع</summary>
    <div class="panel-body">
      <!-- ══ الفرع — لصاحب المحل وحده ══

           ⚠ الخانة دي بتحلّ عطل حقيقي، مش تحسين شكل.

           صاحب المحل بيشوف منتجات **كل فروعه** في شاشة واحدة،
           وخزائن كل فروعه. فكان بيحطّ منتج من فرع ويختار خزينة
           فرع تاني — ودالة قاعدة البيانات بترفض بحق.

           كان فيه ملاحظة مكتوبة تحت الخزينة بتقوله "اختر خزينة
           نفس الفرع". والملاحظة مش حاجز: مفيش حد بيقرا سطر
           رمادي وهو ماسك سلة قدّام زبون.

           دلوقتي الفرع بيتقفل من فوق، والشاشة كلها بتضيق عليه —
           منتجاته وخزائنه. الغلطة بقت **مش ممكنة** بدل ما تكون
           مكتوب عنها تحذير.

           ⚠ ولسه ده **راحة مش حماية**. الحارس في دالة القاعدة
           زي ما هو، وما اتلمسش. -->
      ${data.branches.length > 1
        ? html`<div class="field">
            <label class="field-label" for="pos-branch">الفرع</label>
            <select class="field-input" id="pos-branch">
              ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
            </select>
            <p class="field-hint">
              تظهر لك منتجات هذا الفرع وخزائنه وحدها. تغيير الفرع يفرّغ السلة.
            </p>
          </div>`
        : ''}

      <div class="field">
        <label class="field-label" for="pos-treasury">الخزينة</label>
        <select class="field-input" id="pos-treasury" ${hasTreasury ? '' : raw('disabled')}>
          ${data.treasuries.map(
            (t) => html`<option value="${t.treasuryId}" data-branch="${t.branchId}">${t.name}</option>`,
          )}
        </select>
        <p class="field-hint">
          تُقرأ وسيلة الدفع من الخزينة نفسها — نقدي، فيزا، إنستاباي.
        </p>
      </div>

      <div class="field">
        <label class="field-label" for="pos-cname">اسم العميل (اختياري)</label>
        <input class="field-input" id="pos-cname" type="text" maxlength="80" autocomplete="off">
      </div>

      <div class="field">
        <label class="field-label" for="pos-cphone">رقم الهاتف (اختياري)</label>
        <input class="field-input" id="pos-cphone" type="tel" inputmode="tel"
          dir="ltr" maxlength="32" autocomplete="off">
      </div>

      <div class="field">
        <label class="field-label" for="pos-exit">تاريخ الخروج</label>
        <input class="field-input" id="pos-exit" type="date" dir="ltr"
          value="${data.today}" max="${data.today}">
        <p class="field-hint">
          يوم اليوم افتراضيًا. غيّره لتسجيل بيع تم في يوم سابق —
          ولا يتأثّر وقت تسجيل الفاتورة نفسه.
        </p>
      </div>

      <div class="field">
        <label class="field-label" for="pos-warranty">الضمان بالأيام</label>
        <input class="field-input" id="pos-warranty" type="number" inputmode="numeric"
          dir="ltr" min="0" max="3650" step="1"
          value="${String(data.defaultWarrantyDays)}">
        <p class="field-hint">
          يبدأ من تاريخ الخروج. اتركه فارغًا إن اتفقت مع العميل على
          بيع بلا ضمان — والاسترجاع بعدها يحتاج موافقة صاحب المحل.
        </p>
      </div>

      <button class="btn-primary" id="pos-submit" type="button" disabled>تم البيع</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>المنتجات</summary>
    <div class="panel-body">
      ${hasProducts
        ? html`<div class="field">
            <input class="field-input" id="pos-search" type="search"
              placeholder="ابحث بالاسم" autocomplete="off">
          </div>`
        : ''}
      ${productsHtml}
    </div>
  </details>

  ${data.recentSales.length === 0
    ? html`<details class="panel">
        <summary>آخر الفواتير</summary>
        <div class="panel-body">
          <p class="field-hint">
            لا توجد فواتير في نطاقك بعد. الفواتير تظهر هنا فور إتمام أول بيع،
            ومنها يبدأ الاسترجاع.
          </p>
        </div>
      </details>`
    : html`<details class="panel">
        <summary>آخر الفواتير</summary>
        <div class="panel-body">
          ${data.recentSales.map(
            (s) => html`<div class="mv-row">
              <div class="mv-main">
                <span class="mv-title">${s.customerName ?? 'بيع'}</span>
                <span class="mv-sub">
                  ${s.staffName ? `${s.staffName} · ` : ''}خروج ${formatDate(s.exitDate)}
                </span>
              </div>
              <div class="mv-side">
                <span class="mv-amount" data-dir="IN">+${formatPiastres(s.totalPiastres)}</span>
                ${s.canEditExit
                  ? html`<button class="btn-mini" type="button" data-exit-open="${s.id}">
                      تاريخ الخروج
                    </button>`
                  : ''}
                <button class="btn-mini" type="button" data-print-sale="${s.id}">
                  طباعة
                </button>
                ${data.canRefund
                  ? html`<button class="btn-mini" type="button" data-ret-open="${s.id}">
                      استرجاع
                    </button>`
                  : ''}
              </div>

              ${data.canRefund
                ? html`<div class="exit-edit" id="ret-${s.id}" hidden>
                    <p class="field-hint" id="ret-msg-${s.id}">جارٍ قراءة بنود الفاتورة…</p>
                    <div id="ret-warranty-${s.id}"></div>
                    <div id="ret-lines-${s.id}"></div>

                    <div id="ret-form-${s.id}" hidden>
                      <div class="mv-row" style="border:none;padding:6px 0">
                        <span class="mv-sub">يخرج من الدرج</span>
                        <span class="mv-amount" data-dir="OUT" id="ret-total-${s.id}">0.00</span>
                      </div>
                      <p class="field-hint" id="ret-fee-${s.id}"></p>

                      <label class="field-label" for="ret-tre-${s.id}">الخزينة</label>
                      <select class="field-input" id="ret-tre-${s.id}">
                        ${data.treasuries.map(
                          (t) => html`<option value="${t.treasuryId}">${t.name}</option>`,
                        )}
                      </select>

                      <label class="field-label" for="ret-why-${s.id}">السبب</label>
                      <input class="field-input" id="ret-why-${s.id}" type="text"
                        placeholder="مقاس غلط" autocomplete="off" maxlength="200">

                      <p class="field-hint">
                        البنود المرتجعة تذهب إلى رفّ المراجعة في المخزون — لا تُباع
                        مرة أخرى قبل فحصها.
                      </p>

                      <button class="btn-mini" type="button" data-ret-go="${s.id}">
                        تأكيد الاسترجاع
                      </button>
                    </div>
                  </div>`
                : ''}

              ${s.canEditExit
                ? html`<div class="exit-edit" id="exit-${s.id}" hidden>
                    <input class="field-input" id="exit-in-${s.id}" type="date" dir="ltr"
                      value="${s.exitDate}" max="${data.today}">
                    <button class="btn-mini" type="button" data-exit-save="${s.id}">حفظ</button>
                    <p class="field-hint">
                      يغيّر تاريخ خروج البضاعة فقط. وقت تسجيل الفاتورة يبقى كما هو.
                    </p>
                  </div>`
                : ''}
            </div>`,
          )}
        </div>
      </details>`}
</main>

${tabBar('pos', {
  showPos: true,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function posScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  /** ⚠ اسم المحل مش راجع مع الفاتورة — بيتمرّر صراحةً للطباعة */
  shopName: string,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
${TIME_JS}

(function () {
  // ⚠ JSON.stringify بيعمل الاقتباس والتهريب مع بعض — الاسم
  // ممكن يكون فيه علامة اقتباس تكسر السكربت لو لصقناه كنص.
  var SHOP_NAME = ${JSON.stringify(shopName)};

  // السلة في الذاكرة: معرّف المنتج ← { الاسم، السعر بالقرش، الكمية، المتاح }
  var cart = {};

  var linesEl = document.getElementById('cart-lines');
  var emptyEl = document.getElementById('cart-empty');
  var totalEl = document.getElementById('cart-total');
  var clearEl = document.getElementById('cart-clear');
  var submitEl = document.getElementById('pos-submit');
  var boxEl = document.getElementById('posmsg');

  // ══════════ الضمان ══════════
  //
  // ⚠ تلات حالات مش اتنين، والفرق بينهم بيتحاسب عليه قدّام
  // الزبون بعد شهرين:
  //
  //   الخانة فاضية → null → **بلا ضمان**
  //   مكتوب فيها 0  → 0    → ضمان صفر يوم، بقرار مكتوب
  //   رقم           → الرقم
  //
  // ودالة Number على نص فاضي بترجّع **صفر** — فلو بعتنا القيمة
  // على طول، الخانة الفاضية كانت هتتسجّل "صفر يوم" بدل "بلا ضمان".
  function warrantyValue() {
    var el = document.getElementById('pos-warranty');
    if (!el) return undefined;

    var raw = String(el.value || '').trim();
    if (raw === '') return null;

    var n = parseInt(raw, 10);
    if (isNaN(n) || n < 0) return null;
    return n;
  }
  var textEl = document.getElementById('posmsg-text');

  // نفس منطق formatPiastres في الخادم بالظبط — القسمة على 100
  // بتحصل وقت العرض بس. كل الحسابات فوق بالقرش كأرقام صحيحة.
  function money(piastres) {
    var neg = piastres < 0;
    var abs = Math.abs(Math.trunc(piastres));
    var pounds = Math.floor(abs / 100);
    var rest = abs % 100;
    return (neg ? '-' : '') + pounds.toLocaleString('en-US') + '.' + String(rest).padStart(2, '0');
  }

  // بيرجّع { sum, missing } — missing = عدد البنود اللي لسه بلا سعر.
  // الإجمالي ما بيعدّش الناقص، عشان ما يوريش الكاشير رقم أقل من
  // الحقيقة ويقوله للزبون.
  function total() {
    var sum = 0;
    var missing = 0;
    for (var id in cart) {
      var line = cart[id];
      var price = line.price !== null ? line.price : manualPrice(line.manual);
      if (price === null) { missing++; continue; }
      sum += price * line.qty;
    }
    return { sum: sum, missing: missing };
  }

  // قراءة السعر المكتوب بالإيد وتحويله لقروش.
  // بترجّع null لو فاضي أو غلط — والزرار بيفضل مقفول.
  function manualPrice(raw) {
    var text = String(raw || '')
      .replace(/[٠-٩]/g, function (d) { return String(d.charCodeAt(0) - 0x0660); })
      .replace(/[٫،]/g, '.')
      .replace(/[\s,_]/g, '')
      .trim();
    if (!text) return null;

    var m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(text);
    if (!m) return null;

    var piastres = parseInt(m[1], 10) * 100 + parseInt((m[2] || '0').padEnd(2, '0'), 10);
    return piastres > 0 ? piastres : null;
  }

  function count() {
    var n = 0;
    for (var id in cart) n++;
    return n;
  }

  function render() {
    var ids = Object.keys(cart);
    linesEl.innerHTML = '';

    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      var line = cart[id];

      var row = document.createElement('div');
      row.className = 'cart-line';

      var main = document.createElement('div');
      main.className = 'cart-line-main';

      var name = document.createElement('span');
      name.className = 'cart-line-name';
      name.textContent = line.name;

      var sub = document.createElement('span');
      sub.className = 'cart-line-sub';
      sub.textContent = money(line.price) + ' × ' + line.qty;

      main.appendChild(name);
      main.appendChild(sub);

      // ⚠ المنتج اللي مالوش سعر بيتحطّ له خانة إدخال في السلة
      // نفسها — مش نافذة منفصلة ولا شاشة تانية. الكاشير واقف
      // قدّام الزبون، فأقل عدد خطوات هو الأصح.
      if (line.price === null) {
        var priceWrap = document.createElement('div');
        priceWrap.className = 'cart-price';

        var priceInput = document.createElement('input');
        priceInput.className = 'cart-price-input';
        priceInput.type = 'text';
        priceInput.inputMode = 'decimal';
        priceInput.dir = 'ltr';
        priceInput.placeholder = 'السعر';
        priceInput.value = line.manual || '';
        priceInput.setAttribute('data-price-for', id);
        priceInput.setAttribute('aria-label', 'سعر ' + line.name);

        var priceNote = document.createElement('span');
        priceNote.className = 'cart-price-note';
        priceNote.textContent = 'اكتب سعر البيع';

        priceWrap.appendChild(priceInput);
        priceWrap.appendChild(priceNote);
        main.appendChild(priceWrap);
      }

      var side = document.createElement('div');
      side.className = 'cart-line-side';

      var amount = document.createElement('span');
      amount.className = 'cart-line-amount';
      amount.textContent = line.price === null ? '—' : money(line.price * line.qty);

      var steps = document.createElement('div');
      steps.className = 'qty-steps';

      var minus = document.createElement('button');
      minus.type = 'button';
      minus.className = 'qty-btn';
      minus.setAttribute('data-dec', id);
      minus.setAttribute('aria-label', 'نقص');
      minus.textContent = '−';

      var num = document.createElement('span');
      num.className = 'qty-num';
      num.textContent = String(line.qty);

      var plus = document.createElement('button');
      plus.type = 'button';
      plus.className = 'qty-btn';
      plus.setAttribute('data-inc', id);
      plus.setAttribute('aria-label', 'زيادة');
      plus.textContent = '+';
      // القفل عند حدّ المتاح: أحسن من رسالة خطأ بعد الوعد للزبون
      if (line.qty >= line.max) plus.disabled = true;

      steps.appendChild(minus);
      steps.appendChild(num);
      steps.appendChild(plus);

      side.appendChild(amount);
      side.appendChild(steps);

      row.appendChild(main);
      row.appendChild(side);
      linesEl.appendChild(row);
    }

    var isEmpty = ids.length === 0;
    var t = total();

    emptyEl.hidden = !isEmpty;
    clearEl.hidden = isEmpty;
    totalEl.innerHTML = money(t.sum) + '<span class="bal-cur">ج.م</span>';

    var treasury = document.getElementById('pos-treasury');
    submitEl.disabled = isEmpty || t.missing > 0 || !treasury || !treasury.value;

    if (isEmpty) submitEl.textContent = 'تم البيع';
    else if (t.missing > 0) submitEl.textContent = 'اكتب سعر ' + t.missing + ' صنف';
    else submitEl.textContent = 'تم البيع · ' + money(t.sum) + ' ج.م';
  }

  function add(btn) {
    var id = btn.getAttribute('data-add');
    var max = parseInt(btn.getAttribute('data-max'), 10) || 0;
    if (max <= 0) return;

    if (!cart[id]) {
      var rawPrice = btn.getAttribute('data-price');
      cart[id] = {
        name: btn.getAttribute('data-name'),
        // فاضي = المنتج مالوش سعر مسجّل، والكاشير هيكتبه
        price: rawPrice ? parseInt(rawPrice, 10) : null,
        manual: '',
        qty: 0,
        max: max,
        // ⚠ محفوظ عشان لو صاحب المحل غيّر الفرع ورجع في كلامه،
        // نرجّع الخانة لفرع **السلة** مش لأول فرع في القايمة.
        branchId: btn.getAttribute('data-branch') || ''
      };
    }
    if (cart[id].qty >= cart[id].max) return;
    cart[id].qty++;
    render();
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || !t.closest) return;

    var addBtn = t.closest('[data-add]');
    if (addBtn) { add(addBtn); return; }

    var inc = t.closest('[data-inc]');
    if (inc) {
      var idInc = inc.getAttribute('data-inc');
      if (cart[idInc] && cart[idInc].qty < cart[idInc].max) { cart[idInc].qty++; render(); }
      return;
    }

    var dec = t.closest('[data-dec]');
    if (dec) {
      var idDec = dec.getAttribute('data-dec');
      if (cart[idDec]) {
        cart[idDec].qty--;
        if (cart[idDec].qty <= 0) delete cart[idDec];
        render();
      }
      return;
    }
  });

  // ⚠ ما بنعملش render() هنا: إعادة البناء بتفقد التركيز من
  // الخانة والكاشير بيلاقي نفسه بيكتب في الفراغ. بنحدّث الرقم
  // والزرار بس.
  document.addEventListener('input', function (e) {
    var input = e.target;
    if (!input || !input.getAttribute) return;

    var id = input.getAttribute('data-price-for');
    if (!id || !cart[id]) return;

    cart[id].manual = input.value;

    var t = total();
    totalEl.innerHTML = money(t.sum) + '<span class="bal-cur">ج.م</span>';

    var treasury = document.getElementById('pos-treasury');
    submitEl.disabled = t.missing > 0 || !treasury || !treasury.value;
    submitEl.textContent = t.missing > 0
      ? 'اكتب سعر ' + t.missing + ' صنف'
      : 'تم البيع · ' + money(t.sum) + ' ج.م';

    var row = input.closest ? input.closest('.cart-line') : null;
    var amountEl = row ? row.querySelector('.cart-line-amount') : null;
    if (amountEl) {
      var p = manualPrice(cart[id].manual);
      amountEl.textContent = p === null ? '—' : money(p * cart[id].qty);
    }
  });

  clearEl.addEventListener('click', function () {
    if (!confirm('تفريغ السلة بالكامل؟')) return;
    cart = {};
    render();
  });

  // ── الفرع والبحث: مصفاة واحدة ──
  //
  // ⚠ الاتنين بيتحكّموا في نفس الخاصية («hidden»). لو كل واحد
  // كتبها لوحده، آخر واحد يشتغل بيدهس على التاني — تبحث فيرجع
  // منتج من فرع تاني، أو تغيّر الفرع فيرجع اللي البحث خبّاه.
  //
  // فالقرار بيتاخد مرة واحدة من الاتنين مع بعض.
  var search = document.getElementById('pos-search');
  var branchEl = document.getElementById('pos-branch');
  var treasuryEl = document.getElementById('pos-treasury');

  function applyFilters() {
    var q = search ? search.value.trim() : '';
    var branch = branchEl ? branchEl.value : '';

    var btns = document.querySelectorAll('[data-add]');
    for (var i = 0; i < btns.length; i++) {
      var name = btns[i].getAttribute('data-name') || '';
      var okName = q.length === 0 || name.indexOf(q) !== -1;
      var okBranch = !branch || btns[i].getAttribute('data-branch') === branch;
      btns[i].hidden = !(okName && okBranch);
    }
  }

  // ⚠ خزائن الفروع التانية بتتشال من القايمة مش بتتخبّى بس.
  // «hidden» على «<option>» مش مضمون في كل المتصفحات، والخانة
  // المعطّلة اللي شكلها مختارة بتخلّي الموظّف يبعت خزينة غلط.
  function syncTreasuries() {
    if (!treasuryEl || !branchEl) return;
    var branch = branchEl.value;
    var opts = treasuryEl.options;
    var firstVisible = null;

    for (var i = 0; i < opts.length; i++) {
      var same = opts[i].getAttribute('data-branch') === branch;
      opts[i].disabled = !same;
      opts[i].hidden = !same;
      if (same && firstVisible === null) firstVisible = i;
    }

    // لو المختار دلوقتي بقى من فرع تاني، ننقل لأول خزينة صالحة
    if (treasuryEl.selectedIndex < 0 || opts[treasuryEl.selectedIndex].disabled) {
      treasuryEl.selectedIndex = firstVisible === null ? -1 : firstVisible;
    }
  }

  if (search) search.addEventListener('input', applyFilters);

  if (branchEl) {
    branchEl.addEventListener('change', function () {
      // ⚠ السلة بتتفضّى مع تغيير الفرع، وده مقصود.
      //
      // السلة المخلوطة هي **نفس العطل** اللي الخانة دي اتعملت
      // عشانه: منتج من فرع وخزينة من فرع تاني، والقاعدة بترفض
      // بعد ما الزبون يكون واقف مستني.
      //
      // ⚠ والتأكيد بيظهر **لو فيه حاجة في السلة بس**. سؤال
      // "متأكد؟" على سلة فاضية بيعلّم الموظّف يدوس "موافق" من
      // غير ما يقرا — وساعتها التأكيد اللي بيهمّ بيضيع كمان.
      if (Object.keys(cart).length > 0) {
        if (!confirm('تغيير الفرع سيفرّغ السلة. متابعة؟')) {
          // ⚠ نرجّع الخانة لفرع السلة، مش لأول فرع في القايمة.
          var current = cart[Object.keys(cart)[0]].branchId;
          if (current) branchEl.value = current;
          return;
        }
        cart = {};
        render();
      }
      applyFilters();
      syncTreasuries();
    });

    syncTreasuries();
  }

  applyFilters();

  // ── إتمام البيع ──
  submitEl.addEventListener('click', async function () {
    var ids = Object.keys(cart);
    if (ids.length === 0) return;

    var items = [];
    for (var i = 0; i < ids.length; i++) {
      var line = cart[ids[i]];
      var entry = { productId: ids[i], quantity: line.qty };
      // السعر اليدوي بيتبعت للمنتجات اللي مالهاش سعر بس.
      // الخادم بيتجاهله لو المنتج له سعر مسجّل.
      if (line.price === null) entry.unitPrice = line.manual;
      items.push(entry);
    }

    submitEl.disabled = true;
    submitEl.textContent = 'جارٍ التسجيل…';

    try {
      var res = await fetch('/api/sales', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          treasuryId: document.getElementById('pos-treasury').value,
          items: items,
          customerName: document.getElementById('pos-cname').value || null,
          customerPhone: document.getElementById('pos-cphone').value || null,
          exitDate: document.getElementById('pos-exit').value || null,
          // ⚠ الخانة الفاضية بتتبعت null صراحةً = بلا ضمان.
          // لو بعتناها '' كان الخادم هيقراها صفر — و"بلا ضمان"
          // كانت هتبقى "ضمان صفر يوم".
          warrantyDays: warrantyValue()
        })
      });
      var data = await res.json().catch(function () { return null; });

      boxEl.hidden = false;
      if (res.ok) {
        boxEl.setAttribute('data-tone', 'ok');
        textEl.textContent = 'تم البيع — ' + money(data.totalPiastres) + ' ج.م';
        cart = {};
        // إعادة تحميل عشان الكميات المتاحة تتحدّث من الخادم.
        // لو سبناها زي ما هي، الموظّف ممكن يبيع كمية خلصت.
        setTimeout(function () { window.location.reload(); }, 1100);
        return;
      }

      boxEl.removeAttribute('data-tone');
      textEl.textContent = (data && data.error && data.error.message) || 'فشل البيع.';
    } catch (err) {
      boxEl.hidden = false;
      boxEl.removeAttribute('data-tone');
      // ⚠ مش بنقول "ما اتسجّلتش" — إحنا مش عارفين.
      // الطلب ممكن يكون وصل الخادم واتنفّذ والرد هو اللي ضاع.
      // لو قلنا للموظّف إنها فشلت، هيبيع تاني ويتسجّل بيعين.
      textEl.textContent = 'انقطع الاتصال. حدّث الصفحة وراجع آخر الفواتير قبل إعادة البيع.';
    } finally {
      render();
    }
  });

  // ── تعديل تاريخ الخروج بعد البيع ──
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-exit-open]') : null;
    if (!btn) return;

    var panel = document.getElementById('exit-' + btn.getAttribute('data-exit-open'));
    if (panel) panel.hidden = !panel.hidden;
  });

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-exit-save]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-exit-save');
    var input = document.getElementById('exit-in-' + id);
    if (!input || !input.value) return;

    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/sales/' + encodeURIComponent(id) + '/exit-date', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ exitDate: input.value })
      });
      var data = await res.json().catch(function () { return null; });

      boxEl.hidden = false;
      if (res.ok) {
        boxEl.setAttribute('data-tone', 'ok');
        textEl.textContent = 'تم تعديل تاريخ الخروج.';
        setTimeout(function () { window.location.reload(); }, 900);
        return;
      }
      boxEl.removeAttribute('data-tone');
      textEl.textContent = (data && data.error && data.error.message) || 'تعذّر التعديل.';
    } catch (err) {
      boxEl.hidden = false;
      boxEl.removeAttribute('data-tone');
      textEl.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  // ══════════ الاسترجاع ══════════
  //
  // ⚠ البنود بتتجاب من الخادم مش من الصفحة. الصفحة عندها إجمالي
  // الفاتورة بس؛ المتبقي في كل بند (بعد أي مرتجع سابق) حساب
  // الخادم لوحده. لو بنيناه هنا، مرتجعين ورا بعض من تابين
  // مفتوحين كانوا هيرجّعوا أكتر من اللي اتباع.
  var retLines = {}
  var retWarranty = {};
  var retCanOverride = {};

  /**
   * لافتة الضمان فوق البنود.
   *
   * ⚠ تلات رسايل مختلفة، وكل واحدة بتقول للموظّف **إيه اللي
   * هيحصل** مش بس إيه الحالة:
   *   في الضمان   → أخضر، استرجاع عادي
   *   انتهى/بلا   → أحمر + تأكيد لصاحب المحل
   *   انتهى/بلا   → أحمر + "راجع صاحب المحل" لغيره
   */
  function renderWarranty(id) {
    var host = document.getElementById('ret-warranty-' + id);
    if (!host) return;

    var w = retWarranty[id];
    host.textContent = '';
    if (!w) return;

    var line = document.createElement('p');
    line.className = 'field-hint';

    if (w.isCovered) {
      line.textContent = 'داخل الضمان — ينتهي ' + w.expiresOn +
        ' (باقٍ ' + w.daysLeft + ' يوم).';
      host.appendChild(line);
      return;
    }

    var box = document.createElement('div');
    box.className = 'alert-box';
    box.hidden = false;

    var msg = document.createElement('span');
    msg.textContent = (w.warrantyDays === null || w.warrantyDays === undefined)
      ? 'هذه الفاتورة بلا ضمان.'
      : 'انتهى الضمان يوم ' + w.expiresOn + '.';
    box.appendChild(msg);
    host.appendChild(box);

    if (!retCanOverride[id]) {
      line.textContent = 'الاسترجاع خارج الضمان يحتاج موافقة صاحب المحل.';
      host.appendChild(line);
      return;
    }

    // ⚠ التجاوز اختيار صريح بخانة منفصلة، مش زرار بيمشي لوحده.
    // لو خلّيناه تلقائي لصاحب المحل، هيتجاوز من غير ما ياخد باله
    // إنه تجاوز — والسجل هيمتلي تجاوزات ما حدش قصدها.
    var wrap = document.createElement('label');
    wrap.style.display = 'flex';
    wrap.style.gap = '8px';
    wrap.style.alignItems = 'center';
    wrap.style.marginTop = '6px';

    var chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.id = 'ret-ovr-' + id;
    wrap.appendChild(chk);

    var lbl = document.createElement('span');
    lbl.className = 'mv-sub';
    lbl.textContent = 'أوافق على الاسترجاع خارج الضمان — يُسجَّل باسمي.';
    wrap.appendChild(lbl);

    host.appendChild(wrap);
  };

  function retSay(id, text, ok) {
    var el = document.getElementById('ret-msg-' + id);
    if (!el) return;
    el.textContent = text;
    el.style.color = ok ? '' : 'var(--danger, #9E2B3E)';
  }

  function retRecalc(id) {
    var lines = retLines[id] || [];
    var refund = 0, original = 0, picked = 0;

    for (var i = 0; i < lines.length; i++) {
      var box = document.getElementById('ret-pick-' + id + '-' + i);
      if (!box || !box.checked) continue;

      var qEl = document.getElementById('ret-q-' + id + '-' + i);
      var uEl = document.getElementById('ret-u-' + id + '-' + i);
      var q = parseInt(qEl ? qEl.value : '0', 10);
      var u = Math.round(parseFloat(uEl ? uEl.value : '0') * 100);

      if (!isFinite(q) || q <= 0) continue;
      if (!isFinite(u) || u < 0) u = 0;

      refund += u * q;
      original += lines[i].unitPricePiastres * q;
      picked += 1;
    }

    var totalEl = document.getElementById('ret-total-' + id);
    var feeEl = document.getElementById('ret-fee-' + id);
    var formEl = document.getElementById('ret-form-' + id);

    if (totalEl) totalEl.textContent = '-' + money(refund);
    if (feeEl) {
      feeEl.textContent = original > refund
        ? 'قيمة البنود ' + money(original) + ' · رسوم استرجاع ' + money(original - refund)
        : '';
    }
    if (formEl) formEl.hidden = picked === 0;
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-ret-open]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-ret-open');
    var panel = document.getElementById('ret-' + id);
    if (!panel) return;

    if (!panel.hidden) { panel.hidden = true; return; }
    panel.hidden = false;

    if (retLines[id]) return;   // اتجابت قبل كده

    retSay(id, 'جارٍ قراءة بنود الفاتورة…', true);
    try {
      var res = await fetch('/api/returns/context/' + encodeURIComponent(id), {
        credentials: 'same-origin'
      });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        retSay(id, (data && data.error && data.error.message) || 'تعذّر قراءة الفاتورة.', false);
        return;
      }

      // ══════════ حالة الضمان ══════════
      //
      // ⚠ بتتعرض **قبل** ما الموظّف يختار أي بند.
      // زرار بيرفض بعد الضغط أسوأ من لافتة بتقول ليه قبلها —
      // خصوصًا والزبون واقف قدّامه.
      retWarranty[id] = data.warranty || null;
      retCanOverride[id] = data.canOverride === true;
      renderWarranty(id);

      retLines[id] = data.lines || [];
      var host = document.getElementById('ret-lines-' + id);
      if (!host) return;
      host.textContent = '';

      if (retLines[id].length === 0) {
        retSay(id, 'لا توجد بنود في هذه الفاتورة.', false);
        return;
      }

      var any = false;
      for (var i = 0; i < retLines[id].length; i++) {
        var ln = retLines[id][i];
        var done = ln.quantityRemaining <= 0;
        if (!done) any = true;

        var row = document.createElement('div');
        row.className = 'mv-row';
        if (done) row.style.opacity = '0.5';

        var head = document.createElement('label');
        head.style.display = 'flex';
        head.style.gap = '8px';
        head.style.alignItems = 'flex-start';

        var pick = document.createElement('input');
        pick.type = 'checkbox';
        pick.id = 'ret-pick-' + id + '-' + i;
        pick.disabled = done;
        pick.setAttribute('data-ret-calc', id);
        head.appendChild(pick);

        var info = document.createElement('div');
        var t = document.createElement('span');
        t.className = 'mv-title';
        t.textContent = ln.productName;
        info.appendChild(t);

        var sub = document.createElement('span');
        sub.className = 'mv-sub';
        sub.textContent = done
          ? 'اترجّع بالكامل'
          : 'متبقٍ ' + ln.quantityRemaining + ' من ' + ln.quantitySold +
            ' · سعر الوحدة ' + money(ln.unitPricePiastres) +
            (ln.serialNumber ? ' · ' + ln.serialNumber : '');
        info.appendChild(sub);
        head.appendChild(info);
        row.appendChild(head);

        if (!done) {
          var fields = document.createElement('div');
          fields.style.display = 'flex';
          fields.style.gap = '8px';
          fields.style.marginTop = '6px';

          var q = document.createElement('input');
          q.className = 'field-input';
          q.id = 'ret-q-' + id + '-' + i;
          q.type = 'number';
          q.min = '1';
          q.max = String(ln.quantityRemaining);
          q.value = '1';
          q.dir = 'ltr';
          q.setAttribute('data-ret-calc', id);
          fields.appendChild(q);

          var u = document.createElement('input');
          u.className = 'field-input';
          u.id = 'ret-u-' + id + '-' + i;
          u.type = 'text';
          u.inputMode = 'decimal';
          u.dir = 'ltr';
          u.value = money(ln.unitPricePiastres);
          u.setAttribute('data-ret-calc', id);
          fields.appendChild(u);

          row.appendChild(fields);
        }

        host.appendChild(row);
      }

      retSay(id, any ? 'اختر البنود المرتجعة والمبلغ لكل وحدة.'
                     : 'كل بنود الفاتورة اترجّعت بالفعل.', any);
      retRecalc(id);
    } catch (err) {
      retSay(id, 'تعذّر الاتصال بالخادم.', false);
    }
  });

  // إعادة الحساب مع أي تغيير — الرقم اللي بيطلع من الدرج لازم
  // يفضل صحيح لحظة بلحظة، مش وقت الضغط بس.
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (el && el.getAttribute && el.getAttribute('data-ret-calc')) {
      retRecalc(el.getAttribute('data-ret-calc'));
    }
  });
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el && el.getAttribute && el.getAttribute('data-ret-calc')) {
      retRecalc(el.getAttribute('data-ret-calc'));
    }
  });

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-ret-go]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-ret-go');
    var lines = retLines[id] || [];
    var items = [];

    for (var i = 0; i < lines.length; i++) {
      var box = document.getElementById('ret-pick-' + id + '-' + i);
      if (!box || !box.checked) continue;

      var q = parseInt((document.getElementById('ret-q-' + id + '-' + i) || {}).value, 10);
      var u = Math.round(parseFloat((document.getElementById('ret-u-' + id + '-' + i) || {}).value) * 100);

      if (!isFinite(q) || q <= 0) { retSay(id, 'كمية غير صالحة.', false); return; }
      if (!isFinite(u) || u < 0) { retSay(id, 'مبلغ غير صالح.', false); return; }
      if (q > lines[i].quantityRemaining) {
        retSay(id, 'الكمية أكبر من المتبقي في «' + lines[i].productName + '».', false);
        return;
      }

      items.push({ saleItemId: lines[i].saleItemId, quantity: q, unitRefundPiastres: u });
    }

    if (items.length === 0) { retSay(id, 'اختر بندًا واحدًا على الأقل.', false); return; }

    var tre = document.getElementById('ret-tre-' + id);
    if (!tre || !tre.value) { retSay(id, 'اختر الخزينة.', false); return; }

    // ⚠ الحارس ده قدّام الرسالة العامة عن قصد: السبب المحدّد
    // أنفع من "فشل الاسترجاع" اللي بيرجع من الخادم بعد رحلة.
    var w = retWarranty[id];
    var outside = w && !w.isCovered;
    var ovrEl = document.getElementById('ret-ovr-' + id);
    var override = !!(ovrEl && ovrEl.checked);

    if (outside && !retCanOverride[id]) {
      retSay(id, 'الاسترجاع خارج الضمان يحتاج موافقة صاحب المحل.', false);
      return;
    }
    if (outside && !override) {
      retSay(id, 'علّم على الموافقة بالاسترجاع خارج الضمان أولًا.', false);
      return;
    }

    var ask = outside
      ? 'استرجاع خارج الضمان — يُسجَّل باسمك في سجل التدقيق. تأكيد؟'
      : 'تأكيد الاسترجاع؟ الفلوس هتطلع من الخزينة والبضاعة هتروح لرفّ المراجعة.';
    if (!confirm(ask)) return;

    var why = document.getElementById('ret-why-' + id);
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/returns/sale/' + encodeURIComponent(id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          treasuryId: tre.value,
          items: items,
          reason: why ? why.value : null,
          overrideWarranty: override
        })
      });
      var data = await res.json().catch(function () { return null; });

      boxEl.hidden = false;
      if (res.ok && data && data.ok) {
        boxEl.setAttribute('data-tone', 'ok');
        textEl.textContent = 'تم الاسترجاع — خرج ' + money(data.refundedPiastres) +
          (data.feePiastres > 0 ? ' · رسوم ' + money(data.feePiastres) : '');
        setTimeout(function () { window.location.reload(); }, 1100);
        return;
      }
      boxEl.removeAttribute('data-tone');
      textEl.textContent = (data && data.error && data.error.message) || 'تعذّر الاسترجاع.';
    } catch (err) {
      boxEl.hidden = false;
      boxEl.removeAttribute('data-tone');
      textEl.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  // ══════════ طباعة الفاتورة ══════════
  //
  // ⚠ البنود بتتجاب من الخادم وقت الطباعة مش مع الصفحة.
  // قايمة الفواتير عندها الإجمالي بس؛ تحميل بنود عشر فواتير
  // مقدّمًا عشان يمكن تطبع واحدة = شغل ضايع.
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-print-sale]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-print-sale');
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/sales/' + encodeURIComponent(id), {
        credentials: 'same-origin'
      });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        boxEl.hidden = false;
        boxEl.removeAttribute('data-tone');
        textEl.textContent = (data && data.error && data.error.message) || 'تعذّر جلب الفاتورة.';
        return;
      }

      var sale = data.sale;
      var lines = '';
      var items = sale.items || [];

      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        lines += '<div class="pr-row"><span>' + it.productName +
          (it.quantity > 1 ? ' × ' + it.quantity : '') + '</span>' +
          '<span>' + window.printMoney(it.lineTotalPiastres) + '</span></div>';
      }

      window.printHtml(
        '<div class="pr-doc">' +
          '<div class="pr-head">' +
            '<span class="pr-shop">' + SHOP_NAME + '</span>' +
            '<span>فاتورة ' + String(sale.id).slice(0, 8) + '</span>' +
          '</div>' +
          '<div class="pr-row"><span>التاريخ</span><span>' +
            (sale.exitDate || '') + '</span></div>' +
          (sale.customerName
            ? '<div class="pr-row"><span>العميل</span><span>' + sale.customerName + '</span></div>'
            : '') +
          '<div style="margin-top:10px">' + lines + '</div>' +
          '<div class="pr-row pr-total"><span>الإجمالي</span><span>' +
            window.printMoney(sale.totalPiastres) + ' ج.م</span></div>' +
          '<div class="pr-note">شكرًا لتعاملكم معنا. الاسترجاع خلال المدة المتفق عليها ' +
            'وبحالة الجهاز الأصلية.</div>' +
        '</div>'
      );
    } catch (err) {
      boxEl.hidden = false;
      boxEl.removeAttribute('data-tone');
      textEl.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  render();
})();
`;
}


// ═══════════════════ 6) شاشة المنتجات ═══════════════════

export interface ProductsPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  /** inventory.adjust — يقدر يضيف ويعدّل ويورّد */
  canEdit: boolean;
  /** profit.view_real — يشوف التكلفة */
  canSeeCost: boolean;
  /** inventory.reorder_point — صاحب المحل وحده يحدّد الحد */
  canSetReorder: boolean;
  canSell: boolean;
  canUseTreasury: boolean;
  /**
   * أدراج المنتجات — شجرة على مستويين.
   *
   * `parentId` فاضي = قسم رئيسي (إكسسوار · مكملات)
   * `parentId` موجود = درج جوّاه (جرابات · شواحن)
   *
   * ⚠ والعدّ محسوب في القاعدة مش هنا. لو الشاشة عدّت بنفسها،
   * كانت هتعدّ **المعروض** — والقايمة محدودة بـ500 صف، فالرقم
   * هيكذب أول ما المخزون يكبر.
   */
  categories: Array<{
    id: string;
    parentId: string | null;
    name: string;
    sortOrder: number;
    isSystem: boolean;
    productCount: number;
  }>;
  /**
   * سجل موديلات الموبايل — البُعد التاني جنب الدرج.
   *
   * الدرج بيقول **إيه الصنف**، والموديل بيقول **لأنهي جهاز**.
   * والفلترين بيتجمعوا: "جرابات" + "١٢ برو ماكس".
   *
   * ⚠ `deviceCount` بالكمية مش بعدد الصفوف — الجهاز صفّه بيفضل
   * موجود بعد ما يتباع وكميته بتبقى صفر.
   */
  models: Array<{
    id: string;
    name: string;
    brand: string | null;
    sortOrder: number;
    deviceCount: number;
    accessoryCount: number;
  }>;
  /** للمالك بس — لاختيار الفرع عند الإضافة */
  branches: Array<{ id: string; name: string }>;
  products: Array<{
    id: string;
    name: string;
    productType: 'device' | 'accessory';
    serialNumber: string | null;
    source: string | null;
    entryDate: string;
    pricePiastres: number | null;
    costPiastres?: number;
    quantityOnHand: number;
    isActive: boolean;
    reorderPoint: number;
    customsCleared: boolean;
    /**
     * ⚠ الحقلين دول كانوا **ناقصين من النوع** رغم إن الصفحة
     * بتقرا منهم في أربع أماكن (`23_device_specs.sql` ضاف
     * الأعمدة، والنوع هنا ما اتحدّثش).
     *
     * `tsc` كان بيرنّ عليهم من شهور — بس الفحص مش بيتشغّل من
     * الموبايل، فالتحذير فضل واقف مكانه.
     */
    storageCapacity: string | null;
    /** 0–100. null = ما اتقاسش — وهي **غير** الصفر. */
    batteryHealth: number | null;
    /** درج المنتج. null = غير مصنّف. */
    categoryId: string | null;
    /** موديل الجهاز. null = غير محدّد. */
    modelId: string | null;
  }>;
  /** فروع المحل الأخرى — للتحويل. فاضية = مفيش فرع تاني */
  transferTargets: Array<{ id: string; name: string }>;
  /** maintenance.manage — إرسال جهاز المحل للورشة */
  canSendToRepair: boolean;
  /** ورش الصيانة — لقائمة الاختيار */
  repairShops: Array<{ id: string; name: string }>;
  /** تاريخ النهاردة بتوقيت القاهرة — قيمة افتراضية لحقل التاريخ */
  today: string;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * شاشة المنتجات.
 *
 * ══ ملاحظة على التكلفة ══
 * لو الحقل `costPiastres` مش موجود في الكائن، يبقى اللي بيتفرّج
 * مالوش صلاحية يشوفه — وما وصلوش من الخادم أصلاً.
 *
 * الشرط `p.costPiastres !== undefined` تحت **مش** هو الحماية.
 * هو مجرد تعامل مع حقيقة إن الحقل مش موجود. الحماية اتعملت خلاص
 * في طبقة قاعدة البيانات قبل ما البيانات تسيب الخادم.
 */
export function productsPage(data: ProductsPageData): Html {
  const rows =
    data.products.length === 0
      ? html`<div class="empty">
          <p class="empty-title">لا توجد منتجات بعد</p>
          <p class="empty-note">
            ${data.canEdit
              ? 'ابدأ بإضافة أول منتج من القسم أعلاه.'
              : 'يضيف المديرُ المنتجاتِ.'}
          </p>
        </div>`
      : html`${data.products.map((p) => {
          const isDevice = p.productType === 'device';
          const priceLabel =
            p.pricePiastres === null ? 'بلا سعر' : `${formatPiastres(p.pricePiastres)} ج.م`;

          return html`<div class="prod-row" data-row="${p.id}" data-pid="${p.id}"
            data-searchable="${p.name} ${p.serialNumber ?? ''}"
            data-name="${p.name}" data-serial="${p.serialNumber ?? ''}"
            data-price="${p.pricePiastres === null ? '' : formatPiastres(p.pricePiastres)}"
            data-storage="${p.storageCapacity ?? ''}"
            data-battery="${p.batteryHealth === null ? '' : String(p.batteryHealth)}"
            data-customs="${p.customsCleared ? 'true' : 'false'}"
            data-cat="${p.categoryId ?? '__none__'}"
            data-model="${p.modelId ?? '__none__'}"
            data-entry="${formatDate(p.entryDate)}">
            <div class="prod-row-main">
              <span class="prod-row-name" data-off="${p.isActive ? 'false' : 'true'}">
                ${p.name}
                <span class="type-tag" data-type="${p.productType}">
                  ${isDevice ? 'جهاز' : 'إكسسوار'}
                </span>
              </span>

              <span class="prod-row-sub">
                ${priceLabel}${p.costPiastres !== undefined
                  ? ` · تكلفة ${formatPiastres(p.costPiastres)}`
                  : ''}${p.source ? ` · من ${p.source}` : ''} · دخل ${formatDate(p.entryDate)}${p.isActive
                  ? ''
                  : ' · موقوف'}
              </span>

              ${isDevice && p.serialNumber
                ? html`<span class="serial">SN: ${p.serialNumber}</span>`
                : ''}
            </div>

            <div class="prod-row-side">
              <span class="prod-row-qty" data-zero="${p.quantityOnHand === 0 ? 'true' : 'false'}">
                ${isDevice ? (p.quantityOnHand > 0 ? 'متاح' : 'انباع') : String(p.quantityOnHand)}
              </span>
              ${data.canEdit
                ? html`<button class="btn-mini" type="button" data-edit="${p.id}">تعديل</button>`
                : ''}
            </div>

            ${data.canEdit
              ? html`<div class="prod-edit" id="edit-${p.id}" hidden>

                  <div class="price-now">
                    <span class="price-now-label">سعر البيع الحالي</span>
                    <span class="price-now-value" data-empty="${p.pricePiastres === null ? 'true' : 'false'}">
                      ${p.pricePiastres === null ? 'لم يُحدَّد بعد' : formatPiastres(p.pricePiastres)}
                    </span>
                  </div>

                  <button class="btn-mini" type="button" data-price-open="${p.id}">
                    تعديل سعر البيع
                  </button>

                  <div class="prod-edit-grid" id="price-box-${p.id}" hidden style="margin-top:10px">
                    <div class="field">
                      <label class="field-label" for="price-${p.id}">سعر البيع الجديد</label>
                      <input class="field-input" id="price-${p.id}" type="text"
                        inputmode="decimal" dir="ltr" autocomplete="off" placeholder="مثال: 150">
                      <p class="field-hint">اتركه فارغًا واحفظ لإزالة السعر تمامًا.</p>
                    </div>
                    ${p.costPiastres !== undefined
                      ? html`<div class="field">
                          <label class="field-label" for="cost-${p.id}">التكلفة</label>
                          <input class="field-input" id="cost-${p.id}" type="text"
                            inputmode="decimal" dir="ltr" value="${formatPiastres(p.costPiastres)}">
                        </div>`
                      : ''}
                    <div class="field" style="grid-column:1/-1">
                      <button class="btn-mini" type="button" data-save-price="${p.id}">
                        حفظ السعر الجديد
                      </button>
                    </div>
                  </div>

                  <div class="price-log" id="log-${p.id}" hidden>
                    <p class="price-log-title">آخر تغييرات السعر</p>
                    <div id="log-body-${p.id}"></div>
                  </div>

                  <div class="prod-edit-grid" style="margin-top:12px">
                    ${isDevice
                      ? html`<div class="field">
                          <label class="field-label" for="serial-${p.id}">الرقم التسلسلي</label>
                          <input class="field-input" id="serial-${p.id}" type="text"
                            dir="ltr" value="${p.serialNumber ?? ''}">
                        </div>`
                      : html`<div class="field">
                          <label class="field-label" for="stock-${p.id}">تعديل الكمية</label>
                          <input class="field-input" id="stock-${p.id}" type="text"
                            inputmode="numeric" dir="ltr" placeholder="5 أو -2">
                          <p class="field-hint">اكتب الفرق لا الرقم النهائي.</p>
                        </div>`}

                    <div class="field">
                      <label class="field-label" for="source-${p.id}">مصدر الشراء</label>
                      <input class="field-input" id="source-${p.id}" type="text"
                        maxlength="80" value="${p.source ?? ''}">
                    </div>

                    <div class="field">
                      <label class="field-label" for="entry-${p.id}">تاريخ الدخول</label>
                      <input class="field-input" id="entry-${p.id}" type="date"
                        dir="ltr" value="${p.entryDate}" max="${data.today}">
                    </div>
                  </div>

                  ${data.canSetReorder && !isDevice
                    ? html`<div class="field">
                        <label class="field-label" for="reorder-${p.id}">
                          الحد الأدنى للتنبيه
                        </label>
                        <input class="field-input" id="reorder-${p.id}" type="number"
                          min="0" dir="ltr" value="${String(p.reorderPoint)}">
                        <p class="field-hint">
                          ${p.reorderPoint > 0
                            ? `ينبّهك عند ${p.reorderPoint} أو أقل. صفر = معطّل.`
                            : 'صفر = بلا تنبيه. اكتب رقمًا لتفعيله.'}
                        </p>
                      </div>`
                    : ''}

                  ${isDevice
                    ? html`<div class="field">
                        <label class="field-label" for="storage-${p.id}">المساحة</label>
                        <input class="field-input" id="storage-${p.id}" type="text"
                          dir="ltr" maxlength="32" placeholder="256GB"
                          value="${p.storageCapacity ?? ''}">

                        <label class="field-label" for="battery-${p.id}">صحة البطارية ٪</label>
                        <input class="field-input" id="battery-${p.id}" type="number"
                          min="0" max="100" dir="ltr"
                          value="${p.batteryHealth === null ? '' : String(p.batteryHealth)}">
                        <p class="field-hint">فارغة تعني «لم تُقَس» — وهي غير الصفر.</p>
                      </div>

                      <div class="field">
                        <label class="field-label" for="customs-${p.id}">
                          ضريبة
                        </label>
                        <select class="field-input" id="customs-${p.id}">
                          <option value="true" ${p.customsCleared ? 'selected' : ''}>
                            خالص
                          </option>
                          <option value="false" ${p.customsCleared ? '' : 'selected'}>
                            ضريبة
                          </option>
                        </select>
                        <p class="field-hint">
                          تسجيل يدوي من المستلم. لا يوجد ربط بأي جهة خارجية.
                        </p>
                      </div>`
                    : ''}

                  ${isDevice && data.canSendToRepair
                    ? html`<div class="field">
                        <button class="btn-mini" type="button" data-rep-open="${p.id}">
                          تحويل للصيانة
                        </button>

                        <div id="rep-${p.id}" hidden>
                          <label class="field-label" for="repshop-${p.id}">محل الصيانة</label>
                          <select class="field-input" id="repshop-${p.id}">
                            <option value="">— داخليًا —</option>
                            ${data.repairShops.map(
                              (sh) => html`<option value="${sh.id}">${sh.name}</option>`,
                            )}
                          </select>

                          <label class="field-label" for="repfault-${p.id}">وصف العطل</label>
                          <input class="field-input" id="repfault-${p.id}" type="text"
                            maxlength="500" autocomplete="off">

                          <label class="field-label" for="repcost-${p.id}">
                            التكلفة المتوقّعة
                          </label>
                          <input class="field-input" id="repcost-${p.id}" type="text"
                            inputmode="decimal" dir="ltr">

                          <p class="field-hint">
                            تُخصم القطعة من المخزون فورًا — لا يصحّ أن تُباع وهي في الورشة.
                            التكلفة الفعلية تُكتب عند الاستلام.
                          </p>

                          <button class="btn-mini" type="button" data-rep-send="${p.id}">
                            إرسال للصيانة
                          </button>
                        </div>

                        <div id="rephist-${p.id}"></div>
                      </div>`
                    : ''}

                  ${data.transferTargets.length > 0
                    ? html`<div class="field">
                        <label class="field-label" for="trto-${p.id}">تحويل إلى فرع</label>
                        <select class="field-input" id="trto-${p.id}">
                          <option value="">— اختر الفرع —</option>
                          ${data.transferTargets.map(
                            (b) => html`<option value="${b.id}">${b.name}</option>`,
                          )}
                        </select>
                        ${isDevice
                          ? ''
                          : html`<input class="field-input" id="trq-${p.id}" type="number"
                              min="1" dir="ltr" value="1" placeholder="الكمية">`}
                        <button class="btn-mini" type="button" data-tr-send="${p.id}"
                          data-device="${isDevice ? 'true' : 'false'}">
                          إرسال التحويل
                        </button>
                        <p class="field-hint">
                          تُخصم الكمية فورًا — البضاعة تركت الرفّ ولا يصحّ أن تُباع.
                        </p>
                      </div>`
                    : ''}

                  <div class="prod-edit-actions">
                    ${isDevice && p.serialNumber
                      ? html`<button class="btn-mini" type="button"
                          data-label="${p.id}">طباعة ملصق</button>`
                      : ''}
                    ${isDevice
                      ? html`<button class="btn-mini" type="button" data-save-details="${p.id}">
                          حفظ البيانات
                        </button>`
                      : html`<button class="btn-mini" type="button" data-save-stock="${p.id}">
                            تعديل الكمية
                          </button>
                          <button class="btn-mini" type="button" data-save-details="${p.id}">
                            حفظ البيانات
                          </button>`}
                    <button class="btn-mini" data-danger="${p.isActive ? 'true' : 'false'}"
                      type="button" data-toggle="${p.id}" data-active="${p.isActive ? 'true' : 'false'}">
                      ${p.isActive ? 'إيقاف المنتج' : 'إعادة تفعيل'}
                    </button>
                  </div>
                </div>`
              : ''}
          </div>`;
        })}`;

  const addPanel = !data.canEdit
    ? ''
    : html`<details class="panel">
        <summary>إضافة منتج</summary>
        <div class="panel-body">
          <div class="alert-box" id="addmsg" role="alert" hidden><span id="addmsg-text"></span></div>

          <form id="addf" novalidate>
            ${data.branches.length > 0
              ? html`<div class="field">
                  <label class="field-label" for="np-branch">الفرع</label>
                  <select class="field-input" id="np-branch">
                    ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
                  </select>
                </div>`
              : ''}

            <div class="field">
              <label class="field-label" for="np-type">نوع المنتج</label>
              <select class="field-input" id="np-type">
                <option value="accessory">إكسسوار — صنف بكمية</option>
                <option value="device">جهاز — قطعة برقم تسلسلي</option>
              </select>
              <p class="field-hint">
                الجهاز قطعة واحدة لها رقم تسلسلي. كل وحدة تُضاف على حدة حتى لو كانت الطراز نفسه.
              </p>
            </div>

            <div class="field">
              <label class="field-label" for="np-name">اسم المنتج</label>
              <input class="field-input" id="np-name" type="text" maxlength="80" required>
            </div>

            <div class="field" id="np-serial-field" hidden>
              <label class="field-label" for="np-serial">الرقم التسلسلي</label>
              <input class="field-input" id="np-serial" type="text" dir="ltr"
                autocomplete="off" maxlength="64">
              <p class="field-hint">الكمية تُضبط على قطعة واحدة تلقائيًا.</p>
            </div>

            <!-- ══ درج الإكسسوار ══
                 ⚠ قايمة واحدة بمجموعات، مش قايمتين متسلسلتين
                 (قسم ← درج). القسم مش اختيار — هو عنوان بيوضّح
                 مكان الدرج. وقايمتين على شاشة موبايل معناها
                 نقرتين وانتظار بينهم بلا فايدة.

                 ⚠ ومخفية للأجهزة: الجهاز هيتجمّع بموديله في
                 مرحلة تانية، والدرج ده للإكسسوار والمكملات. -->
            <div class="field" id="np-cat-field" hidden>
              <label class="field-label" for="np-category">الدرج</label>
              <select class="field-input" id="np-category">
                <option value="">— بدون درج —</option>
                ${data.categories
                  .filter((c) => c.parentId === null)
                  .map(
                    (section) => html`<optgroup label="${section.name}">
                      ${data.categories
                        .filter((d) => d.parentId === section.id)
                        .map(
                          (d) => html`<option value="${d.id}" data-parent="${section.id}">
                            ${d.name}
                          </option>`,
                        )}
                    </optgroup>`,
                  )}
              </select>
              <p class="field-hint">
                محتاج درج جديد؟ أضِفه من شرائط الأدراج فوق قائمة المخزون.
              </p>
            </div>

            <!-- ══ الموديل ══
                 ⚠ ظاهر **للنوعين**، على عكس الدرج.

                 الجهاز موديله هو. والإكسسوار موديله الجهاز اللي
                 بيركب عليه — جراب ١٢ برو ماكس ما ينفعش على ١٣،
                 والزبون بيسأل بالموديل مش بالصنف. -->
            <div class="field">
              <label class="field-label" for="np-model">الموديل</label>
              <select class="field-input" id="np-model">
                <option value="">— بدون موديل —</option>
                ${data.models.map(
                  (m) => html`<option value="${m.id}">
                    ${m.brand ? `${m.brand} — ${m.name}` : m.name}
                  </option>`,
                )}
              </select>
              <p class="field-hint">
                موديل جديد؟ أضِفه من شرائط الموديلات فوق قائمة المخزون.
              </p>
            </div>

            <!-- ══ مواصفات الجهاز ══

                 ⚠ دي كانت في شاشة التعديل بس. المستلم كان بيسجّل
                 الجهاز، وبعدين يفتحه تاني ويكمّل مواصفاته —
                 خطوتين لفعل واحد، والتانية هي اللي بتتنسي.

                 دلوقتي بتظهر مع اختيار "جهاز"، فالبيان بيتكتب
                 كامل مرة واحدة وقت الاستلام.

                 ⚠ وبتفضل موجودة في شاشة التعديل زي ما هي — الإدخال
                 السريع حاجة والتصحيح بعدين حاجة تانية. -->
            <div id="np-device-fields" hidden>
              <div class="field">
                <label class="field-label" for="np-storage">المساحة</label>
                <input class="field-input" id="np-storage" type="text"
                  dir="ltr" maxlength="32" placeholder="256GB">
              </div>

              <div class="field">
                <label class="field-label" for="np-battery">صحة البطارية ٪</label>
                <input class="field-input" id="np-battery" type="number"
                  min="0" max="100" dir="ltr">
                <p class="field-hint">فارغة تعني «لم تُقَس» — وهي غير الصفر.</p>
              </div>

              <div class="field">
                <label class="field-label" for="np-customs">ضريبة</label>
                <select class="field-input" id="np-customs">
                  <option value="true">خالص</option>
                  <!-- ⚠ ده الافتراضي عن قصد. "خالص" ادّعاء بيتقال
                       لما حد يتأكد، مش لما حد يسيب الخانة. -->
                  <option value="false" selected>ضريبة</option>
                </select>
                <p class="field-hint">
                  تسجيل يدوي من المستلم. لا يوجد ربط بأي جهة خارجية.
                </p>
              </div>
            </div>

            <div class="field" id="np-qty-field">
              <label class="field-label" for="np-qty">الكمية الحالية</label>
              <input class="field-input" id="np-qty" type="text" inputmode="numeric"
                dir="ltr" value="0">
            </div>

            <div class="field">
              <label class="field-label" for="np-price">سعر البيع (اختياري)</label>
              <input class="field-input" id="np-price" type="text" inputmode="decimal"
                dir="ltr" autocomplete="off">
              <p class="field-hint">
                اتركه فارغًا إن لم يتحدّد بعد. يطلبه النظام عند البيع.
              </p>
            </div>

            <div class="field">
              <label class="field-label" for="np-cost">التكلفة (اختياري)</label>
              <input class="field-input" id="np-cost" type="text" inputmode="decimal"
                dir="ltr" autocomplete="off">
            </div>

            <div class="field">
              <label class="field-label" for="np-source">مصدر الشراء (اختياري)</label>
              <input class="field-input" id="np-source" type="text" maxlength="80">
              <p class="field-hint">اسم التاجر أو المحل.</p>
            </div>

            <div class="field">
              <label class="field-label" for="np-entry">تاريخ الدخول</label>
              <input class="field-input" id="np-entry" type="date" dir="ltr"
                value="${data.today}" max="${data.today}">
            </div>

            <button class="btn-primary" id="addbtn" type="submit">إضافة المنتج</button>
          </form>
        </div>
      </details>`;

  return shell({
    title: 'المنتجات',
    tenantName: data.tenantName,
    script: productsScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.tenantName,
    ),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="prodmsg" role="alert" hidden><span id="prodmsg-text"></span></div>

  ${addPanel}

  <details class="panel" id="tr-panel" hidden>
    <summary>تحويلات معلّقة <span id="tr-count"></span></summary>
    <div class="panel-body">
      <p class="field-hint">
        بضاعة بالطريق بين الفروع. الكمية اتخصمت من الفرع المُرسِل بالفعل،
        ومش هتظهر في مخزون المستقبِل إلا بعد تأكيد الاستلام.
      </p>
      <div id="tr-rows"></div>
    </div>
  </details>

  ${data.canEdit
    ? html`<details class="panel" id="qr-panel" hidden>
        <summary>رفّ المراجعة <span id="qr-count"></span></summary>
        <div class="panel-body">
          <p class="field-hint">
            بضاعة رجعت من عملاء ولسه ما اتفحصتش. مش معروضة للبيع حاليًا —
            راجعها وقرّر: سليمة ترجع للمخزون، أو تالفة تتشطب.
          </p>
          <div id="qr-rows"></div>
        </div>
      </details>`
    : ''}

  <details class="panel" open>
    <summary>المخزون (${String(data.products.length)})</summary>
    <div class="panel-body">
      <!-- ══ شرائط الأدراج والموديلات ══

           ⚠ **صفّين لبُعدين مستقلين**، والفلاتر بتتجمع:
             الدرج   → إيه الصنف  (جراب · شاحن)
             الموديل → لأنهي جهاز (١٢ برو ماكس)

           "جرابات" + "١٢ برو ماكس" = جرابات الـ١٢ برو ماكس.
           وصفّ واحد مدمج كان هيحتاج ضرب الاتنين في بعض — تلات
           أدراج × عشر موديلات = تلاتين شريط.

           ⚠ ودي **فلاتر مش شجرة**. بتخفي صفوف مش بتفتح شاشة،
           فالبحث والاتنين بيشتغلوا مع بعض والرجوع نقرة واحدة.

           ⚠ والعدّ جاي من قاعدة البيانات مش من عدّ الصفوف
           المعروضة: القايمة محدودة بـ500 صف. -->
      <div class="drawers-row">
        <span class="drawers-label">الدرج</span>
        <div class="drawers" id="drawers">
          <button class="drawer" type="button" data-drawer="" data-on>الكل</button>
          ${data.categories
            .filter((c) => c.parentId === null)
            .map(
              (section) => html`${data.categories
                .filter((d) => d.parentId === section.id)
                .map(
                  (d) => html`<button class="drawer" type="button" data-drawer="${d.id}">
                    ${d.name}
                    <span class="drawer-n">${String(d.productCount)}</span>
                  </button>`,
                )}`,
            )}
          <button class="drawer" type="button" data-drawer="__none__">
            غير مصنّف
          </button>
          ${data.canEdit
            ? html`<button class="drawer" type="button" id="drawer-add" data-add-drawer>+</button>`
            : ''}
        </div>
      </div>

      <div class="drawers-row">
        <span class="drawers-label">الموديل</span>
        <div class="drawers" id="models">
          <button class="drawer" type="button" data-model="" data-on>الكل</button>
          ${data.models.map(
            (m) => html`<button class="drawer" type="button" data-model="${m.id}">
              ${m.name}
              <!-- ⚠ الرقمين منفصلين: أجهزة · إكسسوار.
                   رقم مجمّع كان هيقول "٧" ومش هتعرف سبع أجهزة
                   ولا سبع جرابات. -->
              <span class="drawer-n">${String(m.deviceCount)}·${String(m.accessoryCount)}</span>
            </button>`,
          )}
          <button class="drawer" type="button" data-model="__none__">
            بلا موديل
          </button>
          ${data.canEdit
            ? html`<button class="drawer" type="button" id="model-add" data-add-model>+</button>`
            : ''}
        </div>
      </div>

      <label class="field-label" for="prod-search">بحث</label>
      <input class="field-input" id="prod-search" type="search"
        placeholder="اسم أو سريال" autocomplete="off" spellcheck="false">
      <button class="btn-mini" type="button" id="prod-scan">مسح بالكاميرا</button>
      <p class="field-hint" id="prod-search-note">
        امسح بالكاميرا، أو بالماسح الموصول بالكمبيوتر، أو اكتب جزءًا من الاسم.
      </p>
      ${rows}
    </div>
  </details>
</main>

${tabBar('products', {
  showPos: data.canSell,
  showProducts: true,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function productsScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  /** بيتطبع على الملصق — لازم يتمرّر صراحةً */
  shopName: string,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var SHOP_NAME = ${JSON.stringify(shopName)};

  var box = document.getElementById('prodmsg');
  var text = document.getElementById('prodmsg-text');

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    text.textContent = message;
    box.scrollIntoView({ block: 'nearest' });
  }

  function money(piastres) {
    if (piastres === null || piastres === undefined) return 'بلا سعر';
    var abs = Math.abs(Math.trunc(piastres));
    return Math.floor(abs / 100).toLocaleString('en-US') + '.' + String(abs % 100).padStart(2, '0');
  }

  async function send(url, body, btn, busyLabel) {
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = busyLabel;

    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json().catch(function () { return null; });

      if (res.ok) return data || {};
      say((data && data.error && data.error.message) || 'فشل التنفيذ.', false);
      return null;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  // ── فتح وقفل لوحة التعديل ──
  document.addEventListener('click', function (e) {
    var toggle = e.target.closest ? e.target.closest('[data-edit]') : null;
    if (!toggle) return;

    var id = toggle.getAttribute('data-edit');
    var panel = document.getElementById('edit-' + id);
    if (!panel) return;

    panel.hidden = !panel.hidden;
    toggle.textContent = panel.hidden ? 'تعديل' : 'إغلاق';
    if (!panel.hidden) loadHistory(id);
  });

  // ── سجل الأسعار: بيتجاب عند فتح اللوحة بس ──
  // لو جبناه لكل المنتجات مع الصفحة، هتبقى عشرين نداء زيادة
  // عشان معلومة الموظّف غالبًا مش هيفتحها.
  var loaded = {};
  async function loadHistory(id) {
    if (loaded[id]) return;
    loaded[id] = true;

    var wrap = document.getElementById('log-' + id);
    var body = document.getElementById('log-body-' + id);
    if (!wrap || !body) return;

    try {
      var res = await fetch('/api/products/' + encodeURIComponent(id) + '/price-history', {
        credentials: 'same-origin'
      });
      if (!res.ok) return;
      var data = await res.json();
      var items = (data && data.items) || [];
      if (items.length === 0) return;

      body.innerHTML = '';
      for (var i = 0; i < items.length; i++) {
        var it = items[i];

        var row = document.createElement('div');
        row.className = 'price-log-row';

        var move = document.createElement('span');
        move.className = 'price-log-move';
        move.textContent = money(it.oldPricePiastres) + ' ← ' + money(it.newPricePiastres);

        var who = document.createElement('span');
        who.className = 'price-log-who';
        var when = '';
        try {
          when = new Date(it.changedAt).toLocaleDateString('ar-EG', {
            day: 'numeric', month: 'short'
          });
        } catch (err) { when = ''; }
        who.textContent = (it.changedByName || 'غير معروف') + (when ? ' · ' + when : '');

        row.appendChild(move);
        row.appendChild(who);
        body.appendChild(row);
      }
      wrap.hidden = false;
    } catch (err) {
      // فشل صامت: تعطّل السجل ما يصحّش يوقف تعديل السعر
    }
  }

  // ── فتح خانة السعر الجديد ──
  // الخانة **فاضية** مش متملية بالسعر القديم، عشان تكتب رقم جديد
  // مش تصلّح في رقم موجود. ده اللي بيمنع غلطة "مسحت الصفر الأخير".
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-price-open]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-price-open');
    var boxEl = document.getElementById('price-box-' + id);
    if (!boxEl) return;

    boxEl.hidden = !boxEl.hidden;
    btn.textContent = boxEl.hidden ? 'تعديل سعر البيع' : 'إلغاء التعديل';
    if (!boxEl.hidden) {
      var input = document.getElementById('price-' + id);
      if (input) { input.value = ''; input.focus(); }
    }
  });

  // ── حفظ السعر الجديد ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-save-price]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-save-price');
    var priceEl = document.getElementById('price-' + id);
    var costEl = document.getElementById('cost-' + id);

    var newPrice = priceEl ? priceEl.value.trim() : '';
    if (!newPrice && !confirm('إزالة سعر البيع تمامًا؟ سيطلبه النظام يدويًا عند كل بيع.')) return;

    var body = { price: newPrice };
    // التكلفة تُرسل فقط إن كان حقلها موجودًا في الصفحة.
    // لا حقل = لا صلاحية = لا قيمة تُرسل.
    if (costEl) body.cost = costEl.value;

    var result = await send('/api/products/' + encodeURIComponent(id), body, btn, 'جارٍ الحفظ…');
    if (result) {
      say('تم حفظ السعر. السعر السابق محفوظ في السجل.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  // ── حفظ باقي البيانات ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-save-details]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-save-details');
    var serialEl = document.getElementById('serial-' + id);
    var sourceEl = document.getElementById('source-' + id);
    var entryEl = document.getElementById('entry-' + id);

    var body = {};
    if (serialEl) body.serialNumber = serialEl.value;
    if (sourceEl) body.source = sourceEl.value;
    if (entryEl && entryEl.value) body.entryDate = entryEl.value;

    // ⚠ الخانة موجودة لصاحب المحل بس. غيابها من الصفحة معناه
    // إن الحقل ما بيتبعتش أصلاً — والخادم بيفحص الصلاحية برضه.
    var reorderEl = document.getElementById('reorder-' + id);
    if (reorderEl && reorderEl.value !== '') {
      body.reorderPoint = parseInt(reorderEl.value, 10);
    }

    var customsEl = document.getElementById('customs-' + id);
    if (customsEl) body.customsCleared = customsEl.value === 'true';

    var storageEl = document.getElementById('storage-' + id);
    if (storageEl) body.storageCapacity = storageEl.value;

    // ⚠ الفاضي بيتبعت null صراحةً — يعني "امسح القياس" مش
    // "ما تغيّرش". من غير كده مستحيل ترجّع الحقل فاضي.
    var batteryEl = document.getElementById('battery-' + id);
    if (batteryEl) {
      body.batteryHealth = batteryEl.value === '' ? null : parseInt(batteryEl.value, 10);
    }

    var result = await send('/api/products/' + encodeURIComponent(id), body, btn, 'جارٍ الحفظ…');
    if (result) {
      say('تم الحفظ.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── تعديل الكمية (الإكسسوارات فقط) ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-save-stock]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-save-stock');
    var input = document.getElementById('stock-' + id);
    if (!input || !input.value.trim()) { say('اكتب الكمية أولًا.', false); return; }

    var result = await send(
      '/api/products/' + encodeURIComponent(id) + '/stock',
      { delta: input.value },
      btn,
      'جارٍ التعديل…'
    );

    if (result) {
      say('أصبحت الكمية ' + result.quantityOnHand + '.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── إيقاف / تفعيل ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-toggle]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-toggle');
    var isActive = btn.getAttribute('data-active') === 'true';

    if (isActive && !confirm('إيقاف هذا المنتج؟ لن يظهر في شاشة البيع، ويبقى تاريخ مبيعاته كما هو.')) return;

    var result = await send(
      '/api/products/' + encodeURIComponent(id),
      { isActive: !isActive },
      btn,
      'جارٍ التنفيذ…'
    );

    if (result) {
      say(isActive ? 'تم إيقاف المنتج.' : 'تمت إعادة تفعيل المنتج.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── نموذج الإضافة: الحقول بتتبدّل حسب النوع ──
  var typeEl = document.getElementById('np-type');
  var serialField = document.getElementById('np-serial-field');
  var qtyField = document.getElementById('np-qty-field');
  var deviceFields = document.getElementById('np-device-fields');
  var catField = document.getElementById('np-cat-field');

  function syncType() {
    if (!typeEl) return;
    var isDevice = typeEl.value === 'device';
    // الجهاز: سريال ظاهر، وخانة الكمية مختفية لأنها مقفولة على 1
    if (serialField) serialField.hidden = !isDevice;
    if (qtyField) qtyField.hidden = isDevice;
    // ⚠ ومواصفات الجهاز بتظهر مع النوع مرة واحدة — الإكسسوار
    // مالوش بطارية ولا مساحة، والخادم بيصفّرهم برضه لو وصلوا.
    if (deviceFields) deviceFields.hidden = !isDevice;
    // ⚠ والدرج بالعكس: للإكسسوار والمكملات مش للأجهزة.
    // الجهاز هيتجمّع بموديله في مرحلة تانية.
    if (catField) catField.hidden = isDevice;
  }
  if (typeEl) { typeEl.addEventListener('change', syncType); syncType(); }

  var form = document.getElementById('addf');
  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var btn = document.getElementById('addbtn');
      var msg = document.getElementById('addmsg');
      var msgText = document.getElementById('addmsg-text');
      var branch = document.getElementById('np-branch');
      var isDevice = typeEl && typeEl.value === 'device';

      btn.disabled = true;
      btn.textContent = 'جارٍ الإضافة…';

      try {
        var res = await fetch('/api/products', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            name: document.getElementById('np-name').value,
            productType: typeEl ? typeEl.value : 'accessory',
            serialNumber: isDevice ? document.getElementById('np-serial').value : null,
            source: document.getElementById('np-source').value,
            entryDate: document.getElementById('np-entry').value || null,
            price: document.getElementById('np-price').value,
            cost: document.getElementById('np-cost').value,
            // الجهاز كميته مقفولة على 1 في الخادم — بنبعت 1 عشان
            // الرقم يبقى واضح في الطلب، والخادم بيفرضها برضه
            quantity: isDevice ? '1' : document.getElementById('np-qty').value,
            branchId: branch ? branch.value : null,
            // ── مواصفات الجهاز ──
            // ⚠ بتتبعت للأجهزة بس. للإكسسوار بنبعت القيم الفاضية
            // صراحةً بدل ما نسيبها بره الطلب — عشان الخادم يقرا
            // قرار مكتوب مش غياب.
            customsCleared: isDevice
              ? document.getElementById('np-customs').value === 'true'
              : false,
            // فاضي = "ما اتقاسش"، وهي **غير** الصفر
            batteryHealth: isDevice && document.getElementById('np-battery').value !== ''
              ? parseInt(document.getElementById('np-battery').value, 10)
              : null,
            storageCapacity: isDevice
              ? document.getElementById('np-storage').value
              : null,
            // ⚠ الجهاز بياخد null صراحةً. الخادم بيصفّره برضه،
            // بس البعت الصريح بيخلّي الطلب يقول قرار مش غياب.
            categoryId: isDevice
              ? null
              : (document.getElementById('np-category').value || null),
            // ⚠ للنوعين — الجهاز موديله هو، والإكسسوار موديل
            // الجهاز اللي بيركب عليه.
            modelId: document.getElementById('np-model').value || null
          })
        });
        var data = await res.json().catch(function () { return null; });

        msg.hidden = false;
        if (res.ok) {
          msg.setAttribute('data-tone', 'ok');
          msgText.textContent = 'تمت إضافة المنتج.';
          setTimeout(function () { window.location.reload(); }, 900);
          return;
        }

        msg.removeAttribute('data-tone');
        msgText.textContent = (data && data.error && data.error.message) || 'فشلت الإضافة.';
      } catch (err) {
        msg.hidden = false;
        msg.removeAttribute('data-tone');
        msgText.textContent = 'تعذّر الاتصال بالخادم.';
      } finally {
        btn.disabled = false;
        btn.textContent = 'إضافة المنتج';
      }
    });
  }

  // ══════════ رفّ المراجعة ══════════
  //
  // اللوحة مخفية افتراضيًا وبتظهر لو فيه حاجة مستنية بس.
  // لوحة فاضية دايمة بتتحوّل لأثاث — العين بتتعوّد عليها وتبطّل
  // تشوفها، وأول ما يبقى فيها حاجة مهمة ما حدش هيلاحظ.
  var qrPanel = document.getElementById('qr-panel');
  var qrRows  = document.getElementById('qr-rows');
  var qrCount = document.getElementById('qr-count');

  async function loadQuarantine() {
    if (!qrPanel || !qrRows) return;

    try {
      var res = await fetch('/api/returns/quarantine', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) return;

      var rows = data.rows || [];
      if (rows.length === 0) { qrPanel.hidden = true; return; }

      qrPanel.hidden = false;
      if (qrCount) qrCount.textContent = '(' + rows.length + ')';
      qrRows.textContent = '';

      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];

        var row = document.createElement('div');
        row.className = 'prod-row';

        var main = document.createElement('div');
        main.className = 'prod-row-main';

        var name = document.createElement('span');
        name.className = 'prod-row-name';
        name.textContent = r.productName;
        main.appendChild(name);

        var sub = document.createElement('span');
        sub.className = 'prod-row-sub';
        sub.textContent = 'محجوز ' + r.quarantinedQuantity +
          (r.serialNumber ? ' · ' + r.serialNumber : '') +
          (r.lastReturnDate ? ' · رجع ' + r.lastReturnDate : '') +
          (r.lastReason ? ' · ' + r.lastReason : '');
        main.appendChild(sub);
        row.appendChild(main);

        var acts = document.createElement('div');
        acts.className = 'prod-edit-actions';

        var qty = document.createElement('input');
        qty.className = 'field-input';
        qty.type = 'number';
        qty.min = '1';
        qty.max = String(r.quarantinedQuantity);
        qty.value = String(r.quarantinedQuantity);
        qty.dir = 'ltr';
        qty.id = 'qr-q-' + r.productId;
        acts.appendChild(qty);

        var ok = document.createElement('button');
        ok.className = 'btn-mini';
        ok.type = 'button';
        ok.textContent = 'سليم';
        ok.setAttribute('data-qr', r.productId);
        ok.setAttribute('data-qr-do', 'RELEASE');
        acts.appendChild(ok);

        var bad = document.createElement('button');
        bad.className = 'btn-mini';
        bad.type = 'button';
        bad.textContent = 'تالف';
        bad.setAttribute('data-danger', 'true');
        bad.setAttribute('data-qr', r.productId);
        bad.setAttribute('data-qr-do', 'SCRAP');
        acts.appendChild(bad);

        row.appendChild(acts);
        qrRows.appendChild(row);
      }
    } catch (err) {
      // فشل قراءة الرفّ ما يصحّش يعطّل شاشة المنتجات كلها
    }
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-qr-do]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-qr');
    var decision = btn.getAttribute('data-qr-do');
    var qEl = document.getElementById('qr-q-' + id);
    var qty = parseInt(qEl ? qEl.value : '0', 10);

    if (!isFinite(qty) || qty <= 0) {
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'الكمية غير صالحة.';
      return;
    }

    // ⚠ الشطب خسارة مخزون ما بترجعش. تأكيد إضافي على التالف بس —
    // "سليم" فعل قابل للتراجع (ترجّعه للرفّ باسترجاع تاني)،
    // والتالف لأ.
    if (decision === 'SCRAP' && !confirm('شطب ' + qty + ' نهائيًا من المخزون؟')) return;

    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/returns/quarantine/' + encodeURIComponent(id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ quantity: qty, decision: decision })
      });
      var data = await res.json().catch(function () { return null; });

      box.hidden = false;
      if (res.ok && data && data.ok) {
        box.setAttribute('data-tone', 'ok');
        text.textContent = decision === 'RELEASE'
          ? 'رجع للمخزون — المتاح الآن ' + data.nowOnHand
          : 'تم الشطب.';
        setTimeout(function () { window.location.reload(); }, 900);
        return;
      }
      box.removeAttribute('data-tone');
      text.textContent = (data && data.error && data.error.message) || 'تعذّر تنفيذ القرار.';
    } catch (err) {
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  // ══════════ التحويل بين الفروع ══════════

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tr-send]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tr-send');
    var isDevice = btn.getAttribute('data-device') === 'true';
    var toEl = document.getElementById('trto-' + id);
    if (!toEl || !toEl.value) { say('اختر الفرع المستقبِل.', false); return; }

    // الجهاز قطعة واحدة — مفيش خانة كمية أصلاً
    var qty = 1;
    if (!isDevice) {
      var qEl = document.getElementById('trq-' + id);
      qty = parseInt(qEl ? qEl.value : '0', 10);
      if (!isFinite(qty) || qty <= 0) { say('الكمية غير صالحة.', false); return; }
    }

    if (!confirm('إرسال التحويل؟ الكمية هتتخصم من فرعك فورًا.')) return;

    var result = await send(
      '/api/transfers/product/' + encodeURIComponent(id),
      { toBranchId: toEl.value, quantity: qty },
      btn, 'جارٍ الإرسال…'
    );
    if (result) {
      say('تم إرسال ' + result.moved + ' من ' + result.productName + '.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  var trPanel = document.getElementById('tr-panel');
  var trRows  = document.getElementById('tr-rows');
  var trCount = document.getElementById('tr-count');

  async function loadTransfers() {
    if (!trPanel || !trRows) return;

    try {
      var res = await fetch('/api/transfers', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) return;

      var rows = data.transfers || [];
      if (rows.length === 0) { trPanel.hidden = true; return; }

      trPanel.hidden = false;
      if (trCount) trCount.textContent = '(' + rows.length + ')';
      trRows.textContent = '';

      for (var i = 0; i < rows.length; i++) {
        var t = rows[i];

        var row = document.createElement('div');
        row.className = 'prod-row';

        var main = document.createElement('div');
        main.className = 'prod-row-main';

        var name = document.createElement('span');
        name.className = 'prod-row-name';
        name.textContent = t.productName + ' × ' + t.quantity;
        main.appendChild(name);

        var sub = document.createElement('span');
        sub.className = 'prod-row-sub';
        sub.textContent = 'من ' + t.fromBranch + ' إلى ' + t.toBranch +
          ' · ' + t.createdBy +
          (t.serialNumber ? ' · ' + t.serialNumber : '') +
          (t.note ? ' · ' + t.note : '');
        main.appendChild(sub);
        row.appendChild(main);

        var acts = document.createElement('div');
        acts.className = 'prod-edit-actions';

        // ⚠ الاستلام للجاي، والإلغاء للرايح.
        // صاحب المحل (BOTH) بيشوف الاتنين لأن الفرعين بتوعه.
        if (t.direction === 'IN' || t.direction === 'BOTH') {
          var ok = document.createElement('button');
          ok.className = 'btn-mini';
          ok.type = 'button';
          ok.textContent = 'تأكيد الاستلام';
          ok.setAttribute('data-tr-do', t.id);
          ok.setAttribute('data-tr-dec', 'RECEIVE');
          acts.appendChild(ok);
        }
        if (t.direction === 'OUT' || t.direction === 'BOTH') {
          var no = document.createElement('button');
          no.className = 'btn-mini';
          no.type = 'button';
          no.setAttribute('data-danger', 'true');
          no.textContent = 'إلغاء';
          no.setAttribute('data-tr-do', t.id);
          no.setAttribute('data-tr-dec', 'CANCEL');
          acts.appendChild(no);
        }

        row.appendChild(acts);
        trRows.appendChild(row);
      }
    } catch (err) {
      // فشل القراءة ما يصحّش يعطّل شاشة المنتجات
    }
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tr-do]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tr-do');
    var dec = btn.getAttribute('data-tr-dec');

    if (dec === 'CANCEL' && !confirm('إلغاء التحويل؟ البضاعة هترجع لفرع المُرسِل.')) return;

    var result = await send(
      '/api/transfers/' + encodeURIComponent(id) + '/resolve',
      { decision: dec },
      btn, '…'
    );
    if (result) {
      say(dec === 'RECEIVE'
        ? 'تم استلام ' + result.moved + ' من ' + result.productName + '.'
        : 'تم إلغاء التحويل.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  // ══════════ البحث ══════════
  //
  // ⚠ الفلترة في المتصفح مش على الخادم. الصفحة محمّلة المنتجات
  // أصلاً، فالفلترة فورية بلا رحلة شبكة — وده اللي بيخلّي
  // الماسح مفيد: يمسح، السطر يظهر في نفس اللحظة.
  //
  // والماسح الموصول بالكمبيوتر بيتصرّف كلوحة مفاتيح: بيكتب
  // الرقم وبيدوس Enter. فمفيش زرار مسح محتاجينه على ويندوز.
  var searchEl = document.getElementById('prod-search');
  var searchNote = document.getElementById('prod-search-note');
  var DEFAULT_NOTE = 'امسح بالكاميرا، أو بالماسح الموصول بالكمبيوتر، أو اكتب جزءًا من الاسم.';

  // ══════════ الدرج المختار ══════════
  //
  // ⚠ الأدراج والبحث بيتحكّموا في نفس الخاصية («hidden»)، فالقرار
  // بيتاخد مرة واحدة من الاتنين مع بعض. لو كل واحد كتبها لوحده،
  // آخر واحد يشتغل بيدهس على التاني: تبحث فيرجع صنف من درج تاني،
  // أو تغيّر الدرج فيرجع اللي البحث خبّاه.
  //
  // فاضي = الكل. «__none__» = غير مصنّف / بلا موديل.
  var activeDrawer = '';
  var activeModel = '';

  function runSearch() {
    var q = searchEl ? searchEl.value.trim().toLowerCase() : '';
    var rows = document.querySelectorAll('.prod-row[data-searchable]');
    var shown = 0;

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var hay = (row.getAttribute('data-searchable') || '').toLowerCase();
      var okText = !q || hay.indexOf(q) !== -1;
      var okDrawer = !activeDrawer
        || (row.getAttribute('data-cat') || '__none__') === activeDrawer;
      // ⚠ البُعد التاني. الفلترين بيتجمعوا بـ"و" مش بـ"أو":
      // "جرابات" + "١٢ برو ماكس" = جرابات الـ١٢ برو ماكس، مش
      // كل الجرابات وكل حاجة للـ١٢ برو ماكس.
      var okModel = !activeModel
        || (row.getAttribute('data-model') || '__none__') === activeModel;
      var match = okText && okDrawer && okModel;
      row.hidden = !match;

      // لوحة التعديل بتتخفي مع صفها
      var panel = row.nextElementSibling;
      if (panel && panel.classList && panel.classList.contains('prod-edit')) {
        if (!match) panel.hidden = true;
      }
      if (match) shown++;
    }

    // ⚠ العدّ بيظهر مع أي فلتر مش مع البحث وحده. الدرج اللي
    // بيخفي نص المخزون من غير ما يقول كام فاضل بيخلّي الموظّف
    // يفتكر إن باقي البضاعة اتمسحت.
    if (searchNote) {
      searchNote.textContent =
        (q || activeDrawer || activeModel) ? shown + ' نتيجة' : DEFAULT_NOTE;
    }
  }

  // ══════════ شرائط الأدراج ══════════
  var drawersEl = document.getElementById('drawers');
  if (drawersEl) {
    drawersEl.addEventListener('click', async function (e) {
      var chip = e.target.closest ? e.target.closest('.drawer') : null;
      if (!chip) return;

      // ─── زرار الإضافة ───
      if (chip.hasAttribute('data-add-drawer')) {
        // ⚠ القسم بيتاخد من قايمة الإضافة نفسها بدل ما نبني
        // نافذة تانية: الأقسام هي مجموعات «optgroup» في «np-category»،
        // فمصدر الأسماء واحد. لو بنيناها مرتين، هيختلفوا يوم ما.
        var groups = document.querySelectorAll('#np-category optgroup');
        if (!groups.length) { say('لا توجد أقسام.', false); return; }

        var labels = [];
        for (var g = 0; g < groups.length; g++) {
          labels.push((g + 1) + ') ' + groups[g].getAttribute('label'));
        }

        // ⚠ «\\n» بشرطتين مش شرطة.
        //
        // السطر ده هو اللي كسر الصفحة كلها. الملف ده قالب نصي في
        // TypeScript، فالشرطة الواحدة بتتحوّل **سطر جديد حقيقي**
        // قبل ما توصل للمتصفح — والنص الأحادي بيتفتح وما بيتقفلش،
        // فالمتصفح بيرمي "Invalid or unexpected token" ويموّت
        // السكربت كله من أول سطر.
        //
        // والأوحش إن الغلط بيبان في **مكان تاني خالص**: الشرائط
        // والإضافة وكل حاجة تحت بتبطّل، وشكلها كأنها مالهاش علاقة.
        var pick = prompt('في أي قسم؟\\n' + labels.join('\\n'), '1');
        if (pick === null) return;
        var idx = parseInt(pick, 10) - 1;
        if (!(idx >= 0 && idx < groups.length)) { say('اختيار غير صحيح.', false); return; }

        var name = prompt('اسم الدرج الجديد؟');
        if (name === null) return;
        name = name.trim();
        if (!name) return;

        // ⚠ معرّف القسم بيتقرا من أول خيار جوّاه، لأن «optgroup»
        // نفسه مالوش قيمة. ولو القسم فاضي مفيش منّه معرّف —
        // وده السبب إن البذرة بتحطّ أدراج جوّه كل قسم.
        var firstOpt = groups[idx].querySelector('option');
        if (!firstOpt) { say('القسم فاضي — أضف درجه الأول من قاعدة البيانات.', false); return; }

        var parentId = firstOpt.getAttribute('data-parent');

        try {
          var res = await fetch('/api/products/categories', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ parentId: parentId, name: name })
          });
          var data = await res.json();
          if (!res.ok || !data.ok) {
            say((data.error && data.error.message) || 'تعذّر إضافة الدرج.', false);
            return;
          }
          // ⚠ تحديث كامل مش إضافة شريط بإيدنا: الدرج الجديد لازم
          // يظهر في **قايمة الإضافة** كمان، والعدّ بيتحسب في
          // القاعدة. البناء اليدوي كان هيسيب القايمتين مختلفتين.
          window.location.reload();
        } catch (err) {
          say('تعذّر الاتصال بالخادم.', false);
        }
        return;
      }

      // ─── اختيار درج ───
      var all = drawersEl.querySelectorAll('.drawer');
      for (var j = 0; j < all.length; j++) all[j].removeAttribute('data-on');
      chip.setAttribute('data-on', '');

      activeDrawer = chip.getAttribute('data-drawer') || '';
      runSearch();
    });
  }

  // ══════════ شرائط الموديلات ══════════
  var modelsEl = document.getElementById('models');
  if (modelsEl) {
    modelsEl.addEventListener('click', async function (e) {
      var chip = e.target.closest ? e.target.closest('.drawer') : null;
      if (!chip) return;

      // ─── موديل جديد ───
      if (chip.hasAttribute('data-add-model')) {
        var name = prompt('اسم الموديل؟ مثال: ١٢ برو ماكس');
        if (name === null) return;
        name = name.trim();
        if (!name) return;

        // ⚠ الماركة اختيارية وعمود مستقل. لو كتبناها جوّه الاسم،
        // ما نقدرش نجمّع "كل الآيفون" بعدين من غير ما نقصّ النص.
        var brand = prompt('الماركة؟ (اختياري — آيفون · سامسونج)');
        if (brand === null) brand = '';

        try {
          var res = await fetch('/api/products/models', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ name: name, brand: brand.trim() || null })
          });
          var data = await res.json();
          if (!res.ok || !data.ok) {
            say((data.error && data.error.message) || 'تعذّر إضافة الموديل.', false);
            return;
          }
          // تحديث كامل: الموديل لازم يظهر في قايمة الإضافة كمان
          window.location.reload();
        } catch (err) {
          say('تعذّر الاتصال بالخادم.', false);
        }
        return;
      }

      // ─── اختيار موديل ───
      var all = modelsEl.querySelectorAll('.drawer');
      for (var j = 0; j < all.length; j++) all[j].removeAttribute('data-on');
      chip.setAttribute('data-on', '');

      activeModel = chip.getAttribute('data-model') || '';
      runSearch();
    });
  }

  if (searchEl) {
    searchEl.addEventListener('input', runSearch);
    // Enter من الماسح ما يصحّش يعمل submit
    searchEl.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') e.preventDefault();
    });
  }

  // ══════════ المسح بالكاميرا ══════════
  var scanBtn = document.getElementById('prod-scan');
  if (scanBtn) {
    scanBtn.addEventListener('click', async function () {
      try {
        // ⚠ الفحص ده مهم: لو السكربت المشترك ما اتحمّلش لأي
        // سبب، الزرار كان هيسكت من غير أي رسالة.
        if (typeof window.scanBarcode !== 'function') {
          say('الماسح غير متاح على هذا المتصفح.', false);
          return;
        }

        var code = await window.scanBarcode();
        if (!code || !searchEl) return;

        // بنحطّه في خانة البحث وبنشغّل الفلترة — نفس ما لو
        // اتكتب بالماسح الموصول بالكمبيوتر
        searchEl.value = code;
        runSearch();
      } catch (err) {
        say(err && err.message ? err.message : 'تعذّر المسح.', false);
      }
    });
  }

  // ══════════ طباعة الملصق ══════════
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-label]') : null;
    if (!btn) return;

    var row = document.querySelector('[data-pid="' + btn.getAttribute('data-label') + '"]');
    if (!row) return;

    var serial = row.getAttribute('data-serial') || '';
    if (!serial) { say('الملصق يحتاج سريالًا.', false); return; }

    // ⚠ سطر المواصفات بيتبني من الموجود بس. الحقل الفاضي ما
    // بيطبعش شرطة ولا "غير محدّد" — سطر فيه فراغات بيخلّي
    // الزبون يسأل، والملصق النضيف بيجاوب لوحده.
    var specs = [];
    var storage = row.getAttribute('data-storage') || '';
    var battery = row.getAttribute('data-battery') || '';

    if (storage) specs.push(storage);
    if (battery) specs.push('بطارية ' + battery + '٪');
    // ⚠ على الملصق بنكتب "ضريبة خالص" مش "خالص" لوحدها.
    // في الشاشة اسم الخانة جنبها فبتتفهم؛ على ورقة صغيرة جنب
    // "بطارية ٩٠٪" و"256GB"، كلمة "خالص" لوحدها بلا معنى.
    if (row.getAttribute('data-customs') === 'true') specs.push('ضريبة خالص');

    var specHtml = '';
    for (var k = 0; k < specs.length; k++) specHtml += '<span>' + specs[k] + '</span>';

    var price = row.getAttribute('data-price') || '';

    window.printHtml(
      '<div class="pr-doc pr-label">' +
        '<div class="pr-label-shop">' + SHOP_NAME + '</div>' +
        '<div class="pr-label-name">' + (row.getAttribute('data-name') || '') + '</div>' +
        window.barcodeSvg(serial, 46) +
        '<div class="pr-label-code">' + serial + '</div>' +
        (specHtml ? '<div class="pr-label-spec">' + specHtml + '</div>' : '') +
        '<div class="pr-label-foot">' +
          '<span>' + (row.getAttribute('data-entry') || '') + '</span>' +
          '<span>' + (price ? price + ' ج.م' : '') + '</span>' +
        '</div>' +
      '</div>'
    );
  });

  // ══════════ التحويل للصيانة ══════════
  //
  // ⚠ الإرسال بيخصم القطعة من المخزون فورًا — نفس منطق التحويل
  // بين الفروع. الجهاز ساب الرفّ وما ينفعش يتباع وهو في الورشة.
  document.addEventListener('click', async function (e) {
    var open = e.target.closest ? e.target.closest('[data-rep-open]') : null;
    if (open) {
      var id = open.getAttribute('data-rep-open');
      var panel = document.getElementById('rep-' + id);
      if (!panel) return;
      panel.hidden = !panel.hidden;
      if (!panel.hidden) loadRepairHistory(id);
      return;
    }

    var sendBtn = e.target.closest ? e.target.closest('[data-rep-send]') : null;
    if (!sendBtn) return;

    var pid = sendBtn.getAttribute('data-rep-send');
    var fault = (document.getElementById('repfault-' + pid) || {}).value || '';
    if (fault.trim().length < 3) { say('اكتب وصف العطل.', false); return; }

    if (!confirm('إرسال للصيانة؟ القطعة هتتخصم من المخزون.')) return;

    var result = await send('/api/maintenance/product/' + encodeURIComponent(pid), {
      shopId: (document.getElementById('repshop-' + pid) || {}).value || null,
      fault: fault,
      cost: (document.getElementById('repcost-' + pid) || {}).value || null
    }, sendBtn, 'جارٍ الإرسال…');

    if (result) {
      say('تم إرسال ' + result.productName + ' للصيانة.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  /**
   * تاريخ صيانة الجهاز — بيتعرض جوّه كارته.
   *
   * كل مرة راح فيها للورشة: العطل والورشة والتكلفة والنتيجة.
   * ده اللي بيخلّي "الجهاز ده اتصلّح قبل كده؟" سؤال ليه إجابة.
   */
  async function loadRepairHistory(pid) {
    var host = document.getElementById('rephist-' + pid);
    if (!host || host.getAttribute('data-loaded') === 'true') return;

    try {
      var res = await fetch('/api/maintenance/product/' + encodeURIComponent(pid) + '/history',
        { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) return;

      host.setAttribute('data-loaded', 'true');
      host.textContent = '';

      var rows = data.history || [];
      if (rows.length === 0) return;

      var head = document.createElement('p');
      head.className = 'field-label';
      head.textContent = 'سجل الصيانة (' + rows.length + ')';
      host.appendChild(head);

      for (var i = 0; i < rows.length; i++) {
        var h = rows[i];
        var line = document.createElement('p');
        line.className = 'field-hint';
        line.textContent =
          h.sentDate + ' · ' + (h.shopName || 'داخليًا') + ' · ' + h.faultNote +
          (h.status === 'SENT'
            ? ' · لسه في الورشة من ' + h.daysOut + ' يوم'
            : ' · ' + (h.status === 'RETURNED' ? 'رجع' : 'ما اتصلحش') +
              (h.returnedDate ? ' ' + h.returnedDate : '') +
              (h.costPiastres > 0 ? ' · ' + money(h.costPiastres) : '') +
              (h.resultNote ? ' · ' + h.resultNote : ''));
        host.appendChild(line);
      }
    } catch (err) {
      // فشل السجل ما يصحّش يمنع الإرسال
    }
  }

  loadTransfers();
  loadQuarantine();
})();
`;
}


// ═══════════════════ 7) شاشة العملاء ═══════════════════

export interface CustomersPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  /** customer.create */
  canAdd: boolean;
  /** customer.edit */
  canEdit: boolean;
  canSell: boolean;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  /** للمالك بس */
  branches: Array<{ id: string; name: string }>;
  customers: Array<{
    id: string;
    name: string;
    phone: string | null;
    notes: string | null;
    deviceCount: number;
    purchaseCount: number;
    totalPiastres: number;
  }>;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * شاشة العملاء.
 *
 * ══ إيه اللي مش هنا ══
 * مفيش أوسمة (عميل مميّز / دائم)، ومفيش تاريخ مشتريات.
 *
 * الوسام اللي بيتحسب من غير بيانات كافية بيبقى كذب مهذّب: "عميل
 * مميّز" بعد فاتورتين معناها لا حاجة، وبتخلّي الموظّف يبطّل يصدّق
 * أي وسام تاني بعدها. لما يبقى فيه مبيعات تكفي، الوسام هيبقى له
 * معنى — ووقتها نضيفه.
 */
export function customersPage(data: CustomersPageData): Html {
  const rows =
    data.customers.length === 0
      ? html`<div class="empty">
          <p class="empty-title">لا يوجد عملاء بعد</p>
          <p class="empty-note">
            ${data.canAdd
              ? 'سجّل أول عميل من القسم أعلاه.'
              : 'لا تملك صلاحية تسجيل العملاء.'}
          </p>
        </div>`
      : html`${data.customers.map(
          (cust) => html`<div class="prod-row" data-cust="${cust.id}">
            <div class="prod-row-main">
              <span class="prod-row-name">${cust.name}</span>
              ${cust.phone ? html`<span class="serial">${cust.phone}</span>` : ''}
              <span class="prod-row-sub">
                ${cust.purchaseCount > 0
                  ? `${String(cust.purchaseCount)} فاتورة · ${formatPiastres(cust.totalPiastres)} ج.م`
                  : 'لا مشتريات بعد'}
              </span>
              ${cust.notes ? html`<span class="cust-notes">${cust.notes}</span>` : ''}
            </div>

            <div class="prod-row-side">
              <span class="dev-count" data-zero="${cust.deviceCount === 0 ? 'true' : 'false'}">
                <b>${String(cust.deviceCount)}</b>
                <span>جهاز</span>
              </span>
              ${data.canEdit
                ? html`<button class="btn-mini" type="button" data-cedit="${cust.id}">تعديل</button>`
                : ''}
            </div>

            ${data.canEdit
              ? html`<div class="prod-edit" id="cedit-${cust.id}" hidden>
                  <div class="field">
                    <label class="field-label" for="cname-${cust.id}">الاسم</label>
                    <input class="field-input" id="cname-${cust.id}" type="text"
                      maxlength="80" value="${cust.name}">
                  </div>

                  <div class="field">
                    <label class="field-label" for="cphone-${cust.id}">رقم الهاتف</label>
                    <input class="field-input" id="cphone-${cust.id}" type="tel"
                      inputmode="tel" dir="ltr" maxlength="32" value="${cust.phone ?? ''}">
                  </div>

                  <div class="field">
                    <label class="field-label" for="cnotes-${cust.id}">ملاحظات</label>
                    <textarea class="field-input" id="cnotes-${cust.id}" rows="3"
                      maxlength="1000">${cust.notes ?? ''}</textarea>
                  </div>

                  <div class="prod-edit-actions">
                    <button class="btn-mini" type="button" data-csave="${cust.id}">حفظ</button>
                    <button class="btn-mini" data-danger="true" type="button"
                      data-cdel="${cust.id}">حذف العميل</button>
                  </div>
                </div>`
              : ''}
          </div>`,
        )}`;

  const addPanel = !data.canAdd
    ? ''
    : html`<details class="panel">
        <summary>تسجيل عميل</summary>
        <div class="panel-body">
          <div class="alert-box" id="caddmsg" role="alert" hidden><span id="caddmsg-text"></span></div>

          <form id="caddf" novalidate>
            ${data.branches.length > 0
              ? html`<div class="field">
                  <label class="field-label" for="nc-branch">الفرع</label>
                  <select class="field-input" id="nc-branch">
                    ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
                  </select>
                </div>`
              : ''}

            <div class="field">
              <label class="field-label" for="nc-name">اسم العميل</label>
              <input class="field-input" id="nc-name" type="text" maxlength="80" required>
            </div>

            <div class="field">
              <label class="field-label" for="nc-phone">رقم الهاتف (اختياري)</label>
              <input class="field-input" id="nc-phone" type="tel" inputmode="tel"
                dir="ltr" maxlength="32" autocomplete="off">
              <p class="field-hint">اكتبه كما هو. الرقم الواحد لا يتكرّر داخل الفرع.</p>
            </div>

            <div class="field">
              <label class="field-label" for="nc-notes">ملاحظات (اختياري)</label>
              <textarea class="field-input" id="nc-notes" rows="3" maxlength="1000"></textarea>
            </div>

            <button class="btn-primary" id="caddbtn" type="submit">تسجيل العميل</button>
          </form>
        </div>
      </details>`;

  return shell({
    title: 'العملاء',
    tenantName: data.tenantName,
    script: customersScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="custmsg" role="alert" hidden><span id="custmsg-text"></span></div>

  ${addPanel}

  <details class="panel" open>
    <summary>العملاء (${String(data.customers.length)})</summary>
    <div class="panel-body">
      <div class="field">
        <input class="field-input" id="cust-search" type="search"
          placeholder="ابحث بالاسم أو الرقم" autocomplete="off">
        <p class="field-hint">
          القائمة مرتّبة بعدد الأجهزة تنازليًا. يُسجَّل العميل تلقائيًا
          عند أول بيع يُكتب فيه رقم هاتفه.
        </p>
      </div>
      ${rows}
    </div>
  </details>
</main>

${tabBar('app', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function customersScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var box = document.getElementById('custmsg');
  var text = document.getElementById('custmsg-text');

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    text.textContent = message;
    box.scrollIntoView({ block: 'nearest' });
  }

  async function send(url, body, btn, busyLabel) {
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = busyLabel;
    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json().catch(function () { return null; });
      if (res.ok) return data || {};
      say((data && data.error && data.error.message) || 'فشل التنفيذ.', false);
      return null;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  // ── البحث: بيخفي الصفوف مش بيعيد بناءها ──
  // الفلترة في المتصفح لأن القائمة محدودة أصلاً (200 صف)، فمفيش
  // داعي لرحلة شبكة مع كل حرف.
  var search = document.getElementById('cust-search');
  if (search) {
    search.addEventListener('input', function () {
      var q = search.value.trim();
      var rows = document.querySelectorAll('[data-cust]');
      for (var i = 0; i < rows.length; i++) {
        var t = rows[i].textContent || '';
        rows[i].hidden = q.length > 0 && t.indexOf(q) === -1;
      }
    });
  }

  // ── فتح لوحة التعديل ──
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-cedit]') : null;
    if (!btn) return;
    var panel = document.getElementById('cedit-' + btn.getAttribute('data-cedit'));
    if (!panel) return;
    panel.hidden = !panel.hidden;
    btn.textContent = panel.hidden ? 'تعديل' : 'إغلاق';
  });

  // ── حفظ ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-csave]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-csave');
    var result = await send('/api/customers/' + encodeURIComponent(id), {
      name: document.getElementById('cname-' + id).value,
      phone: document.getElementById('cphone-' + id).value,
      notes: document.getElementById('cnotes-' + id).value
    }, btn, 'جارٍ الحفظ…');

    if (result) {
      say('تم الحفظ.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── حذف ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-cdel]') : null;
    if (!btn) return;

    if (!confirm('حذف هذا العميل؟ الفواتير السابقة لا تتأثّر.')) return;

    var id = btn.getAttribute('data-cdel');
    var result = await send(
      '/api/customers/' + encodeURIComponent(id) + '/delete', {}, btn, 'جارٍ الحذف…'
    );

    if (result) {
      say('تم حذف العميل.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── تسجيل عميل ──
  var form = document.getElementById('caddf');
  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var btn = document.getElementById('caddbtn');
      var msg = document.getElementById('caddmsg');
      var msgText = document.getElementById('caddmsg-text');
      var branch = document.getElementById('nc-branch');

      btn.disabled = true;
      btn.textContent = 'جارٍ التسجيل…';

      try {
        var res = await fetch('/api/customers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            name: document.getElementById('nc-name').value,
            phone: document.getElementById('nc-phone').value,
            notes: document.getElementById('nc-notes').value,
            branchId: branch ? branch.value : null
          })
        });
        var data = await res.json().catch(function () { return null; });

        msg.hidden = false;
        if (res.ok) {
          msg.setAttribute('data-tone', 'ok');
          msgText.textContent = 'تم تسجيل العميل.';
          setTimeout(function () { window.location.reload(); }, 900);
          return;
        }
        msg.removeAttribute('data-tone');
        msgText.textContent = (data && data.error && data.error.message) || 'فشل التسجيل.';
      } catch (err) {
        msg.hidden = false;
        msg.removeAttribute('data-tone');
        msgText.textContent = 'تعذّر الاتصال بالخادم.';
      } finally {
        btn.disabled = false;
        btn.textContent = 'تسجيل العميل';
      }
    });
  }
})();
`;
}


// ═══════════════════ 8) إدارة المحلات ═══════════════════

export interface PlatformPageData {
  fullName: string;
  username: string;
  tenants: Array<{
    id: string;
    code: string;
    name: string;
    isActive: boolean;
    maxBranches: number;
    branchCount: number;
    userCount: number;
    ownerName: string | null;
  }>;
  /** محل الحساب الحالي — بيتمنع إيقافه */
  currentTenantId: string;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * شاشة إدارة المحلات.
 *
 * ══ لاحظ اللي **مش** موجود هنا ══
 * مفيش مبيعات، مفيش أرباح، مفيش أرصدة خزينة، مفيش مخزون.
 * الشاشة بتوري حجم الاستخدام بس: كام فرع وكام مستخدم.
 *
 * ده مش نقص في الشاشة — ده حدّ مرسوم عن قصد في تلات طبقات:
 * الصلاحيات، وحالات الاستخدام، وهنا. مشغّل المنصّة بيحاسب على
 * الاشتراك، مش بيتفرّج على شغل عملائه.
 *
 * والسبب تجاري قبل ما يكون أخلاقي: المحلات دي ممكن تكون منافسة
 * لبعض. أول ما واحد فيهم يشك إنك شايف هوامشه، هيدخّل أرقام
 * مزوّقة والنظام يبقى بلا قيمة عندك وعنده.
 */
export function platformPage(data: PlatformPageData): Html {
  const rows =
    data.tenants.length === 0
      ? html`<div class="empty">
          <p class="empty-title">لا توجد محلات بعد</p>
          <p class="empty-note">افتح أول محل من القسم أعلاه.</p>
        </div>`
      : html`${data.tenants.map(
          (t) => html`<div class="prod-row" data-tenant="${t.id}">
            <div class="prod-row-main">
              <span class="prod-row-name" data-off="${t.isActive ? 'false' : 'true'}">
                ${t.name}
                <span class="type-tag" data-type="${t.isActive ? 'device' : 'accessory'}">
                  ${t.code}
                </span>
              </span>
              <span class="prod-row-sub">
                ${t.ownerName ?? 'بلا مالك'} · ${String(t.userCount)} مستخدم${t.isActive
                  ? ''
                  : ' · موقوف'}
              </span>
            </div>

            <div class="prod-row-side">
              <span class="dev-count" data-zero="${t.branchCount === 0 ? 'true' : 'false'}">
                <b>${String(t.branchCount)}/${String(t.maxBranches)}</b>
                <span>فرع</span>
              </span>
              <button class="btn-mini" type="button" data-tedit="${t.id}">إدارة</button>
            </div>

            <div class="prod-edit" id="tedit-${t.id}" hidden>
              <div class="field">
                <label class="field-label" for="tlimit-${t.id}">حد الفروع</label>
                <input class="field-input" id="tlimit-${t.id}" type="text"
                  inputmode="numeric" dir="ltr" value="${String(t.maxBranches)}">
                <p class="field-hint">
                  التخفيض لا يُغلق فروعًا قائمة — يمنع فتح جديد فقط.
                </p>
              </div>

              <div class="prod-edit-actions">
                <button class="btn-mini" type="button" data-tlimit="${t.id}">حفظ الحد</button>
                ${t.id === data.currentTenantId
                  ? html`<span class="price-log-who">لا يمكن إيقاف المحل الذي يضم حسابك.</span>`
                  : html`<button class="btn-mini" data-danger="${t.isActive ? 'true' : 'false'}"
                      type="button" data-tactive="${t.id}"
                      data-on="${t.isActive ? 'true' : 'false'}">
                      ${t.isActive ? 'إيقاف الاشتراك' : 'إعادة التفعيل'}
                    </button>`}
              </div>

              ${t.id === data.currentTenantId
                ? html``
                : t.isActive
                  ? html`<p class="field-hint">
                      المحو النهائي متاح بعد إيقاف الاشتراك — خطوتان منفصلتان عمدًا.
                    </p>`
                  : html`<div class="field">
                      <button class="btn-mini" data-danger="true" type="button"
                        data-tpurge="${t.id}">محو نهائي…</button>

                      <div id="purgep-${t.id}" hidden>
                        <p class="field-hint" id="purgec-${t.id}"></p>

                        <label class="field-label" for="purgek-${t.id}">
                          اكتب كود المحل «${t.code}» للتأكيد
                        </label>
                        <input class="field-input" id="purgek-${t.id}" type="text"
                          dir="ltr" autocomplete="off" spellcheck="false"
                          placeholder="${t.code}">
                        <p class="field-hint">
                          هذا الإجراء لا يمكن التراجع عنه. تُمحى الفروع والحسابات
                          والمنتجات والعملاء والفواتير وحركات الخزينة نهائيًا.
                        </p>

                        <button class="btn-mini" data-danger="true" type="button"
                          data-tpurgego="${t.id}">تأكيد المحو — بلا رجعة</button>
                      </div>
                    </div>`}
            </div>
          </div>`,
        )}`;

  return shell({
    title: 'المحلات',
    tenantName: null,
    noIndex: true,
    script: platformScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
    body: html`<header class="app-bar">
  <div class="who">
    ${raw(brandGlyph())}
    <span class="who-name">${data.fullName}</span>
    <span class="stamp" data-role="PLATFORM_ADMIN">مشغّل المنصّة</span>
  </div>
  <button class="menu-btn" id="menu-btn" type="button" aria-label="القائمة"
    aria-haspopup="true" aria-expanded="false">⋯</button>
  <div class="menu-sheet" id="menu-sheet" hidden>
    <div class="menu-panel" role="menu">
      <div class="menu-row"><span>الحساب</span><b>${data.username}</b></div>
      <a class="menu-item" href="/password">تغيير كلمة المرور</a>
      <button class="menu-item" type="button" data-action="theme">
        الإضاءة<span class="menu-note" id="theme-label"></span>
      </button>
      <button class="menu-item" type="button" data-action="logout">تسجيل الخروج</button>
    </div>
  </div>
</header>

<main class="shell">
  <div class="alert-box" id="pmsg" role="alert" hidden><span id="pmsg-text"></span></div>

  <div class="alert-box" data-tone="ok">
    <span>
      هذه الشاشة تعرض حجم الاشتراك فقط — عدد الفروع والمستخدمين.
      بيانات المبيعات والتكاليف والأرباح غير متاحة لهذا الحساب.
    </span>
  </div>

  <details class="panel">
    <summary>فتح محل جديد</summary>
    <div class="panel-body">
      <div class="alert-box" id="tadd-msg" role="alert" hidden><span id="tadd-text"></span></div>

      <!-- ⚠ ملخّص التسليم. بيفضل ظاهر لحد ما تقفله بإيدك —
           مفيش إعادة تحميل تلقائي، لأن اللي جوّاه ما بيترجّعش تاني. -->
      <div class="handover" id="handover" hidden>
        <p class="handover-title">بيانات التسليم — تظهر مرة واحدة</p>
        <p class="handover-note">
          انسخها الآن. لن تظهر مرة أخرى، والطريقة الوحيدة لاستعادتها
          هي تغييرها من داخل حساب صاحب المحل.
        </p>
        <div id="handover-body"></div>
        <button class="btn-mini" type="button" id="handover-done">نسختها — إغلاق</button>
      </div>

      <form id="tf" novalidate>
        <div class="field">
          <label class="field-label" for="t-code">كود المحل</label>
          <input class="field-input" id="t-code" type="text" dir="ltr"
            autocapitalize="characters" maxlength="16" required>
          <p class="field-hint">
            هذا ما سيكتبه كل موظّفي المحل في شاشة الدخول كل يوم — بكل فروعه.
            اجعله قصيرًا وواضحًا.
          </p>
        </div>

        <div class="field">
          <label class="field-label" for="t-name">اسم المحل</label>
          <input class="field-input" id="t-name" type="text" maxlength="80" required>
        </div>

        <div class="field">
          <label class="field-label" for="t-max">عدد الفروع المسموح بالاشتراك</label>
          <input class="field-input" id="t-max" type="text" inputmode="numeric"
            dir="ltr" value="1" required>
        </div>

        <!-- ═══ الفروع ═══ -->
        <div class="setup-block">
          <div class="setup-head">
            <span class="setup-title">الفروع</span>
            <button class="btn-mini" type="button" id="add-branch">+ فرع</button>
          </div>
          <div id="branch-rows"></div>
          <p class="field-hint">كل فرع يحصل على خزينة نقدية تلقائيًا — بدونها لا يمكن إتمام بيع.</p>
        </div>

        <!-- ═══ الحسابات ═══ -->
        <div class="setup-block">
          <div class="setup-head">
            <span class="setup-title">حسابات المحل</span>
            <button class="btn-mini" type="button" id="add-user">+ حساب</button>
          </div>

          <div class="field">
            <label class="field-label" for="t-ouser">اسم مستخدم صاحب المحل</label>
            <input class="field-input" id="t-ouser" type="text" dir="ltr"
              autocapitalize="none" spellcheck="false" maxlength="32" required>
          </div>

          <div class="field">
            <label class="field-label" for="t-oname">اسم صاحب المحل الكامل</label>
            <input class="field-input" id="t-oname" type="text" maxlength="80" required>
          </div>

          <div class="field">
            <label class="field-label" for="t-opass">كلمة مروره (اختياري)</label>
            <input class="field-input" id="t-opass" type="text" dir="ltr"
              autocomplete="off" maxlength="1024">
            <p class="field-hint">اتركها فارغة ليولّدها النظام. تظهر مرة واحدة بعد الفتح.</p>
          </div>

          <div id="user-rows"></div>
        </div>

        <button class="btn-primary" id="tbtn" type="submit">فتح المحل</button>
      </form>
    </div>
  </details>

  <details class="panel">
    <summary>بثّ إعلان</summary>
    <div class="panel-body">
      <p class="muted">
        رسالة من مورّد النظام لعملائه. تظهر للمستهدفين كنافذة إلزامية
        لا تُغلق قبل الضغط على «قرأت وفهمت».
      </p>

      <div class="field">
        <label class="field-label" for="an-tenant">المحل</label>
        <select class="field-input" id="an-tenant">
          <option value="">— كل المحلات المفعّلة —</option>
          ${data.tenants
            .filter((t) => t.isActive)
            .map((t) => html`<option value="${t.id}">${t.name} (${t.code})</option>`)}
        </select>
      </div>

      <div class="field">
        <label class="field-label" for="an-aud">لمين</label>
        <select class="field-input" id="an-aud">
          <option value="ALL">كل العاملين في المحل</option>
          <option value="OWNERS_ONLY">صاحب المحل وحده</option>
          <option value="MANAGERS_ONLY">مديري الفروع</option>
          <option value="STAFF_ONLY">مندوبي المبيعات</option>
          <option value="SINGLE_BRANCH">فرع بعينه</option>
        </select>
      </div>

      <div class="field" id="an-branch-field" hidden>
        <label class="field-label" for="an-branch">الفرع</label>
        <select class="field-input" id="an-branch">
          <option value="">اختر المحل أولًا</option>
        </select>
        <p class="field-hint">التوجيه لفرع يتطلّب اختيار محل واحد.</p>
      </div>

      <div class="field">
        <label class="field-label" for="an-sev">الأهمية</label>
        <select class="field-input" id="an-sev">
          <option value="INFO">عادي</option>
          <option value="WARNING">تنبيه</option>
          <option value="CRITICAL">حرج</option>
        </select>
      </div>

      <div class="field">
        <label class="field-label" for="an-title">العنوان</label>
        <input class="field-input" id="an-title" type="text" maxlength="140">
      </div>

      <div class="field">
        <label class="field-label" for="an-body">النص</label>
        <textarea class="field-input" id="an-body" rows="4" maxlength="4000"></textarea>
      </div>

      <p class="field-hint" id="an-warn" hidden></p>

      <button class="btn-primary" type="button" id="an-go">بثّ</button>
    </div>
  </details>

  <details class="panel">
    <summary>سجل الإعلانات</summary>
    <div class="panel-body">
      <p class="muted">
        العدّاد يقول: كم شخصًا ضغط «قرأت وفهمت» من إجمالي من يفترض أن يروه.
      </p>
      <div id="an-list"><p class="field-hint">جارٍ التحميل…</p></div>
    </div>
  </details>

  <details class="panel" open>
    <summary>المحلات (${String(data.tenants.length)})</summary>
    <div class="panel-body">
      ${rows}
    </div>
  </details>
</main>

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function platformScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var box = document.getElementById('pmsg');
  var text = document.getElementById('pmsg-text');

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    text.textContent = message;
    box.scrollIntoView({ block: 'nearest' });
  }

  async function send(url, body, btn, busyLabel) {
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = busyLabel;
    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json().catch(function () { return null; });
      if (res.ok) return data || {};
      say((data && data.error && data.error.message) || 'فشل التنفيذ.', false);
      return null;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  // ── فتح لوحة الإدارة ──
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tedit]') : null;
    if (!btn) return;
    var panel = document.getElementById('tedit-' + btn.getAttribute('data-tedit'));
    if (!panel) return;
    panel.hidden = !panel.hidden;
    btn.textContent = panel.hidden ? 'إدارة' : 'إغلاق';
  });

  // ── حد الفروع ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tlimit]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tlimit');
    var input = document.getElementById('tlimit-' + id);
    if (!input || !input.value.trim()) { say('اكتب عدد الفروع.', false); return; }

    var result = await send(
      '/api/platform/' + encodeURIComponent(id) + '/limit',
      { maxBranches: input.value },
      btn, 'جارٍ الحفظ…'
    );
    if (result) {
      say('تم تعديل حد الفروع.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── إيقاف / تفعيل ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tactive]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tactive');
    var isOn = btn.getAttribute('data-on') === 'true';

    if (isOn && !confirm('إيقاف اشتراك هذا المحل؟ سيُمنع الدخول فورًا، ولن تُحذف أي بيانات.')) {
      return;
    }

    var result = await send(
      '/api/platform/' + encodeURIComponent(id) + '/active',
      { isActive: !isOn },
      btn, 'جارٍ التنفيذ…'
    );
    if (result) {
      say(isOn ? 'تم إيقاف الاشتراك.' : 'تمت إعادة التفعيل.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── المحو النهائي، خطوة ١: الجرد ──
  //
  // ⚠ الأرقام دي هي القفل التالت. محل تجربة كله أصفار، ومحل
  // زبون حقيقي هيوريك فواتير بمبلغ. الفرق لازم يبان **قبل**
  // الدوسة مش بعدها.
  function money(piastres) {
    var neg = piastres < 0;
    var abs = Math.abs(Math.trunc(piastres));
    var pounds = Math.floor(abs / 100);
    var rest = abs % 100;
    return (neg ? '-' : '') + pounds.toLocaleString('en-US') +
      '.' + String(rest).padStart(2, '0');
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tpurge]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tpurge');
    var panel = document.getElementById('purgep-' + id);
    var line = document.getElementById('purgec-' + id);
    if (!panel || !line) return;

    if (!panel.hidden) {
      panel.hidden = true;
      btn.textContent = 'محو نهائي…';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'جارٍ الجرد…';
    try {
      var res = await fetch('/api/platform/' + encodeURIComponent(id) + '/census', {
        credentials: 'same-origin'
      });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        say((data && data.error && data.error.message) || 'تعذّر جرد المحل.', false);
        return;
      }

      var c = data.census;
      line.textContent =
        'سيُمحى: ' + c.branchCount + ' فرع · ' + c.userCount + ' حساب · ' +
        c.productCount + ' منتج · ' + c.customerCount + ' عميل · ' +
        c.saleCount + ' فاتورة بإجمالي ' + money(c.salesTotalPiastres) + ' ج.م · ' +
        c.movementCount + ' حركة خزينة · ' + c.auditCount + ' سطر تدقيق.';

      panel.hidden = false;
      btn.textContent = 'إخفاء';
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    } finally {
      btn.disabled = false;
      if (panel.hidden) btn.textContent = 'محو نهائي…';
    }
  });

  // ── المحو النهائي، خطوة ٢: التأكيد بالكود ──
  //
  // ⚠ المقارنة الحقيقية في الخادم. اللي هنا بيوفّر رحلة شبكة
  // ورسالة أوضح — مش هو القفل.
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-tpurgego]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-tpurgego');
    var input = document.getElementById('purgek-' + id);
    if (!input || !input.value.trim()) {
      say('اكتب كود المحل للتأكيد.', false);
      return;
    }

    if (!confirm('محو نهائي بلا رجعة. متأكد؟')) return;

    var result = await send(
      '/api/platform/' + encodeURIComponent(id) + '/purge',
      { confirmCode: input.value },
      btn, 'جارٍ المحو…'
    );
    if (result) {
      var p = result.purged || {};
      say('تم محو المحل ' + (p.code || '') + ' نهائيًا.', true);
      setTimeout(function () { window.location.reload(); }, 1200);
    }
  });

  // ── صفوف الفروع والحسابات ──
  //
  // ⚠ الصفوف بتتبني بـ createElement مش innerHTML.
  // السبب مش تجميلي: أسماء الفروع بتتكتب بإيد المستخدم، ولو
  // ركّبناها كنص HTML، اسم فيه قوس أو علامة بيكسر الصفحة —
  // وفي أسوأ حالة بيحقن كود.
  var branchRows = document.getElementById('branch-rows');
  var userRows = document.getElementById('user-rows');
  var branchSeq = 0;

  function field(labelText, el, hint) {
    var wrap = document.createElement('div');
    wrap.className = 'field';

    var lb = document.createElement('label');
    lb.className = 'field-label';
    lb.textContent = labelText;

    wrap.appendChild(lb);
    wrap.appendChild(el);

    if (hint) {
      var h = document.createElement('p');
      h.className = 'field-hint';
      h.textContent = hint;
      wrap.appendChild(h);
    }
    return wrap;
  }

  function input(placeholder, ltr) {
    var el = document.createElement('input');
    el.className = 'field-input';
    el.type = 'text';
    if (ltr) { el.dir = 'ltr'; el.setAttribute('autocapitalize', 'none'); }
    if (placeholder) el.placeholder = placeholder;
    return el;
  }

  function removeBtn(row) {
    var b = document.createElement('button');
    b.className = 'btn-mini';
    b.type = 'button';
    b.setAttribute('data-danger', 'true');
    b.textContent = 'حذف';
    b.addEventListener('click', function () {
      row.remove();
      syncBranchOptions();
    });
    return b;
  }

  function addBranch(code, name) {
    branchSeq++;
    var row = document.createElement('div');
    row.className = 'setup-row';
    row.setAttribute('data-branch-row', '1');

    var codeEl = input('MAIN', true);
    codeEl.className += ' b-code';
    codeEl.maxLength = 16;
    codeEl.value = code || '';
    codeEl.addEventListener('input', syncBranchOptions);

    var nameEl = input('الفرع الرئيسي', false);
    nameEl.className += ' b-name';
    nameEl.maxLength = 80;
    nameEl.value = name || '';

    row.appendChild(field('كود الفرع', codeEl));
    row.appendChild(field('اسم الفرع', nameEl));

    // أول فرع ما بيتحذفش: المحل لازم يكون له فرع واحد على الأقل
    if (branchRows.children.length > 0) row.appendChild(removeBtn(row));

    branchRows.appendChild(row);
    syncBranchOptions();
  }

  function branchCodes() {
    var out = [];
    var els = branchRows.querySelectorAll('.b-code');
    for (var i = 0; i < els.length; i++) {
      var v = els[i].value.trim().toUpperCase();
      if (v) out.push(v);
    }
    return out;
  }

  // قوائم الفروع في الحسابات بتتحدّث مع كل تعديل في أكواد الفروع،
  // عشان ما تختارش فرع اتغيّر كوده بعد ما اخترته
  function syncBranchOptions() {
    var codes = branchCodes();
    var selects = userRows.querySelectorAll('.u-branch');

    for (var i = 0; i < selects.length; i++) {
      var sel = selects[i];
      var current = sel.value;
      sel.innerHTML = '';

      for (var j = 0; j < codes.length; j++) {
        var opt = document.createElement('option');
        opt.value = codes[j];
        opt.textContent = codes[j];
        sel.appendChild(opt);
      }
      if (codes.indexOf(current) !== -1) sel.value = current;
    }
  }

  function addUser() {
    if (branchCodes().length === 0) {
      say('أضف فرعًا أولًا — كل حساب لازم يكون تابعًا لفرع.', false);
      return;
    }

    var row = document.createElement('div');
    row.className = 'setup-row';
    row.setAttribute('data-user-row', '1');

    var userEl = input('', true);
    userEl.className += ' u-user';
    userEl.maxLength = 32;

    var nameEl = input('', false);
    nameEl.className += ' u-name';
    nameEl.maxLength = 80;

    var roleEl = document.createElement('select');
    roleEl.className = 'field-input u-role';
    var roles = [['STAFF', 'مندوب مبيعات'], ['BRANCH_MANAGER', 'مدير فرع']];
    for (var i = 0; i < roles.length; i++) {
      var o = document.createElement('option');
      o.value = roles[i][0];
      o.textContent = roles[i][1];
      roleEl.appendChild(o);
    }

    var branchEl = document.createElement('select');
    branchEl.className = 'field-input u-branch';

    var passEl = input('', true);
    passEl.className += ' u-pass';
    passEl.maxLength = 1024;

    row.appendChild(field('اسم المستخدم', userEl));
    row.appendChild(field('الاسم الكامل', nameEl));
    row.appendChild(field('الدور', roleEl));
    row.appendChild(field('الفرع', branchEl));
    row.appendChild(field('كلمة المرور (اختياري)', passEl, 'اتركها فارغة ليولّدها النظام.'));
    row.appendChild(removeBtn(row));

    userRows.appendChild(row);
    syncBranchOptions();
  }

  document.getElementById('add-branch').addEventListener('click', function () { addBranch(); });
  document.getElementById('add-user').addEventListener('click', addUser);

  // فرع افتراضي واحد جاهز — أغلب المحلات بتبدأ بفرع واحد
  addBranch('MAIN', 'الفرع الرئيسي');

  // ── ملخّص التسليم ──
  var ROLE_AR = {
    SUPER_ADMIN: 'صاحب المحل',
    BRANCH_MANAGER: 'مدير فرع',
    STAFF: 'مندوب مبيعات'
  };

  function showHandover(shopCode, accounts) {
    var wrap = document.getElementById('handover');
    var body = document.getElementById('handover-body');
    body.innerHTML = '';

    var head = document.createElement('div');
    head.className = 'handover-row';
    var hl = document.createElement('span');
    hl.className = 'handover-label';
    hl.textContent = 'كود المحل';
    var hv = document.createElement('b');
    hv.className = 'handover-value';
    hv.textContent = shopCode;
    head.appendChild(hl);
    head.appendChild(hv);
    body.appendChild(head);

    for (var i = 0; i < accounts.length; i++) {
      var a = accounts[i];

      var card = document.createElement('div');
      card.className = 'handover-card';

      var who = document.createElement('div');
      who.className = 'handover-who';
      who.textContent = a.fullName + ' — ' + (ROLE_AR[a.role] || a.role) +
        (a.branchCode ? ' · ' + a.branchCode : '');

      var creds = document.createElement('div');
      creds.className = 'handover-creds';
      creds.textContent = a.username + '   ' + a.password;

      card.appendChild(who);
      card.appendChild(creds);
      body.appendChild(card);
    }

    wrap.hidden = false;
    wrap.scrollIntoView({ block: 'start' });
  }

  document.getElementById('handover-done').addEventListener('click', function () {
    if (!confirm('إغلاق بيانات التسليم؟ لن تظهر مرة أخرى.')) return;
    window.location.reload();
  });

  // ── فتح محل ──
  var form = document.getElementById('tf');
  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var btn = document.getElementById('tbtn');
      var msg = document.getElementById('tadd-msg');
      var msgText = document.getElementById('tadd-text');

      var branches = [];
      var brows = branchRows.querySelectorAll('[data-branch-row]');
      for (var i = 0; i < brows.length; i++) {
        branches.push({
          code: brows[i].querySelector('.b-code').value,
          name: brows[i].querySelector('.b-name').value
        });
      }

      var users = [];
      var urows = userRows.querySelectorAll('[data-user-row]');
      for (var k = 0; k < urows.length; k++) {
        users.push({
          username: urows[k].querySelector('.u-user').value,
          fullName: urows[k].querySelector('.u-name').value,
          role: urows[k].querySelector('.u-role').value,
          branchCode: urows[k].querySelector('.u-branch').value,
          password: urows[k].querySelector('.u-pass').value
        });
      }

      btn.disabled = true;
      btn.textContent = 'جارٍ التجهيز…';

      try {
        var res = await fetch('/api/platform', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            code: document.getElementById('t-code').value,
            name: document.getElementById('t-name').value,
            maxBranches: document.getElementById('t-max').value,
            ownerUsername: document.getElementById('t-ouser').value,
            ownerFullName: document.getElementById('t-oname').value,
            ownerPassword: document.getElementById('t-opass').value,
            branches: branches,
            users: users
          })
        });
        var data = await res.json().catch(function () { return null; });

        if (res.ok) {
          msg.hidden = true;
          // ⚠ مفيش إعادة تحميل هنا. الملخّص فيه كلمات مرور
          // ما بترجعش تاني، والتحديث التلقائي كان هيمسحها قبل
          // ما تنسخها.
          showHandover(data.code, data.accounts || []);
          return;
        }

        msg.hidden = false;
        msg.removeAttribute('data-tone');
        msgText.textContent = (data && data.error && data.error.message) || 'فشل الفتح.';
      } catch (err) {
        msg.hidden = false;
        msg.removeAttribute('data-tone');
        msgText.textContent = 'تعذّر الاتصال بالخادم.';
      } finally {
        btn.disabled = false;
        btn.textContent = 'فتح المحل';
      }
    });
  }

  // ══════════ الإعلانات ══════════

  var anTenant = document.getElementById('an-tenant');
  var anAud    = document.getElementById('an-aud');
  var anBranch = document.getElementById('an-branch');
  var anBrField= document.getElementById('an-branch-field');
  var anWarn   = document.getElementById('an-warn');
  var anList   = document.getElementById('an-list');

  function anSay(message, ok) {
    // ⚠ الاسم pmsg مش pfmsg — العنصر ده موجود في أول الصفحة.
    // اسم غلط هنا كان هيخلّي كل رسايل الإعلانات تضيع بصمت:
    // الدالة بترجع من غير ما تعمل حاجة، والمستخدم يفتكر إن
    // الزرار مش شغّال.
    var box = document.getElementById('pmsg');
    var txt = document.getElementById('pmsg-text');
    if (!box || !txt) return;
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    txt.textContent = message;
  }

  /**
   * ⚠ تحذير قبل الضغط مش بعده.
   *
   * زرار واحد بيوصل لكل عملائك. اللافتة دي بتقول العدد قبل ما
   * تضغط — مش رسالة "تم البثّ لأربعين محل" بعد ما تخلص.
   */
  function anSync() {
    if (!anAud || !anTenant) return;

    var toBranch = anAud.value === 'SINGLE_BRANCH';
    if (anBrField) anBrField.hidden = !toBranch;

    var all = anTenant.value === '';
    if (anWarn) {
      if (all) {
        var n = anTenant.options.length - 1;
        anWarn.hidden = false;
        anWarn.textContent = 'سيصل هذا الإعلان إلى ' + n + ' محلًا.';
      } else {
        anWarn.hidden = true;
      }
    }

    // الفرع يحتاج محلًا واحدًا — والقايمة بتتحمّل عند الحاجة بس
    if (toBranch && !all) loadBranches(anTenant.value);
  }

  async function loadBranches(tenantId) {
    if (!anBranch) return;
    anBranch.textContent = '';

    try {
      var res = await fetch('/api/platform/' + encodeURIComponent(tenantId) + '/branches',
        { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) return;

      for (var i = 0; i < (d.branches || []).length; i++) {
        var o = document.createElement('option');
        o.value = d.branches[i].branchId;
        o.textContent = d.branches[i].branchName;
        anBranch.appendChild(o);
      }
    } catch (err) {
      // الفرع اختياري في الواجهة؛ الخادم بيرفض لو فاضي
      anBranch.textContent = '';
    }
  }

  if (anAud) anAud.addEventListener('change', anSync);
  if (anTenant) anTenant.addEventListener('change', anSync);
  anSync();

  var anGo = document.getElementById('an-go');
  if (anGo) {
    anGo.addEventListener('click', async function () {
      var title = document.getElementById('an-title');
      var body  = document.getElementById('an-body');
      if (!title || !body) return;

      if (String(title.value || '').trim().length < 3) {
        anSay('اكتب عنوان الإعلان.', false); return;
      }
      if (String(body.value || '').trim().length < 3) {
        anSay('اكتب نص الإعلان.', false); return;
      }

      // ⚠ تأكيد صريح للبثّ الشامل. الفعل ده ما بيترجعش فيه
      // بضغطة — لازم تسحبه من كل محل على حدة.
      var all = anTenant && anTenant.value === '';
      if (all) {
        var n = anTenant.options.length - 1;
        if (!confirm('سيصل الإعلان إلى ' + n + ' محلًا. تأكيد؟')) return;
      }

      anGo.disabled = true;
      try {
        var res = await fetch('/api/platform/announcements', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            tenantId: anTenant ? (anTenant.value || null) : null,
            audience: anAud ? anAud.value : 'ALL',
            branchId: anBranch ? (anBranch.value || null) : null,
            title: title.value,
            body: body.value,
            severity: (document.getElementById('an-sev') || {}).value || 'INFO',
            isMandatory: true
          })
        });
        var d = await res.json().catch(function () { return null; });

        if (res.ok && d && d.ok) {
          anSay(d.message || 'تم البثّ.', true);
          title.value = '';
          body.value = '';
          loadAnnouncements();
          return;
        }
        anSay((d && d.error && d.error.message) || 'تعذّر البثّ.', false);
      } catch (err) {
        anSay('انقطع الاتصال. حدّث الصفحة وتأكّد قبل إعادة المحاولة.', false);
      } finally {
        anGo.disabled = false;
      }
    });
  }

  async function loadAnnouncements() {
    if (!anList) return;
    anList.textContent = '';
    var p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = 'جارٍ التحميل…';
    anList.appendChild(p);

    try {
      var res = await fetch('/api/platform/announcements', { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) { p.textContent = 'تعذّر التحميل.'; return; }

      var items = d.announcements || [];
      if (items.length === 0) { p.textContent = 'لم يُبَثّ شيء بعد.'; return; }

      anList.textContent = '';
      for (var i = 0; i < items.length; i++) {
        var a = items[i];
        var row = document.createElement('div');
        row.className = 'mv-row';

        var t = document.createElement('span');
        t.className = 'mv-title';
        t.textContent = a.title;
        row.appendChild(t);

        var sub = document.createElement('span');
        sub.className = 'mv-sub';
        sub.textContent = a.tenantName + ' · ' + audLabel(a.audience) +
          (a.branchName ? ' · ' + a.branchName : '') +
          ' · قرأه ' + a.readCount + ' من ' + a.targetCount;
        row.appendChild(sub);

        var del = document.createElement('button');
        del.className = 'btn-mini';
        del.type = 'button';
        del.setAttribute('data-withdraw', a.id);
        del.textContent = 'سحب';
        row.appendChild(del);

        anList.appendChild(row);
      }
    } catch (err) {
      p.textContent = 'تعذّر الاتصال بالخادم.';
    }
  }

  function audLabel(a) {
    if (a === 'ALL') return 'الكل';
    if (a === 'OWNERS_ONLY') return 'صاحب المحل';
    if (a === 'MANAGERS_ONLY') return 'مديري الفروع';
    if (a === 'STAFF_ONLY') return 'المناديب';
    if (a === 'SINGLE_BRANCH') return 'فرع بعينه';
    return a;
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-withdraw]') : null;
    if (!btn) return;

    if (!confirm('سحب الإعلان؟ هيختفي من الشاشات فورًا.')) return;

    btn.disabled = true;
    try {
      var res = await fetch('/api/platform/announcements/' +
        encodeURIComponent(btn.getAttribute('data-withdraw')), {
        method: 'DELETE',
        credentials: 'same-origin'
      });
      var d = await res.json().catch(function () { return null; });

      if (res.ok && d && d.ok) { anSay(d.message || 'تم السحب.', true); loadAnnouncements(); return; }
      anSay((d && d.error && d.error.message) || 'تعذّر السحب.', false);
    } catch (err) {
      anSay('تعذّر الاتصال بالخادم.', false);
    } finally {
      btn.disabled = false;
    }
  });

  loadAnnouncements();
})();
`;
}


// ═══════════════════ 9) تأسيس مشغّل المنصّة ═══════════════════

/**
 * صفحة لمرّة واحدة.
 *
 * نفس منطق صفحة الإعداد الأولي بالظبط: بتشتغل مرة، وبعدين تمسح
 * SETUP_SECRET من كلاودفلير فتختفي تمامًا (404).
 */
export function platformSetupPage(): Html {
  return shell({
    title: 'تأسيس المنصّة',
    tenantName: null,
    noIndex: true,
    script: PLATFORM_SETUP_SCRIPT,
    body: html`<main class="counter"><div>
${raw(receiptEdge())}
<div class="counter-card">
  <div class="counter-brand">${raw(brandLockup(false))}</div>
  <h1 class="counter-title">تأسيس المنصّة</h1>
  <p class="counter-sub">
    حساب واحد لإدارة اشتراكات المحلات. يعمل هذا النموذج مرة واحدة فقط.
  </p>

  <div class="alert-box" id="err" role="alert" hidden>
    <span aria-hidden="true">⚠</span><span id="err-text"></span>
  </div>

  <form id="f" novalidate>
    <div class="field">
      <label class="field-label" for="secret">سرّ التأسيس</label>
      <input class="field-input" id="secret" type="password" dir="ltr"
        autocomplete="off" maxlength="512" required>
      <p class="field-hint">القيمة نفسها الموجودة في SETUP_SECRET.</p>
    </div>

    <div class="field">
      <label class="field-label" for="username">اسم المستخدم</label>
      <input class="field-input" id="username" type="text" dir="ltr"
        autocapitalize="none" spellcheck="false" maxlength="32" required>
    </div>

    <div class="field">
      <label class="field-label" for="fullName">الاسم الكامل</label>
      <input class="field-input" id="fullName" type="text" maxlength="80" required>
    </div>

    <div class="field">
      <label class="field-label" for="password">كلمة المرور</label>
      <input class="field-input" id="password" type="password" dir="ltr"
        autocomplete="new-password" maxlength="1024" required>
      <p class="field-hint">12 حرفًا على الأقل.</p>
    </div>

    <div class="field">
      <label class="field-label" for="passkey">المفتاح الثاني</label>
      <input class="field-input" id="passkey" type="password" dir="ltr"
        autocomplete="off" maxlength="512" required>
      <p class="field-hint">
        16 حرفًا على الأقل، ويجب أن يختلف تمامًا عن كلمة المرور.
        هذا هو القفل الثاني على البوّابة السرّية.
      </p>
    </div>

    <button class="btn-primary" id="btn" type="submit">تأسيس الحساب</button>
  </form>

  <div class="counter-foot"><span>بعد الانتهاء</span><span>احذف SETUP_SECRET</span></div>
</div>
</div></main>`,
  });
}

const PLATFORM_SETUP_SCRIPT = `
(function () {
  var form = document.getElementById('f');
  var btn = document.getElementById('btn');
  var box = document.getElementById('err');
  var text = document.getElementById('err-text');

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    btn.disabled = true;
    btn.textContent = 'جارٍ التأسيس…';

    try {
      var res = await fetch('/api/platform/bootstrap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          setupSecret: document.getElementById('secret').value,
          username: document.getElementById('username').value,
          fullName: document.getElementById('fullName').value,
          password: document.getElementById('password').value,
          passkey: document.getElementById('passkey').value
        })
      });
      var data = await res.json().catch(function () { return null; });

      box.hidden = false;
      if (res.ok) {
        box.setAttribute('data-tone', 'ok');
        text.textContent = 'تم التأسيس. ادخل من البوّابة السرّية بكود المحل MEEZAN.';
        return;
      }

      box.removeAttribute('data-tone');
      text.textContent = (data && data.error && data.error.message) || 'فشل التأسيس.';
    } catch (err) {
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'تعذّر الاتصال بالخادم.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'تأسيس الحساب';
    }
  });
})();
`;


// ═══════════════════ 10) تغيير كلمة المرور ═══════════════════

/**
 * شاشة تغيير كلمة المرور.
 *
 * ══ ليه صفحة مستقلة مش نافذة داخل الشاشة؟ ══
 * الرابط في قائمة التلات نقط، والقائمة دي مشتركة بين كل الشاشات.
 * الصفحة المستقلة معناها كود واحد بيخدم الأربعة — مش أربع نسخ
 * من نفس النموذج تتصلّح كل واحدة لوحدها.
 */
export function passwordPage(data: {
  fullName: string;
  username: string;
  tenantName: string;
  roleKey: string;
  branchLabel: string | null;
}): Html {
  return shell({
    title: 'تغيير كلمة المرور',
    tenantName: data.tenantName,
    noIndex: true,
    script: PASSWORD_SCRIPT,
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="pwmsg" role="alert" hidden><span id="pwmsg-text"></span></div>

  <details class="panel" open>
    <summary>تغيير كلمة المرور</summary>
    <div class="panel-body">
      <form id="pwf" novalidate>
        <div class="field">
          <label class="field-label" for="cur">كلمة المرور الحالية</label>
          <input class="field-input" id="cur" type="password" dir="ltr"
            autocomplete="current-password" maxlength="1024" required>
        </div>

        <div class="field">
          <label class="field-label" for="new1">كلمة المرور الجديدة</label>
          <input class="field-input" id="new1" type="password" dir="ltr"
            autocomplete="new-password" maxlength="1024" required>
          <p class="field-hint">12 حرفًا على الأقل.</p>
        </div>

        <div class="field">
          <label class="field-label" for="new2">تأكيد كلمة المرور الجديدة</label>
          <input class="field-input" id="new2" type="password" dir="ltr"
            autocomplete="new-password" maxlength="1024" required>
        </div>

        <div class="alert-box">
          <span>
            بعد التغيير تُغلق كل الجلسات — على هذا الجهاز وغيره —
            وتسجّل الدخول من جديد بكلمتك الجديدة.
          </span>
        </div>

        <button class="btn-primary" id="pwbtn" type="submit">حفظ كلمة المرور</button>
      </form>
    </div>
  </details>
</main>

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

const PASSWORD_SCRIPT = `
${MENU_JS}

(function () {
  var form = document.getElementById('pwf');
  var btn = document.getElementById('pwbtn');
  var box = document.getElementById('pwmsg');
  var text = document.getElementById('pwmsg-text');

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    text.textContent = message;
    box.scrollIntoView({ block: 'nearest' });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    var cur = document.getElementById('cur').value;
    var n1 = document.getElementById('new1').value;
    var n2 = document.getElementById('new2').value;

    // التطابق بيتفحص هنا قبل أي رحلة شبكة — غلطة كتابة ما تستاهلش
    // تروح للخادم وترجع
    if (n1 !== n2) { say('كلمتا المرور الجديدتان غير متطابقتين.', false); return; }
    if (n1.length < 12) { say('كلمة المرور الجديدة 12 حرفًا على الأقل.', false); return; }

    btn.disabled = true;
    btn.textContent = 'جارٍ الحفظ…';

    try {
      var res = await fetch('/api/auth/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ currentPassword: cur, newPassword: n1 })
      });
      var data = await res.json().catch(function () { return null; });

      if (res.ok) {
        say('تم تغيير كلمة المرور. جارٍ نقلك لتسجيل الدخول…', true);
        form.reset();
        setTimeout(function () { window.location.href = '/login'; }, 1800);
        return;
      }

      say((data && data.error && data.error.message) || 'تعذّر تغيير كلمة المرور.', false);
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    } finally {
      btn.disabled = false;
      btn.textContent = 'حفظ كلمة المرور';
    }
  });
})();
`;


// ═══════════════════ شاشة قائمة الدخل ═══════════════════

export interface ReportPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canSell: boolean;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  /** profit.view_real — بيغيّر شكل القائمة كلها مش سطر فيها */
  canSeeCost: boolean;
  from: string;
  to: string;
  today: string;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * قائمة الدخل.
 *
 * ══ ليه الأرقام بتتجاب بالجافاسكربت مش مع الصفحة؟ ══
 * عشان تغيير الفترة ما يعملش تحميل كامل للصفحة. الجدول بيتحدّث
 * مكانه، والفترة بتفضل في العنوان.
 *
 * ══ وليه القائمة شكلين مش شكل واحد؟ ══
 * صاحب المحل بيشوف التكلفة والربح. مدير الفرع بيشوف الحركة بلا
 * هامش، والسطر الأخير عنده مكتوب عليه صراحةً إن التكلفة **مش**
 * محسوبة — عشان ما يفتكرهاش ربح.
 */
export function reportPage(data: ReportPageData): Html {
  return shell({
    title: 'قائمة الدخل',
    tenantName: data.tenantName,
    script: reportScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="repmsg" role="alert" hidden><span id="repmsg-text"></span></div>

  <details class="panel" open>
    <summary>الفترة</summary>
    <div class="panel-body">
      <label class="field-label" for="rep-from">من</label>
      <input class="field-input" id="rep-from" type="date" dir="ltr"
        value="${data.from}" max="${data.today}">

      <label class="field-label" for="rep-to">إلى</label>
      <input class="field-input" id="rep-to" type="date" dir="ltr"
        value="${data.to}" max="${data.today}">

      <button class="btn-mini" type="button" id="rep-go">عرض</button>
      <button class="btn-mini" type="button" id="rep-xls">تصدير إكسيل</button>
      <button class="btn-mini" type="button" id="rep-pdf">تصدير PDF</button>
      <p class="field-hint" id="rep-scope"></p>
    </div>
  </details>

  <details class="panel" open>
    <summary>القائمة</summary>
    <div class="panel-body">
      <div id="rep-body">
        <p class="field-hint">جارٍ الحساب…</p>
      </div>
    </div>
  </details>

  <details class="panel">
    <summary>المصروفات بالتفصيل</summary>
    <div class="panel-body">
      <div id="rep-exp">
        <p class="field-hint">—</p>
      </div>
    </div>
  </details>

  ${data.canSeeCost
    ? html`<p class="field-hint">
        رصيد الخزينة يقول كم مالًا لديك الآن. هذه القائمة تقول كم ربحت.
        الرقمان مختلفان: قد يكون الدرج ممتلئًا وأنت خاسر، إن كانت البضاعة
        المباعة أغلى مما قبضته.
      </p>`
    : html`<p class="field-hint">
        هذه القائمة لا تتضمن تكلفة البضاعة، لذا الرقم الأخير ليس ربحًا —
        هو الفرق بين ما دخل وما خرج فقط.
      </p>`}
</main>

${tabBar('app', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function reportScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
(function () {
  var box  = document.getElementById('repmsg');
  var text = document.getElementById('repmsg-text');
  var body = document.getElementById('rep-body');
  var expEl = document.getElementById('rep-exp');
  var scopeEl = document.getElementById('rep-scope');

  // ⚠ آخر نتيجة محفوظة في الذاكرة. التصدير بيبني من نفس الأرقام
  // اللي على الشاشة — مش بينادي الخادم تاني. لو نادى، ممكن
  // يطلع ملف بأرقام غير اللي المستخدم شافها وقرر على أساسها.
  var LAST = null;

  function money(piastres) {
    if (piastres === null || piastres === undefined) return '—';
    var neg = piastres < 0;
    var abs = Math.abs(Math.trunc(piastres));
    return (neg ? '-' : '') + Math.floor(abs / 100).toLocaleString('en-US') +
      '.' + String(abs % 100).padStart(2, '0');
  }

  // سطر في القائمة. strong = سطر إجمالي بخط أعرض وفاصل فوقه.
  function line(label, value, opts) {
    opts = opts || {};
    var row = document.createElement('div');
    row.className = 'mv-row';
    if (opts.strong) row.style.fontWeight = '500';
    if (opts.top) row.style.borderTop = '1px solid var(--line, #ddd)';
    if (opts.muted) row.style.opacity = '0.7';

    var l = document.createElement('span');
    l.className = 'mv-sub';
    l.textContent = label;
    row.appendChild(l);

    var v = document.createElement('span');
    v.className = 'mv-amount';
    if (opts.dir) v.setAttribute('data-dir', opts.dir);
    if (opts.big) v.style.fontSize = '18px';
    v.textContent = value;
    row.appendChild(v);

    return row;
  }

  async function load() {
    var from = document.getElementById('rep-from').value;
    var to   = document.getElementById('rep-to').value;

    body.textContent = '';
    body.appendChild(line('جارٍ الحساب…', ''));

    try {
      var res = await fetch('/api/reports/income?from=' + encodeURIComponent(from) +
        '&to=' + encodeURIComponent(to), { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });

      if (!res.ok || !data || !data.ok) {
        body.textContent = '';
        box.hidden = false;
        box.removeAttribute('data-tone');
        text.textContent = (data && data.error && data.error.message) || 'تعذّر حساب القائمة.';
        return;
      }
      box.hidden = true;

      var s = data.statement;
      LAST = data;
      if (scopeEl) {
        scopeEl.textContent = 'النطاق: ' + data.scopeLabel +
          ' · ' + s.salesCount + ' فاتورة · ' + s.refundsCount + ' مرتجع';
      }

      body.textContent = '';
      body.appendChild(line('المبيعات', money(s.salesPiastres), { dir: 'IN' }));

      if (s.refundsPiastres > 0) {
        body.appendChild(line('المرتجعات', '-' + money(s.refundsPiastres), { dir: 'OUT' }));
      }
      body.appendChild(line('صافي المبيعات', money(s.netSalesPiastres), { strong: true, top: true }));

      // ⚠ الجزء ده بيظهر لصاحب profit.view_real بس. القيم بترجع
      // null من الخادم لغيره، فمفيش حاجة تتخبّى هنا — مش موجودة.
      if (s.cogsPiastres !== null && s.cogsPiastres !== undefined) {
        var netCogs = s.cogsPiastres - (s.returnedCogsPiastres || 0);
        body.appendChild(line('تكلفة البضاعة المباعة', '-' + money(netCogs), { dir: 'OUT' }));
        body.appendChild(line('مجمل الربح', money(s.grossProfitPiastres),
          { strong: true, top: true }));
      }

      body.appendChild(line('المصروفات', '-' + money(s.expensesPiastres), { dir: 'OUT' }));

      if (s.netProfitPiastres !== null && s.netProfitPiastres !== undefined) {
        body.appendChild(line('صافي الربح', money(s.netProfitPiastres),
          { strong: true, top: true, big: true,
            dir: s.netProfitPiastres >= 0 ? 'IN' : 'OUT' }));

        if (s.netSalesPiastres > 0) {
          var margin = Math.round((s.grossProfitPiastres / s.netSalesPiastres) * 1000) / 10;
          body.appendChild(line('هامش مجمل الربح', margin + '٪', { muted: true }));
        }
      } else {
        var diff = s.netSalesPiastres - s.expensesPiastres;
        body.appendChild(line('صافي النشاط (التكلفة غير محسوبة)', money(diff),
          { strong: true, top: true, big: true }));
      }

      // ⚠ السُلفة بره الحساب عن قصد: دَين على الموظّف بيتخصم من
      // راتبه، مش مصروف على المحل. لو دخلت الحساب هتتحسب مرتين.
      if (s.advancesPiastres > 0) {
        body.appendChild(line('سُلف موظفين (خارج الحساب — تُخصم من الراتب)',
          money(s.advancesPiastres), { muted: true, top: true }));
      }
      // ⚠ خارج الحساب لنفس سبب السُلف: شرا البضاعة تحويل فلوس
      // لمخزون، والتكلفة بتتحسب وقت البيع. لو دخلت المصروفات
      // كانت هتتحسب مرتين.
      if (s.inventoryPurchasesPiastres > 0) {
        body.appendChild(line('شراء بضاعة (خارج الحساب — تُحتسب عند البيع)',
          money(s.inventoryPurchasesPiastres), { muted: true }));
      }
      if (s.refundFeesPiastres > 0) {
        body.appendChild(line('منها رسوم استرجاع محتجزة',
          money(s.refundFeesPiastres), { muted: true }));
      }

      // ─── المصروفات بالتفصيل ───
      expEl.textContent = '';
      var rows = data.expenses || [];
      if (rows.length === 0) {
        expEl.appendChild(line('لا مصروفات في هذه الفترة.', ''));
      } else {
        for (var i = 0; i < rows.length; i++) {
          expEl.appendChild(line(
            rows[i].reasonName + ' (' + rows[i].movementCount + ')',
            money(rows[i].totalPiastres), { dir: 'OUT' }));
        }
      }
    } catch (err) {
      body.textContent = '';
      box.hidden = false;
      box.removeAttribute('data-tone');
      text.textContent = 'تعذّر الاتصال بالخادم.';
    }
  }

  document.getElementById('rep-go').addEventListener('click', load);

  /** بيبني صفوف القائمة للتصدير — نفس ترتيب الشاشة */
  function exportRows() {
    if (!LAST) return null;
    var s = LAST.statement;

    var rows = [
      ['المبيعات', money(s.salesPiastres)],
      ['المرتجعات', '-' + money(s.refundsPiastres)],
      ['صافي المبيعات', money(s.netSalesPiastres)]
    ];

    if (s.cogsPiastres !== null && s.cogsPiastres !== undefined) {
      rows.push(['تكلفة البضاعة المباعة',
        '-' + money(s.cogsPiastres - (s.returnedCogsPiastres || 0))]);
      rows.push(['مجمل الربح', money(s.grossProfitPiastres)]);
    }

    rows.push(['المصروفات', '-' + money(s.expensesPiastres)]);

    // تفصيل المصروفات جوّه نفس الملف — الرقم المجمّع لوحده
    // ما بيخليكش تعمل حاجة
    var exp = LAST.expenses || [];
    for (var i = 0; i < exp.length; i++) {
      rows.push(['   ' + exp[i].reasonName, '-' + money(exp[i].totalPiastres)]);
    }

    if (s.advancesPiastres > 0) rows.push(['سُلف (خارج الحساب)', money(s.advancesPiastres)]);
    if (s.inventoryPurchasesPiastres > 0) {
      rows.push(['شراء بضاعة (خارج الحساب)', money(s.inventoryPurchasesPiastres)]);
    }

    var final = s.netProfitPiastres !== null && s.netProfitPiastres !== undefined
      ? ['صافي الربح', money(s.netProfitPiastres)]
      : ['صافي النشاط (التكلفة غير محسوبة)',
         money(s.netSalesPiastres - s.expensesPiastres)];

    return {
      title: 'قائمة الدخل',
      subtitle: LAST.from + ' إلى ' + LAST.to + ' · ' + LAST.scopeLabel,
      columns: ['البند', 'المبلغ (ج.م)'],
      rows: rows,
      totals: final,
      filename: 'income-' + LAST.from + '_' + LAST.to
    };
  }

  document.getElementById('rep-xls').addEventListener('click', function () {
    var d = exportRows();
    if (d) { window.exportXls(d); return; }
    box.hidden = false; box.removeAttribute('data-tone');
    text.textContent = 'اعرض القائمة أولًا.';
  });

  document.getElementById('rep-pdf').addEventListener('click', function () {
    var d = exportRows();
    if (d) { window.exportPdf(d); return; }
    box.hidden = false; box.removeAttribute('data-tone');
    text.textContent = 'اعرض القائمة أولًا.';
  });

  load();
})();
`;
}


// ═══════════════════ شاشة الموردين ═══════════════════

export interface SuppliersPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canSell: boolean;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  treasuries: Array<{ treasuryId: string; name: string }>;
  today: string;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * الموردين والديون.
 *
 * ══ ليه القائمة بتتجاب بالجافاسكربت؟ ══
 * الأرصدة بتتغيّر مع كل حركة في نفس الشاشة. لو اتجابت مع
 * الصفحة، كل تسجيل دين كان هيحتاج إعادة تحميل كاملة.
 */
export function suppliersPage(data: SuppliersPageData): Html {
  return shell({
    title: 'الموردين',
    tenantName: data.tenantName,
    script: suppliersScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.treasuries,
    ),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="supmsg" role="alert" hidden><span id="supmsg-text"></span></div>

  <details class="panel">
    <summary>إضافة مورّد</summary>
    <div class="panel-body">
      <label class="field-label" for="sup-name">الاسم</label>
      <input class="field-input" id="sup-name" type="text" maxlength="80" autocomplete="off">

      <label class="field-label" for="sup-phone">الهاتف</label>
      <input class="field-input" id="sup-phone" type="text" dir="ltr" maxlength="32"
        autocomplete="off">

      <label class="field-label" for="sup-notes">ملاحظات</label>
      <input class="field-input" id="sup-notes" type="text" maxlength="500" autocomplete="off">

      <button class="btn-mini" type="button" id="sup-add">إضافة</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>الموردين <span id="sup-count"></span></summary>
    <div class="panel-body">
      <p class="field-hint">
        الدين محسوب من الحركات: ما استلمته بالأجل ناقص ما سدّدته.
        السداد يخرج من الخزينة فورًا، ولا يُحتسب مصروفًا في قائمة الدخل —
        تكلفة البضاعة تُحتسب عند بيعها.
      </p>
      <div id="sup-rows"><p class="field-hint">جارٍ التحميل…</p></div>
    </div>
  </details>
</main>

${tabBar('app', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function suppliersScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  /** ⚠ لازم تتمرّر صراحةً — الدالة دي مالهاش وصول لبيانات الصفحة */
  treasuries: Array<{ treasuryId: string; name: string }>,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
(function () {
  var box  = document.getElementById('supmsg');
  var text = document.getElementById('supmsg-text');
  var rows = document.getElementById('sup-rows');
  var countEl = document.getElementById('sup-count');

  function say(msg, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok'); else box.removeAttribute('data-tone');
    text.textContent = msg;
  }

  function money(p) {
    var neg = p < 0, abs = Math.abs(Math.trunc(p));
    return (neg ? '-' : '') + Math.floor(abs / 100).toLocaleString('en-US') +
      '.' + String(abs % 100).padStart(2, '0');
  }

  async function send(url, body, btn, busy) {
    var original = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = busy; }
    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json().catch(function () { return null; });
      if (res.ok && data && data.ok) return data;
      say((data && data.error && data.error.message) || 'تعذّر تنفيذ الطلب.', false);
      return null;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = original; }
    }
  }

  async function load() {
    try {
      var res = await fetch('/api/suppliers', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        rows.textContent = '';
        say((data && data.error && data.error.message) || 'تعذّر تحميل الموردين.', false);
        return;
      }

      var list = data.suppliers || [];
      if (countEl) countEl.textContent = '(' + list.length + ')';
      rows.textContent = '';

      if (list.length === 0) {
        var empty = document.createElement('p');
        empty.className = 'field-hint';
        empty.textContent = 'لا يوجد موردون بعد. أضف أول مورّد من الأعلى.';
        rows.appendChild(empty);
        return;
      }

      for (var i = 0; i < list.length; i++) {
        var sp = list[i];

        var row = document.createElement('div');
        row.className = 'prod-row';

        var main = document.createElement('div');
        main.className = 'prod-row-main';

        var nm = document.createElement('span');
        nm.className = 'prod-row-name';
        nm.textContent = sp.name;
        main.appendChild(nm);

        var sub = document.createElement('span');
        sub.className = 'prod-row-sub';
        sub.textContent =
          (sp.phone ? sp.phone + ' · ' : '') +
          sp.productCount + ' منتج · استلمت ' + money(sp.debtPiastres) +
          ' · سدّدت ' + money(sp.paidPiastres) +
          (sp.lastMovement ? ' · آخر حركة ' + sp.lastMovement : '');
        main.appendChild(sub);
        row.appendChild(main);

        // ⚠ الرصيد الموجب معناه **عليك** دين. بنعرضه بلون
        // المنصرف عشان العين تفرّق بين ما لك وما عليك.
        var bal = document.createElement('span');
        bal.className = 'mv-amount';
        bal.setAttribute('data-dir', sp.balancePiastres > 0 ? 'OUT' : 'IN');
        bal.textContent = money(sp.balancePiastres);
        row.appendChild(bal);

        var btn = document.createElement('button');
        btn.className = 'btn-mini';
        btn.type = 'button';
        btn.textContent = 'حركة';
        btn.setAttribute('data-sup-open', sp.supplierId);
        row.appendChild(btn);

        rows.appendChild(row);

        var panel = document.createElement('div');
        panel.className = 'exit-edit';
        panel.id = 'supp-' + sp.supplierId;
        panel.hidden = true;
        panel.innerHTML =
          '<label class="field-label">النوع</label>' +
          '<select class="field-input" id="supk-' + sp.supplierId + '">' +
            '<option value="DEBT">استلمت بضاعة بالأجل (دين)</option>' +
            '<option value="PAYMENT">سدّدت له (يخرج من الخزينة)</option>' +
          '</select>' +
          '<label class="field-label">المبلغ</label>' +
          '<input class="field-input" id="supa-' + sp.supplierId + '" type="text" ' +
            'inputmode="decimal" dir="ltr" placeholder="1500.00">' +
          '<div id="supt-wrap-' + sp.supplierId + '" hidden>' +
            '<label class="field-label">الخزينة</label>' +
            '<select class="field-input" id="supt-' + sp.supplierId + '">' +
              ${JSON.stringify(
                treasuries
                  .map((t) => `<option value="${t.treasuryId}">${t.name}</option>`)
                  .join(''),
              )} +
            '</select>' +
          '</div>' +
          '<label class="field-label">ملاحظة</label>' +
          '<input class="field-input" id="supn-' + sp.supplierId + '" type="text" maxlength="500">' +
          '<button class="btn-mini" type="button" data-sup-go="' + sp.supplierId + '">تسجيل</button>';

        rows.appendChild(panel);
      }
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    }
  }

  // فتح/قفل لوحة الحركة
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sup-open]') : null;
    if (!btn) return;
    var panel = document.getElementById('supp-' + btn.getAttribute('data-sup-open'));
    if (panel) panel.hidden = !panel.hidden;
  });

  // ⚠ خانة الخزينة بتظهر للسداد بس. الدين ما بيمسّش الدرج،
  // فعرض خزينة معاه كان هيوحي إن فيه فلوس هتتحرّك.
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (!el || !el.id || el.id.indexOf('supk-') !== 0) return;
    var id = el.id.slice(5);
    var wrap = document.getElementById('supt-wrap-' + id);
    if (wrap) wrap.hidden = el.value !== 'PAYMENT';
  });

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sup-go]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-sup-go');
    var kind = (document.getElementById('supk-' + id) || {}).value;
    var amount = (document.getElementById('supa-' + id) || {}).value;
    var note = (document.getElementById('supn-' + id) || {}).value;

    if (!amount || !amount.trim()) { say('اكتب المبلغ.', false); return; }

    var body = { kind: kind, amount: amount, note: note };
    if (kind === 'PAYMENT') {
      var tre = document.getElementById('supt-' + id);
      if (!tre || !tre.value) { say('اختر الخزينة.', false); return; }
      body.treasuryId = tre.value;
    }

    var result = await send('/api/suppliers/' + encodeURIComponent(id) + '/movement',
      body, btn, '…');
    if (result) {
      say('تم التسجيل — الرصيد الآن ' + money(result.newBalance) + '.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  document.getElementById('sup-add').addEventListener('click', async function () {
    var name = document.getElementById('sup-name').value;
    if (!name || name.trim().length < 2) { say('اكتب اسم المورّد.', false); return; }

    var result = await send('/api/suppliers', {
      name: name,
      phone: document.getElementById('sup-phone').value,
      notes: document.getElementById('sup-notes').value
    }, this, 'جارٍ الإضافة…');

    if (result) {
      say('تمت الإضافة.', true);
      setTimeout(function () { window.location.reload(); }, 800);
    }
  });

  load();
})();
`;
}


// ═══════════════════ شاشة الصيانة ═══════════════════

export interface MaintenancePageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canSell: boolean;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  /** maintenance.manage — الحالات والتكاليف وإدارة الورش */
  canManage: boolean;
  /** فروع المحل — للمالك بس، فاضية لغيره لأنه مقفول على فرعه */
  branches: Array<{ id: string; name: string }>;
  today: string;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * الصيانة — تبويبين لنوعين مختلفين تمامًا.
 *
 * أجهزة العملاء أولًا لأنها الأكتر يوميًا: الزبون بيقف على
 * الكاونتر مستني. أجهزة المحل بتروح للورشة مرة كل فترة.
 */
export function maintenancePage(data: MaintenancePageData): Html {
  return shell({
    title: 'الصيانة',
    tenantName: data.tenantName,
    script: maintenanceScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.canManage,
    ),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="mtmsg" role="alert" hidden><span id="mtmsg-text"></span></div>

  <details class="panel">
    <summary>استلام جهاز عميل</summary>
    <div class="panel-body">
      ${data.branches.length > 0
        ? html`<label class="field-label" for="tk-branch">الفرع</label>
            <select class="field-input" id="tk-branch">
              <option value="">— اختر الفرع —</option>
              ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
            </select>
            <p class="field-hint">
              صاحب المحل يرى كل الفروع، فلا بد أن يحدّد أي فرع استلم الجهاز.
            </p>`
        : ''}

      <label class="field-label" for="tk-cname">اسم العميل</label>
      <input class="field-input" id="tk-cname" type="text" maxlength="80" autocomplete="off">

      <label class="field-label" for="tk-cphone">هاتف العميل</label>
      <input class="field-input" id="tk-cphone" type="text" dir="ltr" maxlength="32"
        autocomplete="off">

      <label class="field-label" for="tk-device">الجهاز</label>
      <input class="field-input" id="tk-device" type="text" maxlength="80" autocomplete="off">

      <label class="field-label" for="tk-serial">السريال (اختياري)</label>
      <input class="field-input" id="tk-serial" type="text" dir="ltr" maxlength="64"
        autocomplete="off">

      <label class="field-label" for="tk-color">اللون</label>
      <input class="field-input" id="tk-color" type="text" maxlength="32" autocomplete="off">

      <label class="field-label" for="tk-cond">حالة الجهاز عند الاستلام</label>
      <input class="field-input" id="tk-cond" type="text" maxlength="500"
        placeholder="خدش في الزاوية · الشاشة سليمة" autocomplete="off">
      <p class="field-hint">
        اكتبها بدقة — هي التي تحمي الطرفين لو حصل خلاف عند التسليم.
      </p>

      <label class="field-label" for="tk-complaint">شكوى العميل</label>
      <input class="field-input" id="tk-complaint" type="text" maxlength="1000"
        autocomplete="off">

      <label class="field-label" for="tk-unlock-kind">فتح الجهاز</label>
      <select class="field-input" id="tk-unlock-kind">
        <option value="NONE">مفتوح / لم يُعطِ البيانات</option>
        <option value="PASSWORD">كلمة مرور</option>
        <option value="PATTERN">نمط</option>
      </select>

      <div id="tk-pass-wrap" hidden>
        <label class="field-label" for="tk-pass">كلمة المرور</label>
        <input class="field-input" id="tk-pass" type="text" dir="ltr" maxlength="200"
          autocomplete="off">
      </div>

      <div id="tk-pattern-wrap" hidden>
        <label class="field-label">ارسم النمط</label>
        <div class="pat-grid" id="tk-pattern">
          <div class="pat-dot" data-dot="1">1</div><div class="pat-dot" data-dot="2">2</div>
          <div class="pat-dot" data-dot="3">3</div><div class="pat-dot" data-dot="4">4</div>
          <div class="pat-dot" data-dot="5">5</div><div class="pat-dot" data-dot="6">6</div>
          <div class="pat-dot" data-dot="7">7</div><div class="pat-dot" data-dot="8">8</div>
          <div class="pat-dot" data-dot="9">9</div>
        </div>
        <p class="pat-out" id="tk-pattern-out">—</p>
        <button class="btn-mini" type="button" id="tk-pattern-clear">مسح النمط</button>
      </div>

      <label class="field-label" for="tk-shop">محل الصيانة</label>
      <select class="field-input" id="tk-shop"><option value="">— داخليًا —</option></select>

      <label class="field-label" for="tk-cost">التكلفة المتوقّعة</label>
      <input class="field-input" id="tk-cost" type="text" inputmode="decimal" dir="ltr">

      <label class="field-label" for="tk-promised">تاريخ التسليم المتوقّع</label>
      <input class="field-input" id="tk-promised" type="date" dir="ltr">

      <button class="btn-mini" type="button" id="tk-add">استلام الجهاز</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>أجهزة العملاء <span id="tk-count"></span></summary>
    <div class="panel-body">
      <label class="field-label" for="tk-scope">العرض</label>
      <select class="field-input" id="tk-scope">
        <option value="OPEN">عندنا الآن</option>
        <option value="DELIVERED">سُلِّمت للعملاء</option>
        <option value="ALL">الكل</option>
      </select>

      <input class="field-input" id="tk-search" type="search"
        placeholder="اسم · هاتف · سريال · جهاز · شكوى" autocomplete="off">

      <label class="field-label" for="tk-shop-filter">محل الصيانة</label>
      <select class="field-input" id="tk-shop-filter">
        <option value="">— كل المحلات —</option>
      </select>

      <div class="prod-edit-grid">
        <div>
          <label class="field-label" for="tk-from">من</label>
          <input class="field-input" id="tk-from" type="date" dir="ltr">
        </div>
        <div>
          <label class="field-label" for="tk-to">إلى</label>
          <input class="field-input" id="tk-to" type="date" dir="ltr">
        </div>
      </div>
      <button class="btn-mini" type="button" id="tk-clear">مسح الفلاتر</button>

      <div id="tk-rows"><p class="field-hint">جارٍ التحميل…</p></div>
    </div>
  </details>

  <details class="panel">
    <summary>أجهزة المحل في الورش <span id="mr-count"></span></summary>
    <div class="panel-body">
      <p class="field-hint">
        الجهاز المُرسَل تُخصم كميته من المخزون — لا يصحّ أن يُباع وهو في الورشة.
        الإرسال يتم من شاشة المنتجات.
      </p>
      <div id="mr-rows"></div>
    </div>
  </details>

  ${data.canManage
    ? html`<details class="panel">
        <summary>محلات الصيانة <span id="rs-count"></span></summary>
        <div class="panel-body">
          <label class="field-label" for="rs-name">اسم المحل</label>
          <input class="field-input" id="rs-name" type="text" maxlength="80" autocomplete="off">
          <label class="field-label" for="rs-phone">الهاتف</label>
          <input class="field-input" id="rs-phone" type="text" dir="ltr" maxlength="32"
            autocomplete="off">
          <button class="btn-mini" type="button" id="rs-add">إضافة</button>
          <div id="rs-rows"></div>
        </div>
      </details>`
    : ''}
</main>

${tabBar('app', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function maintenanceScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  canManage: boolean,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
(function () {
  var CAN_MANAGE = ${JSON.stringify(canManage)};

  var box  = document.getElementById('mtmsg');
  var text = document.getElementById('mtmsg-text');

  var STATUS = {
    CHECKING: 'قيد الفحص',
    WAITING_PART: 'بانتظار قطعة غيار',
    READY: 'جاهز للتسليم',
    DELIVERED: 'تم التسليم',
    CANCELLED: 'ملغاة'
  };

  function say(msg, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok'); else box.removeAttribute('data-tone');
    text.textContent = msg;
  }

  function money(p) {
    var abs = Math.abs(Math.trunc(p || 0));
    return Math.floor(abs / 100).toLocaleString('en-US') + '.' + String(abs % 100).padStart(2, '0');
  }

  async function send(url, body, btn, busy, method) {
    var original = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = busy; }
    try {
      var res = await fetch(url, {
        method: method || 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json().catch(function () { return null; });
      if (res.ok && data && data.ok) return data;
      say((data && data.error && data.error.message) || 'تعذّر تنفيذ الطلب.', false);
      return null;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = original; }
    }
  }

  // ══════════ رسم النمط ══════════
  //
  // ⚠ التسلسل بيتخزّن كأرقام "1-2-3-6-9" مش كصورة.
  // السبب: النص بيتقرا ويتعدّل بالكتابة لو الشبكة ما اشتغلتش
  // على جهاز معيّن، والصورة بتبقى طريق واحد بلا مخرج.
  var pattern = [];

  function paintPattern() {
    var dots = document.querySelectorAll('#tk-pattern .pat-dot');
    for (var i = 0; i < dots.length; i++) {
      dots[i].setAttribute('data-on',
        pattern.indexOf(dots[i].getAttribute('data-dot')) !== -1 ? 'true' : 'false');
    }
    var out = document.getElementById('tk-pattern-out');
    if (out) out.textContent = pattern.length ? pattern.join('-') : '—';
  }

  function touchDot(el) {
    if (!el || !el.getAttribute) return;
    var d = el.getAttribute('data-dot');
    // النقطة ما بتتكررش — النمط في أندرويد ما بيعديش على نفس
    // النقطة مرتين
    if (!d || pattern.indexOf(d) !== -1) return;
    pattern.push(d);
    paintPattern();
  }

  var grid = document.getElementById('tk-pattern');
  if (grid) {
    var drawing = false;
    grid.addEventListener('pointerdown', function (e) {
      drawing = true;
      touchDot(e.target.closest('.pat-dot'));
    });
    grid.addEventListener('pointermove', function (e) {
      if (!drawing) return;
      // السحب على الموبايل: العنصر تحت الإصبع مش اللي بدأنا منه
      var el = document.elementFromPoint(e.clientX, e.clientY);
      if (el && el.classList && el.classList.contains('pat-dot')) touchDot(el);
    });
    window.addEventListener('pointerup', function () { drawing = false; });

    var clr = document.getElementById('tk-pattern-clear');
    if (clr) clr.addEventListener('click', function () { pattern = []; paintPattern(); });
  }

  // إظهار الحقل المناسب لنوع الفتح
  var kindEl = document.getElementById('tk-unlock-kind');
  if (kindEl) {
    kindEl.addEventListener('change', function () {
      document.getElementById('tk-pass-wrap').hidden = kindEl.value !== 'PASSWORD';
      document.getElementById('tk-pattern-wrap').hidden = kindEl.value !== 'PATTERN';
    });
  }

  // ══════════ عرض بيانات الفتح ══════════
  //
  // ⚠ النمط بيتعاد **رسمه**، مش بيتعرض كأرقام.
  //
  // "1-2-3-6-9" رقم لازم تترجمه في دماغك لشكل قبل ما تقدر
  // ترسمه على الجهاز. والترجمة دي بتتعمل غلط بسهولة — تحت ضغط
  // وقدّام زبون مستني.
  //
  // الرسم المتحرّك بيوري الشكل واتجاه السحب مرة واحدة.

  var PAT_TIMERS = [];

  function clearPatternTimers() {
    for (var i = 0; i < PAT_TIMERS.length; i++) clearTimeout(PAT_TIMERS[i]);
    PAT_TIMERS = [];
  }

  // مكان النقطة في مربع 300×300 — نفس ترتيب لوحة الرسم
  function dotXY(n) {
    var idx = parseInt(n, 10) - 1;
    return { x: (idx % 3) * 100 + 50, y: Math.floor(idx / 3) * 100 + 50 };
  }

  function playPattern(seq, stage, svg) {
    clearPatternTimers();

    var dots = stage.querySelectorAll('.pat-play-dot');
    for (var i = 0; i < dots.length; i++) dots[i].setAttribute('data-on', 'false');
    svg.textContent = '';

    var steps = String(seq || '').split('-').filter(function (x) { return x; });
    if (steps.length === 0) return;

    // النقطة الأولى بتنوّر فورًا، وكل خط بعدها بمهلة
    var STEP = 380;

    steps.forEach(function (n, k) {
      PAT_TIMERS.push(setTimeout(function () {
        var dot = stage.querySelector('[data-play="' + n + '"]');
        if (dot) dot.setAttribute('data-on', 'true');

        if (k > 0) {
          var a = dotXY(steps[k - 1]);
          var b = dotXY(n);
          var ln = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          ln.setAttribute('x1', a.x); ln.setAttribute('y1', a.y);
          ln.setAttribute('x2', b.x); ln.setAttribute('y2', b.y);
          ln.setAttribute('stroke', 'var(--brand)');
          ln.setAttribute('stroke-width', '5');
          ln.setAttribute('stroke-linecap', 'round');
          svg.appendChild(ln);
        }
      }, k * STEP));
    });
  }

  function showUnlock(kind, value, ticketId) {
    var wrap = document.createElement('div');
    wrap.className = 'unlock-wrap';

    var body = '';
    if (kind === 'PATTERN') {
      var dotsHtml = '';
      for (var n = 1; n <= 9; n++) {
        var p = dotXY(n);
        dotsHtml += '<div class="pat-play-dot" data-play="' + n +
          '" style="left:' + (p.x / 3) + '%;top:' + (p.y / 3) + '%"></div>';
      }
      body =
        '<div class="pat-play" id="patstage">' +
          '<svg viewBox="0 0 300 300" id="patsvg"></svg>' + dotsHtml +
        '</div>' +
        '<p class="pat-play-seq">' + (value || '—') + '</p>' +
        '<button class="btn-mini" type="button" data-replay>إعادة الرسم</button>';
    } else if (kind === 'PASSWORD') {
      body = '<div class="unlock-pass">' + (value || '—') + '</div>';
    } else {
      body = '<p class="field-hint">لا توجد بيانات فتح محفوظة.</p>';
    }

    // ⚠ التعديل جوّه نفس النافذة عن قصد: الموظّف اللي شاف الرقم
    // غلط بيصلّحه في نفس اللحظة، مش بيقفل ويدوّر على شاشة تانية.
    var edit =
      '<details class="panel" style="margin-top:14px;text-align:right">' +
        '<summary>تعديل</summary>' +
        '<div class="panel-body">' +
          '<label class="field-label">النوع</label>' +
          '<select class="field-input" id="uk-kind">' +
            '<option value="NONE"' + (kind === 'NONE' ? ' selected' : '') +
              '>مفتوح / لا بيانات</option>' +
            '<option value="PASSWORD"' + (kind === 'PASSWORD' ? ' selected' : '') +
              '>كلمة مرور</option>' +
            '<option value="PATTERN"' + (kind === 'PATTERN' ? ' selected' : '') +
              '>نمط</option>' +
          '</select>' +
          '<label class="field-label" for="uk-val">القيمة</label>' +
          '<input class="field-input" id="uk-val" type="text" dir="ltr" maxlength="200" ' +
            'value="' + (value || '') + '" placeholder="للنمط: 1-2-3-6-9">' +
          '<p class="field-hint">' +
            'النمط يُكتب أرقامًا بالترتيب مفصولة بشرطة، حسب مواضع النقاط أعلاه.' +
          '</p>' +
          '<button class="btn-mini" type="button" data-uk-save>حفظ</button>' +
        '</div>' +
      '</details>';

    wrap.innerHTML =
      '<div class="unlock-panel">' +
        '<div class="unlock-title">' +
          (kind === 'PATTERN' ? 'نمط فتح الجهاز'
            : kind === 'PASSWORD' ? 'كلمة مرور الجهاز' : 'بيانات فتح الجهاز') +
        '</div>' + body + edit +
        '<button class="btn-mini" type="button" data-close style="margin-top:14px">إغلاق</button>' +
      '</div>';

    document.body.appendChild(wrap);

    var stage = wrap.querySelector('#patstage');
    var svg   = wrap.querySelector('#patsvg');

    function play() { if (stage && svg) playPattern(value, stage, svg); }
    play();

    var again = wrap.querySelector('[data-replay]');
    if (again) again.addEventListener('click', play);

    function close() {
      clearPatternTimers();
      if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
    }
    wrap.querySelector('[data-close]').addEventListener('click', close);

    wrap.querySelector('[data-uk-save]').addEventListener('click', async function () {
      var k = wrap.querySelector('#uk-kind').value;
      var v = wrap.querySelector('#uk-val').value;

      var ok = await send('/api/maintenance/tickets/' + encodeURIComponent(ticketId) + '/unlock',
        { unlockKind: k, unlockValue: v }, this, '…');

      if (ok) {
        close();
        say('تم تحديث بيانات الفتح.', true);
        load();
      }
    });
  }

  // ══════════ صفحة تفاصيل الجهاز ══════════
  //
  // ⚠ صفحة كاملة مش لوحة صغيرة تحت الصف.
  //
  // كل حاجة عن الجهاز في مكان واحد: بيانات العميل، وصف الجهاز
  // وحالته وقت الاستلام، الشكوى، بيانات الفتح، والحالة والتكلفة.
  // الموظّف بيفتحها وهو ماسك الجهاز، وبيحتاج يقرا الكل مرة واحدة.

  var TICKETS = {};

  function detailLine(label, value) {
    if (!value && value !== 0) return '';
    return '<div class="mv-row"><span class="mv-sub">' + label +
      '</span><span>' + value + '</span></div>';
  }

  function showTicket(id) {
    var t = TICKETS[id];
    if (!t) return;

    var wrap = document.createElement('div');
    wrap.className = 'unlock-wrap';

    var canEdit = CAN_MANAGE && t.status !== 'CANCELLED';

    var head =
      '<div class="unlock-title">' + t.deviceName +
        (t.visitNumber > 1 ? ' — زيارة ' + t.visitNumber : '') + '</div>';

    var info =
      '<div style="text-align:right">' +
        detailLine('العميل', t.customerName) +
        detailLine('الهاتف', t.customerPhone) +
        detailLine('السريال', t.serialNumber) +
        detailLine('اللون', t.deviceColor) +
        detailLine('حالته عند الاستلام', t.conditionNote) +
        detailLine('الشكوى', t.complaint) +
        detailLine('محل الصيانة', t.shopName || 'داخليًا') +
        detailLine('استُلم', t.receivedDate) +
        detailLine('موعد التسليم', t.promisedDate) +
        detailLine('سُلِّم', t.deliveredDate) +
        detailLine('الحالة', STATUS[t.status]) +
        detailLine('التكلفة', money(t.costPiastres) + ' ج.م') +
        detailLine('ملاحظة العمل', t.workNote) +
        detailLine('استلمه', t.createdByName) +
        detailLine('مفتوح من', t.daysOpen + ' يوم') +
      '</div>';

    var buttons =
      '<div class="prod-edit-actions" style="margin-top:14px">' +
        '<button class="btn-mini" type="button" data-unlock="' + t.id + '">' +
          (t.hasUnlock ? 'بيانات الفتح' : 'إضافة بيانات فتح') + '</button>' +
        '<button class="btn-mini" type="button" data-tk-again="' + t.id + '">رجع تاني</button>' +
        '<button class="btn-mini" type="button" data-close>إغلاق</button>' +
      '</div>';

    // ⚠ التحديث للمدير بس. الموظّف بيشوف كل حاجة ومش بيغيّر
    // الحالة ولا التكلفة.
    var editBlock = canEdit
      ? '<details class="panel" style="margin-top:14px;text-align:right">' +
          '<summary>تحديث الحالة والتكلفة</summary>' +
          '<div class="panel-body">' +
            '<label class="field-label">الحالة</label>' +
            '<select class="field-input" id="tks">' +
              '<option value="CHECKING">قيد الفحص</option>' +
              '<option value="WAITING_PART">بانتظار قطعة غيار</option>' +
              '<option value="READY">جاهز للتسليم</option>' +
              '<option value="DELIVERED">تم التسليم</option>' +
              '<option value="CANCELLED">ملغاة</option>' +
            '</select>' +
            '<label class="field-label">التكلفة</label>' +
            '<input class="field-input" id="tkc" type="text" inputmode="decimal" dir="ltr" ' +
              'value="' + money(t.costPiastres) + '">' +
            '<label class="field-label">ملاحظة العمل</label>' +
            '<input class="field-input" id="tkn" type="text" maxlength="1000" value="' +
              (t.workNote || '') + '">' +
            '<button class="btn-mini" type="button" data-tk-save="' + t.id + '">حفظ</button>' +
          '</div>' +
        '</details>'
      : '';

    wrap.innerHTML =
      '<div class="unlock-panel" style="max-height:88vh;overflow:auto">' +
        head + info + editBlock + buttons +
      '</div>';

    document.body.appendChild(wrap);

    var sel = wrap.querySelector('#tks');
    if (sel) sel.value = t.status;

    function close() { if (wrap.parentNode) wrap.parentNode.removeChild(wrap); }
    wrap.querySelector('[data-close]').addEventListener('click', close);
    wrap.setAttribute('data-ticket-modal', t.id);
  }

  // ══════════ التحميل ══════════
  var shops = [];

  function val(id) { var el = document.getElementById(id); return el ? el.value : ''; }

  async function load() {
    // ⚠ الفلاتر بتتبعت للخادم مش بتتفلتر في المتصفح: التذاكر
    // ممكن تكون مئات، والبحث في الشكوى محتاج قاعدة البيانات.
    var qs = 'scope=' + encodeURIComponent(val('tk-scope') || 'OPEN') +
      '&q=' + encodeURIComponent(val('tk-search')) +
      '&shop=' + encodeURIComponent(val('tk-shop-filter')) +
      '&from=' + encodeURIComponent(val('tk-from')) +
      '&to=' + encodeURIComponent(val('tk-to'));

    try {
      var res = await fetch('/api/maintenance?' + qs, { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        say((data && data.error && data.error.message) || 'تعذّر التحميل.', false);
        return;
      }

      shops = data.shops || [];
      fillShops();
      renderTickets(data.tickets || []);
      renderRecords(data.records || []);
      renderShops();
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    }
  }

  function fillShops() {
    // فلتر البحث — بيحتفظ باختيارك بعد التحميل
    var filt = document.getElementById('tk-shop-filter');
    if (filt) {
      var keep = filt.value;
      filt.textContent = '';
      var all = document.createElement('option');
      all.value = ''; all.textContent = '— كل المحلات —';
      filt.appendChild(all);
      for (var k = 0; k < shops.length; k++) {
        var of = document.createElement('option');
        of.value = shops[k].id; of.textContent = shops[k].name;
        filt.appendChild(of);
      }
      filt.value = keep;
    }

    var sel = document.getElementById('tk-shop');
    if (!sel) return;
    sel.textContent = '';
    var none = document.createElement('option');
    none.value = ''; none.textContent = '— داخليًا —';
    sel.appendChild(none);
    for (var i = 0; i < shops.length; i++) {
      var o = document.createElement('option');
      o.value = shops[i].id; o.textContent = shops[i].name;
      sel.appendChild(o);
    }
  }

  function row(main, sub) {
    var r = document.createElement('div');
    r.className = 'prod-row';
    var m = document.createElement('div');
    m.className = 'prod-row-main';
    var a = document.createElement('span');
    a.className = 'prod-row-name'; a.textContent = main;
    var b = document.createElement('span');
    b.className = 'prod-row-sub'; b.textContent = sub;
    m.appendChild(a); m.appendChild(b); r.appendChild(m);
    return r;
  }

  function renderTickets(list) {
    var host = document.getElementById('tk-rows');
    var cnt = document.getElementById('tk-count');
    if (cnt) cnt.textContent = '(' + list.length + ')';
    host.textContent = '';

    if (list.length === 0) {
      var e = document.createElement('p');
      e.className = 'field-hint';
      e.textContent = 'لا توجد أجهزة عملاء مطابقة.';
      host.appendChild(e);
      return;
    }

    for (var i = 0; i < list.length; i++) {
      var t = list[i];
      var visit = t.visitNumber > 1 ? ' · زيارة ' + t.visitNumber : '';
      var r = row(
        t.deviceName + ' — ' + t.customerName + visit,
        STATUS[t.status] + ' · ' + t.receivedDate +
          (t.shopName ? ' · ' + t.shopName : ' · داخليًا') +
          (t.customerPhone ? ' · ' + t.customerPhone : '') +
          (t.costPiastres > 0 ? ' · ' + money(t.costPiastres) : '') +
          ' · ' + t.daysOpen + ' يوم'
      );

      // ⚠ الصف كله بيفتح التفاصيل. الأزرار بقت جوّه صفحة
      // التفاصيل مش على الصف — الصف بقى ضيّق على الموبايل
      // بأربع أزرار، وأول حاجة الموظّف بيعملها إنه يبصّ.
      r.style.cursor = 'pointer';
      r.setAttribute('data-open-ticket', t.id);
      TICKETS[t.id] = t;

      var acts = document.createElement('div');
      acts.className = 'prod-edit-actions';

      var openBtn = document.createElement('button');
      openBtn.className = 'btn-mini'; openBtn.type = 'button';
      openBtn.textContent = 'التفاصيل';
      openBtn.setAttribute('data-open-ticket', t.id);
      acts.appendChild(openBtn);

      r.appendChild(acts);
      host.appendChild(r);
    }
  }

  function renderRecords(list) {
    var host = document.getElementById('mr-rows');
    var cnt = document.getElementById('mr-count');
    if (cnt) cnt.textContent = '(' + list.length + ')';
    host.textContent = '';

    if (list.length === 0) {
      var e = document.createElement('p');
      e.className = 'field-hint';
      e.textContent = 'لا توجد أجهزة للمحل في الورش.';
      host.appendChild(e);
      return;
    }

    for (var i = 0; i < list.length; i++) {
      var m = list[i];
      var r = row(
        m.productName + (m.serialNumber ? ' · ' + m.serialNumber : ''),
        m.faultNote + ' · ' + (m.shopName || 'داخليًا') + ' · ' + m.sentDate +
          ' · ' + m.daysOut + ' يوم' +
          (m.costPiastres > 0 ? ' · ' + money(m.costPiastres) : '')
      );

      if (CAN_MANAGE && m.status === 'SENT') {
        var acts = document.createElement('div');
        acts.className = 'prod-edit-actions';
        var ok = document.createElement('button');
        ok.className = 'btn-mini'; ok.type = 'button';
        ok.textContent = 'رجع'; ok.setAttribute('data-mr', m.id);
        ok.setAttribute('data-mr-status', 'RETURNED');
        acts.appendChild(ok);

        var no = document.createElement('button');
        no.className = 'btn-mini'; no.type = 'button';
        no.setAttribute('data-danger', 'true');
        no.textContent = 'ما اتصلحش'; no.setAttribute('data-mr', m.id);
        no.setAttribute('data-mr-status', 'CANCELLED');
        acts.appendChild(no);
        r.appendChild(acts);
      }
      host.appendChild(r);
    }
  }

  function renderShops() {
    var host = document.getElementById('rs-rows');
    if (!host) return;
    var cnt = document.getElementById('rs-count');
    if (cnt) cnt.textContent = '(' + shops.length + ')';
    host.textContent = '';

    for (var i = 0; i < shops.length; i++) {
      var sp = shops[i];
      var r = row(sp.name, sp.phone || '—');
      var acts = document.createElement('div');
      acts.className = 'prod-edit-actions';
      var h = document.createElement('button');
      h.className = 'btn-mini'; h.type = 'button';
      h.textContent = 'السجل'; h.setAttribute('data-rs-hist', sp.id);
      acts.appendChild(h);
      r.appendChild(acts);
      host.appendChild(r);

      var panel = document.createElement('div');
      panel.className = 'exit-edit';
      panel.id = 'rsh-' + sp.id;
      panel.hidden = true;
      host.appendChild(panel);
    }
  }

  // ══════════ التفاعلات ══════════
  document.addEventListener('click', async function (e) {
    var el = e.target.closest ? e.target : null;
    if (!el || !el.closest) return;

    // فتح التفاصيل — من الصف أو من زرار «التفاصيل»
    var openT = el.closest('[data-open-ticket]');
    if (openT && !el.closest('[data-unlock]') && !el.closest('[data-tk-again]')) {
      showTicket(openT.getAttribute('data-open-ticket'));
      return;
    }

    var unlockBtn = el.closest('[data-unlock]');
    if (unlockBtn) {
      var tid = unlockBtn.getAttribute('data-unlock');
      var res = await fetch('/api/maintenance/tickets/' + encodeURIComponent(tid) + '/unlock',
        { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) {
        say((d && d.error && d.error.message) || 'تعذّر عرض البيانات.', false);
        return;
      }
      showUnlock(d.kind, d.value, tid);
      return;
    }

    var saveBtn = el.closest('[data-tk-save]');
    if (saveBtn) {
      var id = saveBtn.getAttribute('data-tk-save');
      var modal = saveBtn.closest('[data-ticket-modal]');
      if (!modal) return;

      var st = (modal.querySelector('#tks') || {}).value;
      var cost = (modal.querySelector('#tkc') || {}).value || '';

      // ⚠ التسليم بصفر ممكن يكون صح (إصلاح بضمان)، لكن السكوت
      // التام غلط: الجهاز بيتسلّم والفلوس ما اتكتبتش، ومحدش
      // بيلاحظ غير آخر الشهر.
      var zero = !cost.trim() || parseFloat(cost) === 0;
      if (st === 'DELIVERED' && zero) {
        if (!confirm('التكلفة صفر — الجهاز هيتسلّم من غير فلوس. متأكد؟')) return;
      }

      var ok2 = await send('/api/maintenance/tickets/' + encodeURIComponent(id), {
        status: st,
        cost: cost,
        workNote: (modal.querySelector('#tkn') || {}).value
      }, saveBtn, '…');

      if (ok2) {
        if (modal.parentNode) modal.parentNode.removeChild(modal);
        say('تم الحفظ.', true);
        load();
      }
      return;
    }

    // الزيارة التانية: بنملا الفورم ببيانات الجهاز ونربط التذكرة
    var againBtn = el.closest('[data-tk-again]');
    if (againBtn) {
      var old = TICKETS[againBtn.getAttribute('data-tk-again')];
      if (!old) return;

      // بيانات الجهاز بتتنقل، والشكوى بتفضل فاضية — دي زيارة
      // جديدة بمشكلة جديدة مش نسخة من القديمة
      document.getElementById('tk-cname').value = old.customerName || '';
      document.getElementById('tk-cphone').value = old.customerPhone || '';
      document.getElementById('tk-device').value = old.deviceName || '';
      document.getElementById('tk-serial').value = old.serialNumber || '';
      document.getElementById('tk-color').value = old.deviceColor || '';
      document.getElementById('tk-complaint').value = '';
      document.getElementById('tk-add').setAttribute('data-parent', old.id);

      var modalA = againBtn.closest('[data-ticket-modal]');
      if (modalA && modalA.parentNode) modalA.parentNode.removeChild(modalA);

      say('اكتب الشكوى الجديدة — الجهاز مربوط بزيارته السابقة.', true);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    var mrBtn = el.closest('[data-mr]');
    if (mrBtn) {
      var note = prompt('ملاحظة النتيجة (اختياري):') || '';
      var ok3 = await send('/api/maintenance/record/' +
        encodeURIComponent(mrBtn.getAttribute('data-mr')) + '/return',
        { status: mrBtn.getAttribute('data-mr-status'), note: note }, mrBtn, '…');
      if (ok3) { say('تم — الكمية رجعت للمخزون.', true); load(); }
      return;
    }

    var histBtn = el.closest('[data-rs-hist]');
    if (histBtn) {
      var sid = histBtn.getAttribute('data-rs-hist');
      var panel2 = document.getElementById('rsh-' + sid);
      if (!panel2) return;
      if (!panel2.hidden) { panel2.hidden = true; return; }

      var hres = await fetch('/api/maintenance/shops/' + encodeURIComponent(sid) + '/history',
        { credentials: 'same-origin' });
      var hd = await hres.json().catch(function () { return null; });
      if (!hres.ok || !hd || !hd.ok) { say('تعذّر جلب السجل.', false); return; }

      panel2.textContent = '';
      var rows2 = hd.history || [];
      if (rows2.length === 0) {
        var em = document.createElement('p');
        em.className = 'field-hint'; em.textContent = 'لا سجل بعد.';
        panel2.appendChild(em);
      } else {
        for (var j = 0; j < rows2.length; j++) {
          var it = rows2[j];
          var line = document.createElement('p');
          line.className = 'field-hint';
          line.textContent = (it.kind === 'OWN' ? '🏪 ' : '👤 ') + it.title +
            ' · ' + it.detail + ' · ' + it.onDate +
            (it.costPiastres > 0 ? ' · ' + money(it.costPiastres) : '');
          panel2.appendChild(line);
        }
      }
      panel2.hidden = false;
      return;
    }
  });

  var addBtn = document.getElementById('tk-add');
  if (addBtn) {
    addBtn.addEventListener('click', async function () {
      var kind = (document.getElementById('tk-unlock-kind') || {}).value || 'NONE';
      var value = null;
      if (kind === 'PASSWORD') value = document.getElementById('tk-pass').value;
      if (kind === 'PATTERN') value = pattern.join('-');

      var result = await send('/api/maintenance/tickets', {
        customerName: document.getElementById('tk-cname').value,
        customerPhone: document.getElementById('tk-cphone').value,
        deviceName: document.getElementById('tk-device').value,
        serialNumber: document.getElementById('tk-serial').value,
        deviceColor: document.getElementById('tk-color').value,
        conditionNote: document.getElementById('tk-cond').value,
        complaint: document.getElementById('tk-complaint').value,
        unlockKind: kind,
        unlockValue: value,
        repairShopId: document.getElementById('tk-shop').value,
        cost: document.getElementById('tk-cost').value,
        promisedDate: document.getElementById('tk-promised').value,
        parentTicketId: addBtn.getAttribute('data-parent'),
        branchId: (document.getElementById('tk-branch') || {}).value || null
      }, addBtn, 'جارٍ الاستلام…');

      if (result) {
        say('تم استلام الجهاز.', true);
        setTimeout(function () { window.location.reload(); }, 900);
      }
    });
  }

  var rsAdd = document.getElementById('rs-add');
  if (rsAdd) {
    rsAdd.addEventListener('click', async function () {
      var r = await send('/api/maintenance/shops', {
        name: document.getElementById('rs-name').value,
        phone: document.getElementById('rs-phone').value
      }, rsAdd, 'جارٍ الإضافة…');
      if (r) { say('تمت الإضافة.', true); load(); }
    });
  }

  var searchEl = document.getElementById('tk-search');
  if (searchEl) {
    var timer = null;
    searchEl.addEventListener('input', function () {
      clearTimeout(timer);
      // ⚠ البحث على الخادم (التذاكر ممكن تكون مئات)، فبنستنى
      // شوية بعد آخر حرف بدل نداء مع كل ضغطة
      timer = setTimeout(load, 350);
    });
  }
  ['tk-scope', 'tk-shop-filter', 'tk-from', 'tk-to'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', load);
  });

  var clearBtn = document.getElementById('tk-clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      ['tk-search', 'tk-shop-filter', 'tk-from', 'tk-to'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.value = '';
      });
      var sc = document.getElementById('tk-scope');
      if (sc) sc.value = 'OPEN';
      load();
    });
  }

  load();
})();
`;
}


// ═══════════════════════════════════════════════════════════
//  سجل اليوميات
// ═══════════════════════════════════════════════════════════

export interface ClosingsPageData {
  fullName: string;
  username: string;
  branchLabel: string | null;
  tenantName: string;
  roleKey: string;
  canSell: boolean;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  /** profit.view_real — بيقرّر ظهور سطر التكلفة والربح في التفاصيل */
  canSeeCost: boolean;
  /** صاحب المحل مالوش فرع، فلازم يختار من قائمة */
  isOwner: boolean;
  branches: Array<{ id: string; name: string }>;
  idleTimeoutSeconds: number;
  idleWarningSeconds: number;
  idleAction: 'LOGOUT' | 'LOCK';
}

/**
 * سجل اليوميات.
 *
 * ══ ليه الصفحة دي مش زي التقرير؟ ══
 * التقرير بيجاوب "كسبت كام في الفترة دي". اليومية بتجاوب
 * "إيه اللي حصل في الوردية دي" — وده سؤال تشغيلي مش محاسبي.
 *
 * عشان كده الترتيب هنا زمني بحت: آخر يومية فوق، وكل واحدة
 * بتفتح على تفاصيلها الكاملة.
 *
 * ══ والزرار مخفي لحد ما نسأل ══
 * ⚠ مين يقدر يقفل مش صلاحية على المستخدم — ده إعداد على الفرع.
 * فالصفحة بتفتح للكل، وبتسأل الخادم أول ما تحمّل: أقدر أقفل؟
 * ولو لأ، بتقول ليه.
 *
 * ══ واللقطة مش مرجع ══
 * التفاصيل اللي بتظهر جاية من **نسخة محفوظة** وقت التقفيل، مش
 * من الفواتير الحيّة. يعني لو عدّلت فاتورة بكرة، اليومية
 * المقفولة ما بتتغيّرش — وده الغرض كله.
 */
export function closingsPage(data: ClosingsPageData): Html {
  return shell({
    title: 'سجل اليوميات',
    tenantName: data.tenantName,
    script: closingsScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.isOwner,
      data.canSeeCost,
    ),
    body: html`${appBar({
      fullName: data.fullName,
      username: data.username,
      roleKey: data.roleKey,
      branchLabel: data.branchLabel,
      tenantName: data.tenantName,
    })}

<main class="shell">
  <div class="alert-box" id="clmsg" role="alert" hidden><span id="clmsg-text"></span></div>

  ${data.isOwner
    ? html`<div class="field">
        <label class="field-label" for="cl-branch">الفرع</label>
        <select class="field-input" id="cl-branch">
          ${data.branches.map((b) => html`<option value="${b.id}">${b.name}</option>`)}
        </select>
        ${data.branches.length === 0
          ? html`<p class="field-hint">لا توجد فروع بعد.</p>`
          : ''}
      </div>`
    : ''}

  <details class="panel" open>
    <summary>الوردية المفتوحة</summary>
    <div class="panel-body">
      <div id="cl-preview">
        <p class="field-hint">جارٍ الحساب…</p>
      </div>
    </div>
  </details>

  ${data.isOwner
    ? html`<details class="panel">
        <summary>من يقفل اليومية</summary>
        <div class="panel-body">
          <p class="muted">
            الزر مخفي عن الجميع افتراضيًا. اختر من يظهر له في هذا الفرع.
            أنت تستطيع التقفيل دائمًا.
          </p>

          <label class="field-label" style="display:flex;gap:8px;align-items:center">
            <input type="checkbox" id="cl-role-mgr"> مدير الفرع
          </label>
          <label class="field-label" style="display:flex;gap:8px;align-items:center">
            <input type="checkbox" id="cl-role-staff"> مندوب المبيعات
          </label>

          <button class="btn-mini" type="button" id="cl-roles-save">حفظ الإعداد</button>
          <p class="field-hint">
            لا يمكن تقفيل يومية جديدة قبل مرور ثلاث ساعات على السابقة —
            وهذا يسري عليك أيضًا.
          </p>
        </div>
      </details>`
    : ''}

  <details class="panel" open>
    <summary>اليوميات المقفولة</summary>
    <div class="panel-body">
      <div id="cl-list">
        <p class="field-hint">جارٍ التحميل…</p>
      </div>
    </div>
  </details>

  <div id="cl-detail" hidden></div>
</main>

${tabBar('app', {
  showPos: data.canSell,
  showProducts: data.canViewProducts,
  showTreasury: data.canUseTreasury,
})}

<div id="idle-root"></div>
<div id="lock-root"></div>`,
  });
}

function closingsScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  isOwner: boolean,
  canSeeCost: boolean,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
${TIME_JS}

(function () {
  var IS_OWNER = ${String(isOwner)};
  var SEE_COST = ${String(canSeeCost)};

  var box = document.getElementById('clmsg');
  var boxText = document.getElementById('clmsg-text');
  var previewEl = document.getElementById('cl-preview');
  var listEl = document.getElementById('cl-list');
  var detailEl = document.getElementById('cl-detail');
  var branchEl = document.getElementById('cl-branch');

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    boxText.textContent = message;
  }

  function money(piastres) {
    var n = Number(piastres || 0);
    var neg = n < 0;
    var abs = Math.abs(Math.trunc(n));
    var pounds = Math.floor(abs / 100);
    var rest = abs % 100;
    return (neg ? '-' : '') + pounds.toLocaleString('en-US') + '.' +
      String(rest).padStart(2, '0');
  }

  function when(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString('ar-EG', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  function branchId() {
    return branchEl ? branchEl.value : '';
  }

  function row(host, label, value, tone) {
    var r = document.createElement('div');
    r.className = 'mv-row';
    var t = document.createElement('span');
    t.className = 'mv-sub';
    t.textContent = label;
    r.appendChild(t);
    var v = document.createElement('span');
    v.className = 'mv-amount';
    if (tone) v.setAttribute('data-dir', tone);
    v.textContent = value;
    r.appendChild(v);
    host.appendChild(r);
    return r;
  }

  // ══════════ الوردية المفتوحة ══════════
  //
  // ⚠ الزرار ما بيظهرش قبل الرد. لو عرضناه ومنعناه بعدين،
  // الموظّف هيضغط ويستنى ويترفض — والزبون واقف قدّامه.
  async function loadPreview() {
    previewEl.textContent = '';
    var p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = 'جارٍ الحساب…';
    previewEl.appendChild(p);

    var url = '/api/closings/preview';
    if (IS_OWNER) {
      if (!branchId()) { p.textContent = 'اختر فرعًا أولًا.'; return; }
      url += '?branchId=' + encodeURIComponent(branchId());
    }

    try {
      var res = await fetch(url, { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) {
        p.textContent = (d && d.error && d.error.message) || 'تعذّر قراءة الوردية.';
        return;
      }

      previewEl.textContent = '';

      var since = document.createElement('p');
      since.className = 'field-hint';
      since.textContent = 'من ' + when(d.periodFrom) +
        ' — ' + Math.floor(d.minutesOpen / 60) + ' ساعة و' +
        (d.minutesOpen % 60) + ' دقيقة';
      previewEl.appendChild(since);

      row(previewEl, 'فواتير', String(d.salesCount));
      row(previewEl, 'مبيعات', money(d.salesPiastres), 'IN');
      row(previewEl, 'مرتجعات', String(d.returnsCount));
      row(previewEl, 'حركات خزينة', String(d.movementsCount));

      if (d.canClose) {
        var btn = document.createElement('button');
        btn.className = 'btn-primary';
        btn.type = 'button';
        btn.id = 'cl-close';
        btn.textContent = 'تقفيل اليومية';
        previewEl.appendChild(btn);
      } else {
        var why = document.createElement('p');
        why.className = 'field-hint';
        why.textContent = d.reason || 'التقفيل غير متاح الآن.';
        previewEl.appendChild(why);
      }

      // خانات الأدوار بتتملي من نفس الرد — مصدر واحد
      if (IS_OWNER) {
        var mgr = document.getElementById('cl-role-mgr');
        var stf = document.getElementById('cl-role-staff');
        var roles = d.closingRoles || [];
        if (mgr) mgr.checked = roles.indexOf('BRANCH_MANAGER') >= 0;
        if (stf) stf.checked = roles.indexOf('STAFF') >= 0;
      }
    } catch (err) {
      p.textContent = 'تعذّر الاتصال بالخادم.';
    }
  }

  // ══════════ التقفيل ══════════
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('#cl-close') : null;
    if (!btn) return;

    if (!confirm('تقفيل اليومية؟ تُحفظ نسخة كاملة من الحركة، والعمل يستمر عاديًا بعدها.')) return;

    btn.disabled = true;
    btn.textContent = 'جارٍ التقفيل…';

    try {
      var res = await fetch('/api/closings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ branchId: IS_OWNER ? branchId() : null, note: null })
      });
      var d = await res.json().catch(function () { return null; });

      if (res.ok && d && d.ok) {
        say('تم تقفيل اليومية — مبيعات ' + money(d.salesPiastres) + ' ج.م', true);
        await loadPreview();
        await loadList();
        return;
      }
      say((d && d.error && d.error.message) || 'تعذّر التقفيل.', false);
    } catch (err) {
      // ⚠ مش بنقول "ما اتقفلتش" — إحنا مش عارفين. الطلب ممكن
      // يكون وصل واتنفّذ والرد هو اللي ضاع.
      say('انقطع الاتصال. حدّث الصفحة وتأكّد قبل إعادة المحاولة.', false);
    } finally {
      btn.disabled = false;
      btn.textContent = 'تقفيل اليومية';
    }
  });

  // ══════════ ضبط من يقفل ══════════
  var saveRoles = document.getElementById('cl-roles-save');
  if (saveRoles) {
    saveRoles.addEventListener('click', async function () {
      if (!branchId()) { say('اختر فرعًا أولًا.', false); return; }

      var roles = [];
      var mgr = document.getElementById('cl-role-mgr');
      var stf = document.getElementById('cl-role-staff');
      if (mgr && mgr.checked) roles.push('BRANCH_MANAGER');
      if (stf && stf.checked) roles.push('STAFF');

      saveRoles.disabled = true;
      try {
        var res = await fetch('/api/closings/roles', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ branchId: branchId(), roles: roles })
        });
        var d = await res.json().catch(function () { return null; });

        if (res.ok && d && d.ok) {
          say(roles.length === 0
            ? 'تم الحفظ — الزر مخفي عن الجميع، وأنت تقفل.'
            : 'تم الحفظ.', true);
          return;
        }
        say((d && d.error && d.error.message) || 'تعذّر الحفظ.', false);
      } catch (err) {
        say('تعذّر الاتصال بالخادم.', false);
      } finally {
        saveRoles.disabled = false;
      }
    });
  }

  // ══════════ السجل ══════════
  async function loadList() {
    listEl.textContent = '';
    var p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = 'جارٍ التحميل…';
    listEl.appendChild(p);

    try {
      var res = await fetch('/api/closings', { credentials: 'same-origin' });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) {
        p.textContent = (d && d.error && d.error.message) || 'تعذّر التحميل.';
        return;
      }

      var rows = d.closings || [];
      if (rows.length === 0) {
        p.textContent = 'لم تُقفل أي يومية بعد.';
        return;
      }

      listEl.textContent = '';
      for (var i = 0; i < rows.length; i++) {
        var it = rows[i];
        var card = document.createElement('div');
        card.className = 'mv-row';

        var head = document.createElement('div');
        var t = document.createElement('span');
        t.className = 'mv-title';
        t.textContent = when(it.closedAt) + ' · ' + it.branchName;
        head.appendChild(t);

        var sub = document.createElement('span');
        sub.className = 'mv-sub';
        sub.textContent = it.salesCount + ' فاتورة · ' +
          money(it.salesPiastres) + ' ج.م · قفلها ' + (it.closedByName || '—');
        head.appendChild(sub);
        card.appendChild(head);

        var open = document.createElement('button');
        open.className = 'btn-mini';
        open.type = 'button';
        open.setAttribute('data-closing', it.id);
        open.textContent = 'التفاصيل';
        card.appendChild(open);

        listEl.appendChild(card);
      }
    } catch (err) {
      p.textContent = 'تعذّر الاتصال بالخادم.';
    }
  }

  // ══════════ التفاصيل ══════════
  //
  // ⚠ الأرقام دي من **اللقطة** مش من الجداول الحيّة. لو فاتورة
  // اتعدّلت بعد التقفيل، اللي هنا ما بيتغيّرش.
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-closing]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-closing');
    var original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
      var res = await fetch('/api/closings/' + encodeURIComponent(id), {
        credentials: 'same-origin'
      });
      var d = await res.json().catch(function () { return null; });
      if (!res.ok || !d || !d.ok) {
        say((d && d.error && d.error.message) || 'تعذّر قراءة اليومية.', false);
        return;
      }

      renderDetail(d.closing);
      detailEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  function panel(title) {
    var d = document.createElement('details');
    d.className = 'panel';
    d.open = true;
    var s = document.createElement('summary');
    s.textContent = title;
    d.appendChild(s);
    var b = document.createElement('div');
    b.className = 'panel-body';
    d.appendChild(b);
    detailEl.appendChild(d);
    return b;
  }

  function renderDetail(cl) {
    detailEl.textContent = '';
    detailEl.hidden = false;

    var head = panel('يومية ' + when(cl.closedAt) + ' · ' + cl.branchName);
    var span = document.createElement('p');
    span.className = 'field-hint';
    span.textContent = 'الفترة: من ' + when(cl.periodFrom) + ' إلى ' + when(cl.periodTo);
    head.appendChild(span);

    row(head, 'مبيعات', money(cl.salesPiastres), 'IN');
    row(head, 'مرتجعات', money(cl.returnsPiastres), 'OUT');
    row(head, 'مصروفات', money(cl.expensesPiastres), 'OUT');
    row(head, 'سُلف', money(cl.advancesPiastres), 'OUT');
    row(head, 'شراء بضاعة', money(cl.purchasesPiastres), 'OUT');
    row(head, 'دخل الدرج', money(cl.cashInPiastres), 'IN');
    row(head, 'خرج من الدرج', money(cl.cashOutPiastres), 'OUT');

    // ⚠ الحقل ده مش موجود في الرد أصلاً لمن مالوش الصلاحية —
    // مش مخفي في الشاشة. الفحص هنا للعرض بس.
    if (SEE_COST && cl.cost) {
      row(head, 'تكلفة المباع', money(cl.cost.cogsPiastres), 'OUT');
      row(head, 'مجمل الربح', money(cl.cost.grossProfitPiastres), 'IN');
    }

    // ── المبيعات ──
    var salesBody = panel('المبيعات (' + (cl.sales || []).length + ')');
    if ((cl.sales || []).length === 0) {
      var e1 = document.createElement('p');
      e1.className = 'field-hint';
      e1.textContent = 'لا مبيعات في هذه الفترة.';
      salesBody.appendChild(e1);
    }
    for (var i = 0; i < (cl.sales || []).length; i++) {
      var sale = cl.sales[i];
      var r = document.createElement('div');
      r.className = 'mv-row';

      var st = document.createElement('span');
      st.className = 'mv-title';
      st.textContent = when(sale.at) + ' · ' + money(sale.totalPiastres) + ' ج.م';
      r.appendChild(st);

      var names = [];
      for (var j = 0; j < (sale.items || []).length; j++) {
        var it = sale.items[j];
        names.push(it.name + ' ×' + it.quantity);
      }

      var ss = document.createElement('span');
      ss.className = 'mv-sub';
      ss.textContent = names.join(' · ') +
        (sale.staff ? ' — ' + sale.staff : '') +
        (sale.customer ? ' — ' + sale.customer : '');
      r.appendChild(ss);

      salesBody.appendChild(r);
    }

    // ── الخزينة ──
    var mvBody = panel('حركات الخزينة (' + (cl.movements || []).length + ')');
    if ((cl.movements || []).length === 0) {
      var e2 = document.createElement('p');
      e2.className = 'field-hint';
      e2.textContent = 'لا حركات في هذه الفترة.';
      mvBody.appendChild(e2);
    }
    for (var k = 0; k < (cl.movements || []).length; k++) {
      var mv = cl.movements[k];
      var mr = document.createElement('div');
      mr.className = 'mv-row';

      var mt = document.createElement('span');
      mt.className = 'mv-title';
      mt.textContent = typeLabel(mv.type) + ' · ' + money(mv.amountPiastres) + ' ج.م';
      mr.appendChild(mt);

      var ms = document.createElement('span');
      ms.className = 'mv-sub';
      ms.textContent = when(mv.at) +
        (mv.reason ? ' · ' + mv.reason : '') +
        (mv.person ? ' · ' + mv.person : '') +
        (mv.by ? ' — ' + mv.by : '') +
        (mv.status === 'PENDING' ? ' · معلّقة' : '');
      mr.appendChild(ms);

      mvBody.appendChild(mr);
    }

    // ── المشتريات ──
    var puBody = panel('شراء البضاعة (' + (cl.purchases || []).length + ')');
    if ((cl.purchases || []).length === 0) {
      var e3 = document.createElement('p');
      e3.className = 'field-hint';
      e3.textContent = 'لا مشتريات في هذه الفترة.';
      puBody.appendChild(e3);
    }
    for (var m = 0; m < (cl.purchases || []).length; m++) {
      var pu = cl.purchases[m];
      var pr = document.createElement('div');
      pr.className = 'mv-row';

      var pt = document.createElement('span');
      pt.className = 'mv-title';
      pt.textContent = (pu.item || 'شراء بلا بيان') + ' · ' + money(pu.amountPiastres) + ' ج.م';
      pr.appendChild(pt);

      var ps = document.createElement('span');
      ps.className = 'mv-sub';
      ps.textContent = when(pu.at) +
        (pu.quantity ? ' · ' + pu.quantity + ' قطعة' : '') +
        (pu.supplier ? ' · ' + pu.supplier : '') +
        (pu.by ? ' — ' + pu.by : '');
      pr.appendChild(ps);

      puBody.appendChild(pr);
    }
  }

  function typeLabel(t) {
    if (t === 'EXPENSE') return 'مصروف';
    if (t === 'ADVANCE') return 'سُلفة';
    if (t === 'REFUND') return 'مرتجع';
    if (t === 'DEPOSIT') return 'إيداع';
    if (t === 'WITHDRAWAL') return 'سحب';
    if (t === 'ADJUSTMENT') return 'تسوية';
    if (t === 'TRANSFER_IN') return 'تحويل وارد';
    if (t === 'TRANSFER_OUT') return 'تحويل صادر';
    return t;
  }

  if (branchEl) branchEl.addEventListener('change', loadPreview);

  loadPreview();
  loadList();
})();
`;
}
