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


/**
 * كود الخمول وقفل الشاشة — مشترك بين لوحة التحكم والخزينة.
 *
 * ليه مستخرج؟ لأنه كان هيتكرر في صفحتين. ولو اتكرر، أول تعديل
 * على واحدة وهنسيان التانية بيعمل سلوك مختلف بين شاشتين في نفس
 * النظام — وده أسوأ من كود أطول.
 *
 * العلامات __IDLE__ و __WARN__ و __ACTION__ بتتبدّل وقت التوليد.
 */
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


const FONTS =
  'https://fonts.googleapis.com/css2?family=Reem+Kufi:wght@500;600&family=Readex+Pro:wght@400;500;600;700&family=IBM+Plex+Sans+Arabic:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap';

type Html = HtmlEscapedString | Promise<HtmlEscapedString>;

function shell(opts: { title: string; noIndex?: boolean; body: Html; script: string }): Html {
  return html`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${opts.title}</title>
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

<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<style>${raw(BASE_CSS)}</style>
</head>
<body>
${opts.body}
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
  /** اسم المحل — بيظهر في القائمة عشان الموظّف يتأكد إنه في المكان الصح */
  tenantName?: string | null;
}): Html {
  return html`<header class="app-bar">
  <div class="who">
    ${raw(brandGlyph())}
    <span class="who-name">${opts.fullName}</span>
    <span class="stamp" data-role="${opts.roleKey}">${ROLE_STAMP[opts.roleKey] ?? opts.roleKey}</span>
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
      <button class="menu-item" type="button" data-action="lock">قفل الشاشة</button>
      <button class="menu-item" type="button" data-action="logout" data-danger>تسجيل الخروج</button>
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

  menu.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-action]') : null;
    if (!btn) return;
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
  const canManageProducts = data.permissions.includes('inventory.adjust');
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

  // ── البلاطات: اللي تقدر تعمله، بكلام مفهوم مش أكواد نظام ──
  const tiles: Html[] = [];

  // البيع أول بلاطة عن قصد: دي الحاجة اللي الموظّف بيفتح النظام
  // عشانها. اللي بيتعمل خمسين مرة في اليوم بييجي قبل اللي بيتعمل
  // مرة في الأسبوع.
  if (canSell) {
    tiles.push(html`<a class="tile" data-wide href="/pos">
      <span class="tile-label">شاشة البيع</span>
      <span class="tile-note">اختر المنتجات وأتمم الفاتورة</span>
    </a>`);
  }

  if (canViewProducts) {
    tiles.push(html`<a class="tile" href="/products">
      <span class="tile-label">المنتجات</span>
      <span class="tile-note">${canManageProducts ? 'أسعار وكميات' : 'عرض المخزون'}</span>
    </a>`);
  }

  if (canUseTreasury) {
    tiles.push(html`<a class="tile" href="/treasury">
      <span class="tile-label">الخزينة</span>
      <span class="tile-note">${data.canApproveExpenses ? 'مصروفات وسُلف وأرصدة' : 'تسجيل مصروف أو سُلفة'}</span>
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
  }>;
  movements: TreasuryMovementView[];
  pending: TreasuryMovementView[];
  reasons: Array<{ id: string; name: string; isAdvance: boolean }>;
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
  DEPOSIT: 'إيداع',
  WITHDRAWAL: 'سحب',
  EXPENSE: 'مصروف',
  ADVANCE: 'سُلفة',
  ADJUSTMENT: 'تسوية',
};

const TREASURY_TYPE_LABEL: Record<string, string> = {
  CASH: 'كاش',
  VISA: 'فيزا',
  INSTAPAY: 'إنستاباي',
};

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
  const total = data.balances.reduce((sum, b) => sum + b.balancePiastres, 0);

  const balancesHtml =
    data.balances.length === 0
      ? html`<p class="muted">لا توجد خزائن. يضيفها المالك من قاعدة البيانات حاليًا.</p>`
      : html`<div class="balances">
          ${data.balances.map(
            (b) => html`<div class="bal-card">
              <span class="bal-name">${b.name}</span>
              <span class="bal-meta">${TREASURY_TYPE_LABEL[b.type] ?? b.type} · ${b.movementCount} حركة</span>
              <span class="bal-amount" data-negative="${b.balancePiastres < 0 ? 'true' : 'false'}">
                ${formatPiastres(b.balancePiastres)}<span class="bal-cur">ج.م</span>
              </span>
            </div>`,
          )}
        </div>`;

  return shell({
    title: 'الخزينة',
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
    ${data.balances.length > 1
      ? html`<div class="bal-card bal-total">
          <span class="bal-name">الإجمالي</span>
          <span class="bal-amount" data-negative="${total < 0 ? 'true' : 'false'}">${formatPiastres(total)}<span class="bal-cur">ج.م</span></span>
        </div>`
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
      <div class="field">
        <label class="field-label" for="mv-treasury">الخزينة</label>
        <select class="field-input" id="mv-treasury" required>
          ${data.balances.map((b) => html`<option value="${b.treasuryId}">${b.name}</option>`)}
        </select>
      </div>

      <div class="field">
        <label class="field-label" for="mv-type">نوع الحركة</label>
        <select class="field-input" id="mv-type">
          <option value="EXPENSE">مصروف</option>
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
          ${data.reasons.map((r) => html`<option value="${r.id}">${r.name}</option>`)}
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

      <div class="field">
        <label class="field-label" for="mv-note">ملاحظة (اختياري)</label>
        <input class="field-input" id="mv-note" type="text" maxlength="500">
      </div>

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

  function syncFields() {
    var t = typeEl.value;
    // سبب الصرف للمصروف وحده. السُلفة سببها معروف من نوعها،
    // والمطلوب معاها اسم الموظّف مش سبب.
    reasonField.hidden = t !== 'EXPENSE';
    userField.hidden = t !== 'ADVANCE';
    dirField.hidden = t !== 'ADJUSTMENT';
  }
  typeEl.addEventListener('change', syncFields);
  syncFields();

  // ── تسجيل حركة ──
  document.getElementById('mvf').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = document.getElementById('mvbtn');
    var box = document.getElementById('mvmsg');
    var text = document.getElementById('mvmsg-text');
    var t = typeEl.value;

    btn.disabled = true;
    btn.textContent = 'جارٍ التسجيل…';

    try {
      var res = await fetch('/api/treasury/movements', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
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
  treasuries: Array<{ treasuryId: string; name: string; type: string }>;
  products: Array<{
    id: string;
    name: string;
    productType: 'device' | 'accessory';
    serialNumber: string | null;
    /** null = يطلب النظام السعر يدويًا وقت البيع */
    pricePiastres: number | null;
    quantityOnHand: number;
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
    script: posScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
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
      <div class="field">
        <label class="field-label" for="pos-treasury">الخزينة</label>
        <select class="field-input" id="pos-treasury" ${hasTreasury ? '' : raw('disabled')}>
          ${data.treasuries.map(
            (t) => html`<option value="${t.treasuryId}">${t.name}</option>`,
          )}
        </select>
        <p class="field-hint">
          تُقرأ وسيلة الدفع من الخزينة نفسها — نقدي، فيزا، إنستاباي.${data.roleKey === 'SUPER_ADMIN'
            ? ' تظهر لك منتجات كل الفروع، فاختر خزينة الفرع نفسه الذي تنتمي إليه منتجات السلة.'
            : ''}
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

  ${data.recentSales.length > 0
    ? html`<details class="panel">
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
              </div>

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
      </details>`
    : ''}
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

function posScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}
${TIME_JS}

(function () {
  // السلة في الذاكرة: معرّف المنتج ← { الاسم، السعر بالقرش، الكمية، المتاح }
  var cart = {};

  var linesEl = document.getElementById('cart-lines');
  var emptyEl = document.getElementById('cart-empty');
  var totalEl = document.getElementById('cart-total');
  var clearEl = document.getElementById('cart-clear');
  var submitEl = document.getElementById('pos-submit');
  var boxEl = document.getElementById('posmsg');
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
        max: max
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

  // ── البحث: بيخفي المربّعات مش بيعيد بناءها ──
  var search = document.getElementById('pos-search');
  if (search) {
    search.addEventListener('input', function () {
      var q = search.value.trim();
      var btns = document.querySelectorAll('[data-add]');
      for (var i = 0; i < btns.length; i++) {
        var name = btns[i].getAttribute('data-name') || '';
        btns[i].hidden = q.length > 0 && name.indexOf(q) === -1;
      }
    });
  }

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
          exitDate: document.getElementById('pos-exit').value || null
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
  canSell: boolean;
  canUseTreasury: boolean;
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
  }>;
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

          return html`<div class="prod-row" data-row="${p.id}">
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

                  <div class="prod-edit-actions">
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
    script: productsScript(data.idleTimeoutSeconds, data.idleWarningSeconds, data.idleAction),
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

  <details class="panel" open>
    <summary>المخزون (${String(data.products.length)})</summary>
    <div class="panel-body">
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

function productsScript(idleTimeout: number, warnAt: number, action: 'LOGOUT' | 'LOCK'): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
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

  function syncType() {
    if (!typeEl) return;
    var isDevice = typeEl.value === 'device';
    // الجهاز: سريال ظاهر، وخانة الكمية مختفية لأنها مقفولة على 1
    if (serialField) serialField.hidden = !isDevice;
    if (qtyField) qtyField.hidden = isDevice;
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
            branchId: branch ? branch.value : null
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
            </div>
          </div>`,
        )}`;

  return shell({
    title: 'المحلات',
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
