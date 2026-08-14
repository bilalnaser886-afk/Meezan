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
        '<p class="lock-who">شغلك محفوظ. اكتب كلمة المرور للمتابعة.</p>' +
        '<form id="lkf"><input class="lock-input" id="lkpw" type="password" dir="ltr" ' +
          'autocomplete="current-password" required>' +
          '<button class="lock-btn" id="lkbtn" type="submit">فتح</button></form>' +
        '<p class="lock-error" id="lkerr" role="alert" aria-live="assertive"></p>' +
        '<button class="lock-exit" id="lkout" type="button">تسجيل خروج بدل كده</button>' +
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
          '<span>' + (ACTION === 'LOCK' ? 'الشاشة هتتقفل خلال' : 'هيتم تسجيل خروجك خلال') + '</span>' +
          '<span class="idle-count">' + remaining + '</span><span>ثانية</span>' +
          '<button class="idle-btn" id="stay" type="button">أنا هنا</button>' +
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
  'https://fonts.googleapis.com/css2?family=Readex+Pro:wght@400;500;600;700&family=IBM+Plex+Sans+Arabic:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap';

type Html = HtmlEscapedString | Promise<HtmlEscapedString>;

function shell(opts: { title: string; noIndex?: boolean; body: Html; script: string }): Html {
  return html`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${opts.title}</title>
${opts.noIndex ? raw('<meta name="robots" content="noindex, nofollow, noarchive">') : ''}
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<style>${raw(BASE_CSS)}</style>
</head>
<body>
${opts.body}
<script>${raw(opts.script)}</script>
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

const ROLE_STAMP: Record<string, string> = {
  SUPER_ADMIN: 'المالك',
  BRANCH_MANAGER: 'مدير فرع',
  STAFF: 'موظّف',
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
}): Html {
  return html`<header class="app-bar">
  <div class="who">
    <span class="who-name">${opts.fullName}</span>
    <span class="stamp" data-role="${opts.roleKey}">${ROLE_STAMP[opts.roleKey] ?? opts.roleKey}</span>
  </div>

  <details class="menu" id="menu">
    <summary aria-label="القائمة" title="القائمة">⋮</summary>
    <div class="menu-sheet">
      <div class="menu-info">
        <div class="menu-row"><span>اسم المستخدم</span><b>${opts.username}</b></div>
        ${opts.branchLabel
          ? html`<div class="menu-row"><span>الفرع</span><b>${opts.branchLabel}</b></div>`
          : ''}
      </div>
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
  <p class="counter-eyebrow">POS TERMINAL</p>
  <h1 class="counter-title">تسجيل الدخول</h1>
  <p class="counter-sub">استخدم بيانات الحساب اللي مدير الفرع أداهالك.</p>

  ${opts.expired
    ? raw(
        '<div class="alert-box" role="status"><span aria-hidden="true">⏱</span><span>انتهت الجلسة لعدم النشاط. سجّل الدخول لاستئناف الوردية.</span></div>',
      )
    : ''}

  <div class="alert-box" id="err" role="alert" hidden>
    <span aria-hidden="true">⚠</span><span id="err-text"></span>
  </div>

  <form id="f" novalidate>
    <div class="field">
      <label class="field-label" for="username">اسم المستخدم</label>
      <input class="field-input" id="username" type="text" dir="ltr" autocomplete="username"
        autocapitalize="none" spellcheck="false" maxlength="64" required autofocus>
    </div>
    <div class="field">
      <label class="field-label" for="password">كلمة المرور</label>
      <input class="field-input" id="password" type="password" dir="ltr"
        autocomplete="current-password" maxlength="1024" required>
      <p class="field-hint">الشاشة بتتقفل تلقائياً بعد ١٠ دقايق من غير حركة.</p>
    </div>
    <button class="btn-primary" id="btn" type="submit">ابدأ الوردية</button>
  </form>

  <div class="counter-foot"><span>MODULE 01</span><span>v1.0.0</span></div>
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
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
          gate: 'staff'
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
      fail('تعذّر الاتصال بالخادم. اتأكد إن الجهاز متصل بالشبكة.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'ابدأ الوردية';
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
export function vaultPage(): Html {
  return shell({
    title: ' ',
    noIndex: true,
    script: VAULT_SCRIPT,
    body: html`<main class="vault"><div class="vault-card">
<p class="vault-error" id="err" role="alert" aria-live="assertive"></p>
<form id="f" novalidate autocomplete="off">
  <div class="vault-field">
    <label class="sr-only" for="u">المعرّف</label>
    <input class="vault-input" id="u" type="text" placeholder="IDENTIFIER" dir="ltr"
      autocomplete="off" spellcheck="false" maxlength="64" required>
  </div>
  <div class="vault-field">
    <label class="sr-only" for="p">كلمة المرور</label>
    <input class="vault-input" id="p" type="password" placeholder="PASSPHRASE" dir="ltr"
      autocomplete="off" maxlength="1024" required>
  </div>
  <div class="vault-field">
    <label class="sr-only" for="k">المفتاح السرّي</label>
    <input class="vault-input" id="k" type="password" placeholder="SECOND KEY" dir="ltr"
      autocomplete="off" maxlength="512" required>
  </div>
  <button class="vault-btn" id="btn" type="submit">UNLOCK</button>
</form>
</div></main>`,
  });
}

const VAULT_SCRIPT = `
(function () {
  var form = document.getElementById('f');
  var btn = document.getElementById('btn');
  var err = document.getElementById('err');

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'VERIFYING';

    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          username: document.getElementById('u').value,
          password: document.getElementById('p').value,
          adminPasskey: document.getElementById('k').value,
          gate: 'admin'
        })
      });

      if (!res.ok) {
        // رسالة واحدة لكل أنواع الفشل — ما نرشدش المهاجم لغلطته
        err.textContent = res.status === 429 ? 'ACCESS THROTTLED' : 'ACCESS DENIED';
        document.getElementById('p').value = '';
        document.getElementById('k').value = '';
        return;
      }
      window.location.href = '/app';
      return;
    } catch (e) {
      err.textContent = 'CONNECTION FAILED';
    } finally {
      btn.disabled = false;
      btn.textContent = 'UNLOCK';
    }
  });
})();
`;

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
    الصفحة دي بتشتغل مرة واحدة بس. بعد ما تخلص، امسح <code>SETUP_SECRET</code>
    من إعدادات كلاودفلير وهتقفل نفسها تلقائياً.
  </p>

  <div class="alert-box" id="msg" role="alert" hidden><span id="msg-text"></span></div>

  <form id="f" novalidate>
    <div class="field">
      <label class="field-label" for="setupSecret">سرّ الإعداد</label>
      <input class="field-input" id="setupSecret" name="setupSecret" type="password"
        dir="ltr" autocomplete="off" required>
      <p class="field-hint">نفس القيمة اللي حطّيتها في SETUP_SECRET.</p>
    </div>
    <div class="field">
      <label class="field-label" for="username">اسم المستخدم</label>
      <input class="field-input" id="username" name="username" type="text" dir="ltr"
        autocomplete="off" spellcheck="false" maxlength="32" required>
      <p class="field-hint">حروف إنجليزية صغيرة وأرقام، من 3 لـ 32 حرف.</p>
    </div>
    <div class="field">
      <label class="field-label" for="fullName">الاسم الكامل</label>
      <input class="field-input" id="fullName" name="fullName" type="text" maxlength="80" required>
    </div>
    <div class="field">
      <label class="field-label" for="password">كلمة المرور</label>
      <input class="field-input" id="password" name="password" type="password" dir="ltr"
        autocomplete="new-password" required>
      <p class="field-hint">12 حرف على الأقل.</p>
    </div>
    <div class="field">
      <label class="field-label" for="passkey">المفتاح السرّي الثاني</label>
      <input class="field-input" id="passkey" name="passkey" type="password" dir="ltr"
        autocomplete="new-password" required>
      <p class="field-hint">
        16 حرف على الأقل، ولازم يكون مختلف تماماً عن كلمة المرور.
        ده القفل التاني على بوّابتك السرّية.
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
  allBranches: DashboardBranchFull[];
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
    <p class="lock-who">جلستك لسه شغّالة. اكتب كلمة المرور للمتابعة.</p>

    <form id="lf" novalidate>
      <label class="sr-only" for="lpw">كلمة المرور</label>
      <input class="lock-input" id="lpw" type="password" dir="ltr"
        autocomplete="current-password" required autofocus>
      <button class="lock-btn" id="lbtn" type="submit">فتح</button>
    </form>

    <p class="lock-error" id="lerr" role="alert" aria-live="assertive"></p>
    <button class="lock-exit" id="lout" type="button">تسجيل خروج بدل كده</button>
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
    هيظهر كنافذة إلزامية لكل من يخصّه عند أول دخول، ومش هيقدر يكمّل
    قبل ما يضغط «قرأت وفهمت» — والضغطة بتتسجّل باسمه ووقتها.
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
        <option value="MANAGERS_ONLY">مديري الفروع بس</option>
        <option value="STAFF_ONLY">الموظفين بس</option>
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
  STAFF: 'موظّف',
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
    return html`<p class="muted">لسه مفيش حسابات مضافة. ابدأ بإضافة حساب من الفورم فوق.</p>`;
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
        التعطيل بيقطع جلسة الموظّف فورًا ويمنعه من الدخول، وبيحتفظ بكل سجلّه ومبيعاته.
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
    data.allBranches.length === 0
      ? html`<p class="muted">مفيش فروع لسه.</p>`
      : html`<ul class="roster">
          ${data.allBranches.map(
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
      الفرع لازم يتعمل قبل ما تقدر تضيف حسابات ليه. الكود بيظهر في الفواتير
      والتقارير، فخلّيه قصير وثابت.
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
        <label class="field-label" for="br-phone">التليفون (اختياري)</label>
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
        ? 'اختَر الفرع والدور. الحساب هيدخل بنفس اسم المستخدم وكلمة المرور اللي هتكتبها.'
        : 'الحساب هيتربط بفرعك تلقائياً. لو اخترت «مدير فرع»، هيبقى بنفس صلاحياتك بالظبط جوّه الفرع ده.'}
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
        <p class="field-hint">حروف إنجليزية صغيرة وأرقام فقط، من 3 لـ 32 حرف.</p>
      </div>
      <div class="field">
        <label class="field-label" for="u-password">كلمة المرور المبدئية</label>
        <input class="field-input" id="u-password" type="text" dir="ltr" autocomplete="off" required>
        <p class="field-hint">12 حرف على الأقل. سلّمها للموظّف بنفسك بعد الإنشاء.</p>
      </div>
      <div class="field">
        <label class="field-label" for="u-role">الدور</label>
        <select class="field-input" id="u-role">
          <option value="STAFF">موظّف</option>
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
          <span class="strip-text"><b>طلبات صرف مستنية اعتمادك.</b> مش داخلة في الرصيد لحد ما تعتمدها.</span>
          <a class="strip-go" href="/treasury">راجعها</a>
        </section>`
      : html`<section class="strip" data-tone="calm">
          <span class="strip-text">مفيش حاجة مستنية قرارك دلوقتي.</span>
        </section>`;

  // ── البلاطات: اللي تقدر تعمله، بكلام مفهوم مش أكواد نظام ──
  const tiles: Html[] = [];

  // البيع أول بلاطة عن قصد: دي الحاجة اللي الموظّف بيفتح النظام
  // عشانها. اللي بيتعمل خمسين مرة في اليوم بييجي قبل اللي بيتعمل
  // مرة في الأسبوع.
  if (canSell) {
    tiles.push(html`<a class="tile" data-wide href="/pos">
      <span class="tile-label">شاشة البيع</span>
      <span class="tile-note">اختار المنتجات واقفل الفاتورة</span>
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
      <span class="tile-note">${data.canApproveExpenses ? 'مصروفات وسُلف وأرصدة' : 'سجّل مصروف أو سُلفة'}</span>
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
      <span class="tile-num">${String(data.allBranches.length)}</span>
    </a>`);
  }

  if (data.canBroadcast) {
    tiles.push(html`<a class="tile" data-wide href="#broadcast">
      <span class="tile-label">بثّ إعلان</span>
      <span class="tile-note">نافذة إلزامية لكل من يخصّه</span>
    </a>`);
  }

  // ── شاشة الموظّف: بتقول له إيه اللي جاي بدل ما تسيبه في فراغ ──
  const staffEmpty = html`<section class="panel" open>
    <div class="empty">
      <p class="empty-title">يومك يبدأ من شاشة البيع</p>
      <p class="empty-note">
        اختار المنتجات، حدّد الخزينة، واقفل الفاتورة.<br>
        المرتجعات وتسجيل العملاء هيتفتحوا في تحديث جاي.
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
        alert('تعذّر تسجيل الإقرار. اتأكد من الاتصال وحاول تاني.');
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
          text.textContent = 'تم إنشاء الحساب. الصفحة هتتحدّث الآن…';
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

    if (!turnOn && !confirm('تعطيل الحساب ده؟ هيتقطع من النظام فورًا.')) return;

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
          text.textContent = 'تمت إضافة الفرع. الصفحة هتتحدّث الآن…';
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
  if (items.length === 0) return html`<p class="muted">مفيش حركات.</p>`;

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
      ? html`<p class="muted">مفيش خزائن. المالك بيضيفها من قاعدة البيانات حاليًا.</p>`
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
        ? 'حركتك بتتعتمد فورًا وبتأثّر على الرصيد على طول.'
        : 'حركتك بتتسجّل كطلب معلّق، وما بتأثّرش على الرصيد قبل اعتماد المدير.'}
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
          ${data.team.map((t) => html`<option value="${t.id}">${t.fullName}</option>`)}
        </select>
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
          <p class="muted">الطلبات دي مش داخلة في الرصيد لحد ما تعتمدها.</p>
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
    reasonField.hidden = !(t === 'EXPENSE' || t === 'ADVANCE');
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
          expenseReasonId: (t === 'EXPENSE' || t === 'ADVANCE') ? document.getElementById('mv-reason').value : null,
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

    if (decision === 'REJECTED' && !confirm('رفض الطلب ده؟')) return;

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
  roleKey: string;
  canViewProducts: boolean;
  canUseTreasury: boolean;
  treasuries: Array<{ treasuryId: string; name: string; type: string }>;
  products: Array<{ id: string; name: string; pricePiastres: number; quantityOnHand: number }>;
  recentSales: Array<{
    id: string;
    totalPiastres: number;
    customerName: string | null;
    staffName: string | null;
    createdAt: Date;
  }>;
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
        <p class="empty-title">مفيش منتجات متاحة</p>
        <p class="empty-note">
          إمّا لسه ما اتضافتش منتجات، أو الكميات كلها خلصت.<br>
          المدير بيضيفها ويورّدها من شاشة المنتجات.
        </p>
      </div>`
    : html`<div class="prod-grid" id="prod-grid">
        ${data.products.map(
          (p) => html`<button class="prod-btn" type="button"
            data-add="${p.id}"
            data-name="${p.name}"
            data-price="${String(p.pricePiastres)}"
            data-max="${String(p.quantityOnHand)}">
            <span class="prod-btn-name">${p.name}</span>
            <span class="prod-btn-price">${formatPiastres(p.pricePiastres)}</span>
            <span class="prod-btn-qty">متاح ${String(p.quantityOnHand)}</span>
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
    })}

<main class="shell">
  <div class="alert-box" id="posmsg" role="alert" hidden><span id="posmsg-text"></span></div>

  <section class="cart">
    <div class="cart-head">
      <span class="cart-title">السلة</span>
      <button class="btn-mini" type="button" id="cart-clear" hidden>تفريغ</button>
    </div>

    <p class="cart-empty" id="cart-empty">فاضية. اختار منتج من تحت.</p>
    <div id="cart-lines"></div>

    <div class="cart-total">
      <span class="cart-total-label">الإجمالي</span>
      <span class="cart-total-num" id="cart-total">0.00<span class="bal-cur">ج.م</span></span>
    </div>
  </section>

  ${!hasTreasury
    ? html`<div class="alert-box"><span>
        مفيش خزينة متاحة لفرعك، فمش هينفع تقفل فاتورة. كلّم المالك يضيف خزينة للفرع.
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
          وسيلة الدفع بتتقرا من الخزينة نفسها — كاش، فيزا، إنستاباي.${data.roleKey === 'SUPER_ADMIN'
            ? ' إنت بتشوف منتجات كل الفروع، فاختار خزينة نفس فرع المنتجات اللي في السلة.'
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

      <button class="btn-primary" id="pos-submit" type="button" disabled>تم البيع</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>المنتجات</summary>
    <div class="panel-body">
      ${hasProducts
        ? html`<div class="field">
            <input class="field-input" id="pos-search" type="search"
              placeholder="دوّر بالاسم" autocomplete="off">
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
                  ${s.staffName ? `${s.staffName} · ` : ''}<span data-time="${s.createdAt.toISOString()}"></span>
                </span>
              </div>
              <div class="mv-side">
                <span class="mv-amount" data-dir="IN">+${formatPiastres(s.totalPiastres)}</span>
              </div>
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

  function total() {
    var sum = 0;
    for (var id in cart) sum += cart[id].price * cart[id].qty;
    return sum;
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

      var side = document.createElement('div');
      side.className = 'cart-line-side';

      var amount = document.createElement('span');
      amount.className = 'cart-line-amount';
      amount.textContent = money(line.price * line.qty);

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
    emptyEl.hidden = !isEmpty;
    clearEl.hidden = isEmpty;
    totalEl.innerHTML = money(total()) + '<span class="bal-cur">ج.م</span>';

    var treasury = document.getElementById('pos-treasury');
    submitEl.disabled = isEmpty || !treasury || !treasury.value;
    submitEl.textContent = isEmpty ? 'تم البيع' : 'تم البيع · ' + money(total()) + ' ج.م';
  }

  function add(btn) {
    var id = btn.getAttribute('data-add');
    var max = parseInt(btn.getAttribute('data-max'), 10) || 0;
    if (max <= 0) return;

    if (!cart[id]) {
      cart[id] = {
        name: btn.getAttribute('data-name'),
        price: parseInt(btn.getAttribute('data-price'), 10) || 0,
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

  clearEl.addEventListener('click', function () {
    if (!confirm('تفريغ السلة كلها؟')) return;
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
      items.push({ productId: ids[i], quantity: cart[ids[i]].qty });
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
          customerPhone: document.getElementById('pos-cphone').value || null
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
      textEl.textContent = 'انقطع الاتصال. حدّث الصفحة وشوف آخر الفواتير قبل ما تعيد البيع.';
    } finally {
      render();
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
    pricePiastres: number;
    costPiastres?: number;
    quantityOnHand: number;
    isActive: boolean;
  }>;
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
          <p class="empty-title">مفيش منتجات لسه</p>
          <p class="empty-note">
            ${data.canEdit
              ? 'ابدأ بإضافة أول منتج من القسم اللي فوق.'
              : 'المدير هو اللي بيضيف المنتجات.'}
          </p>
        </div>`
      : html`${data.products.map(
          (p) => html`<div class="prod-row" data-row="${p.id}">
            <div class="prod-row-main">
              <span class="prod-row-name" data-off="${p.isActive ? 'false' : 'true'}">${p.name}</span>
              <span class="prod-row-sub">
                ${formatPiastres(p.pricePiastres)} ج.م${p.costPiastres !== undefined
                  ? ` · تكلفة ${formatPiastres(p.costPiastres)}`
                  : ''}${p.isActive ? '' : ' · موقوف'}
              </span>
            </div>

            <div class="prod-row-side">
              <span class="prod-row-qty" data-zero="${p.quantityOnHand === 0 ? 'true' : 'false'}">
                ${String(p.quantityOnHand)}
              </span>
              ${data.canEdit
                ? html`<button class="btn-mini" type="button" data-edit="${p.id}">تعديل</button>`
                : ''}
            </div>

            ${data.canEdit
              ? html`<div class="prod-edit" id="edit-${p.id}" hidden>
                  <div class="prod-edit-grid">
                    <div class="field">
                      <label class="field-label" for="price-${p.id}">سعر البيع</label>
                      <input class="field-input" id="price-${p.id}" type="text"
                        inputmode="decimal" dir="ltr" value="${formatPiastres(p.pricePiastres)}">
                    </div>
                    ${p.costPiastres !== undefined
                      ? html`<div class="field">
                          <label class="field-label" for="cost-${p.id}">التكلفة</label>
                          <input class="field-input" id="cost-${p.id}" type="text"
                            inputmode="decimal" dir="ltr" value="${formatPiastres(p.costPiastres)}">
                        </div>`
                      : ''}
                  </div>
                  <button class="btn-mini" type="button" data-save-price="${p.id}">حفظ الأسعار</button>

                  <div class="prod-edit-grid" style="margin-top:12px">
                    <div class="field">
                      <label class="field-label" for="stock-${p.id}">تعديل الكمية</label>
                      <input class="field-input" id="stock-${p.id}" type="text"
                        inputmode="numeric" dir="ltr" placeholder="5 أو -2">
                      <p class="field-hint">اكتب الفرق مش الرقم النهائي. سالب = خصم تالف أو جرد.</p>
                    </div>
                  </div>
                  <div class="prod-edit-actions">
                    <button class="btn-mini" type="button" data-save-stock="${p.id}">تعديل الكمية</button>
                    <button class="btn-mini" type="button" data-danger="${p.isActive ? 'true' : 'false'}"
                      data-toggle="${p.id}" data-active="${p.isActive ? 'true' : 'false'}">
                      ${p.isActive ? 'إيقاف المنتج' : 'إعادة تفعيل'}
                    </button>
                  </div>
                </div>`
              : ''}
          </div>`,
        )}`;

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
              <label class="field-label" for="np-name">اسم المنتج</label>
              <input class="field-input" id="np-name" type="text" maxlength="80" required>
            </div>

            <div class="field">
              <label class="field-label" for="np-price">سعر البيع</label>
              <input class="field-input" id="np-price" type="text" inputmode="decimal"
                dir="ltr" autocomplete="off" required>
              <p class="field-hint">بالجنيه. مثال: 150 أو 150.75</p>
            </div>

            <div class="field">
              <label class="field-label" for="np-cost">التكلفة (اختياري)</label>
              <input class="field-input" id="np-cost" type="text" inputmode="decimal"
                dir="ltr" autocomplete="off">
              <p class="field-hint">سيبها فاضية لو مش معروفة — هتتسجّل صفر.</p>
            </div>

            <div class="field">
              <label class="field-label" for="np-qty">الكمية الحالية</label>
              <input class="field-input" id="np-qty" type="text" inputmode="numeric"
                dir="ltr" value="0">
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
    var t = e.target;
    if (!t || !t.closest) return;

    var toggle = t.closest('[data-edit]');
    if (toggle) {
      var panel = document.getElementById('edit-' + toggle.getAttribute('data-edit'));
      if (panel) {
        panel.hidden = !panel.hidden;
        toggle.textContent = panel.hidden ? 'تعديل' : 'إغلاق';
      }
    }
  });

  // ── حفظ الأسعار ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-save-price]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-save-price');
    var priceEl = document.getElementById('price-' + id);
    var costEl = document.getElementById('cost-' + id);

    var body = { price: priceEl ? priceEl.value : undefined };
    // التكلفة بتتبعت بس لو الحقل موجود أصلاً في الصفحة.
    // مفيش حقل = مفيش صلاحية = مفيش قيمة تتبعت.
    if (costEl) body.cost = costEl.value;

    var result = await send('/api/products/' + encodeURIComponent(id), body, btn, 'جارٍ الحفظ…');
    if (result) {
      say('اتحفظ.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── تعديل الكمية ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-save-stock]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-save-stock');
    var input = document.getElementById('stock-' + id);
    if (!input || !input.value.trim()) { say('اكتب الكمية الأول.', false); return; }

    var result = await send(
      '/api/products/' + encodeURIComponent(id) + '/stock',
      { delta: input.value },
      btn,
      'جارٍ التعديل…'
    );

    if (result) {
      say('الكمية بقت ' + result.quantityOnHand + '.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── إيقاف / تفعيل ──
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-toggle]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-toggle');
    var isActive = btn.getAttribute('data-active') === 'true';

    if (isActive && !confirm('إيقاف المنتج ده؟ مش هيظهر في شاشة البيع، وتاريخ مبيعاته هيفضل زي ما هو.')) return;

    var result = await send(
      '/api/products/' + encodeURIComponent(id),
      { isActive: !isActive },
      btn,
      'جارٍ التنفيذ…'
    );

    if (result) {
      say(isActive ? 'المنتج اتوقف.' : 'المنتج رجع شغّال.', true);
      setTimeout(function () { window.location.reload(); }, 900);
    }
  });

  // ── إضافة منتج ──
  var form = document.getElementById('addf');
  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var btn = document.getElementById('addbtn');
      var msg = document.getElementById('addmsg');
      var msgText = document.getElementById('addmsg-text');
      var branch = document.getElementById('np-branch');

      btn.disabled = true;
      btn.textContent = 'جارٍ الإضافة…';

      try {
        var res = await fetch('/api/products', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            name: document.getElementById('np-name').value,
            price: document.getElementById('np-price').value,
            cost: document.getElementById('np-cost').value,
            quantity: document.getElementById('np-qty').value,
            branchId: branch ? branch.value : null
          })
        });
        var data = await res.json().catch(function () { return null; });

        msg.hidden = false;
        if (res.ok) {
          msg.setAttribute('data-tone', 'ok');
          msgText.textContent = 'المنتج اتضاف.';
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
