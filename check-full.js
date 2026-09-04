const fs = require('fs'), vm = require('vm');

// ══ ⚠ حارس المدخلات وكود الخروج — إضافة البوّابة ══
//
// السبب: الفاحص كان بيطبع المشاكل وبيخرج بكود نجاح (0) دايمًا.
// يدويًا ده ماكانش بيفرق — إنت بتقرا الشاشة. لكن على السيرفر،
// كود الخروج هو **الإشارة الوحيدة**. فالبوّابة كانت هتقول أخضر
// حتى والفاحص طالع ٢٠ مشكلة.
//
// ⚠ ده بالظبط الفشل الصامت اللي الفاحص نفسه اتعمل عشانه.
//
// وكمان: من غير وسيط، `readFileSync(undefined)` بترمي استثناء
// غامض. دلوقتي بترجع رسالة صريحة بطريقة الاستخدام.
const target = process.argv[2];

if (!target) {
  console.error('الاستخدام: node check-full.js <مسار الملف>');
  console.error('مثال:      node check-full.js src/ui/pages.ts');
  process.exit(2);
}

if (!fs.existsSync(target)) {
  console.error('الملف مش موجود: ' + target);
  process.exit(2);
}

console.log('── فحص: ' + target + ' ──');

function unescapeTemplate(s) {
  return s.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\s\S])/g, (m, g) => {
    switch (g[0]) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      case 'b': return '\b';
      case 'f': return '\f';
      case 'v': return '\v';
      case '0': return g.length === 1 ? '\0' : m;
      case 'u': case 'x':
        try { return JSON.parse('"' + m + '"'); } catch { return m; }
      default: return g;
    }
  });
}

function strip(js) {
  let o = '', i = 0;
  while (i < js.length) {
    if (js[i] === '$' && js[i + 1] === '{') {
      let d = 1; i += 2;
      while (i < js.length && d > 0) { if (js[i] === '{') d++; else if (js[i] === '}') d--; i++; }
      o += '0';
    } else o += js[i++];
  }
  return o;
}

const src = fs.readFileSync(target, 'utf8');
const names = [...src.matchAll(/^function (\w*Script)\(/gm)].map(m => m[1]);
let bad = 0;

// ══ ⚠ الثوابت المشتركة — النقطة العميا اللي كلّفتنا جلسة ══
//
// الفحص النحوي كان بيغطّي دوال `*Script` بس. والماسح بالكاميرا
// وسكربت الطباعة والتنبيهات كلهم في ثوابت `_JS` مشتركة — يعني
// **بره الفحص تمامًا**.
//
// والنتيجة: نص أحادي اتكسر جوّه PRINT_SHARED_JS، فالسكربت كله
// وقع و`window.scanBarcode` ما اتعرّفتش. الشاشة قالت "الماسح
// غير متاح على هذا المتصفح" — رسالة بتشاور على المتصفح والغلط
// في سطر عندنا.
//
// ⚠ والفاحص كان بيقول أخضر، لأنه ما بصّش على المكان أصلاً.
for (const m of src.matchAll(/^const (\w+_JS) = `/gm)) {
  const from = m.index + m[0].length;
  const to = src.indexOf('\n`;', from);
  if (to < 0) { console.log('WARN  ' + m[1]); continue; }
  try { new vm.Script(unescapeTemplate(strip(src.slice(from, to)))); }
  catch (err) { bad++; console.log('FAIL نحوي ' + m[1] + ': ' + err.message); }
}

for (const n of names) {
  const i = src.indexOf('function ' + n + '(');
  const s = src.indexOf('return `', i);
  const e = src.indexOf('\n`;\n}', s);
  if (s < 0 || e < 0) { console.log('WARN  ' + n); continue; }
  try { new vm.Script(unescapeTemplate(strip(src.slice(s + 8, e)))); }
  catch (err) { bad++; console.log('FAIL نحوي ' + n + ': ' + err.message); }
}

let ticks = 0;
{
  const ranges = [];
  for (const m of src.matchAll(/const \w+_JS = `/g)) {
    const from = m.index + m[0].length;
    const to = src.indexOf('\n`;', from);
    if (to > from) ranges.push([from, to]);
  }
  for (const m of src.matchAll(/^function \w*Script\(/gm)) {
    const st = src.indexOf('return `', m.index);
    if (st < 0) continue;
    const to = src.indexOf('\n`;', st);
    if (to > st) ranges.push([st + 8, to]);
  }
  for (const [from, to] of ranges) {
    const lines = src.slice(from, to).split('\n');
    const base = src.slice(0, from).split('\n').length;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      const isComment = t.startsWith('*') || t.startsWith('//') || t.startsWith('/*');
      if (isComment && t.includes('`')) {
        ticks++;
        console.log('FAIL backtick في تعليق سكربت — السطر ' + (base + i));
      }
    }
  }

  const htmlComments = src.matchAll(/<!--[\s\S]*?-->/g);
  for (const m of htmlComments) {
    if (!m[0].includes('`')) continue;
    ticks++;
    const line = src.slice(0, m.index).split('\n').length;
    console.log('FAIL backtick في تعليق HTML — السطر ' + line);
  }
}

const fnRe = /^function (\w*Script)\(([^)]*)\)/gms;
let scope = 0, m;
while ((m = fnRe.exec(src))) {
  const params = m[2].split(',').map(x => x.trim().split(':')[0].trim())
    .filter(x => x && !x.startsWith('/') && !x.startsWith('*'));
  const st = src.indexOf('return `', m.index);
  const en = src.indexOf('\n`;', st);
  if (st < 0 || en < 0) continue;
  const body = src.slice(st, en);
  const refs = [...body.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)/g)].map(x => x[1]);
  const known = new Set([...params, 'shared', 'JSON', 'String', 'Number', 'Math']);
  const badRefs = [...new Set(refs)].filter(r =>
    !known.has(r) && !src.includes('const ' + r) && !src.includes('function ' + r));
  if (badRefs.length) { scope++; console.log('FAIL نطاق — ' + m[1] + ': ' + badRefs.join(', ')); }
}

const COMMON = new Set(['fetch','parseInt','parseFloat','setTimeout','setInterval',
  'clearTimeout','clearInterval','confirm','alert','prompt','isFinite','String',
  'Number','Boolean','Array','Object','JSON','Math','Date','Promise','Event',
  'Notification','Blob','URL','FormData','encodeURIComponent','decodeURIComponent',
  'if','for','while','switch','catch','function','return','typeof','new','await',
  'filter','map','forEach','push','indexOf','slice','join','split','replace','trim',
  'toLocaleString','padStart','querySelector','querySelectorAll','getElementById',
  'createElement','appendChild','addEventListener','removeChild','getAttribute',
  'setAttribute','hasAttribute','removeAttribute','closest','dispatchEvent',
  'reset','focus','open','close','play','detect','decodeFromVideoElement',
  'getUserMedia','requestPermission','showNotification','getRegistration',
  'createElementNS','elementFromPoint','scrollTo','print','stop','getTracks',
  'createObjectURL','revokeObjectURL','click','matchAll','test','exec','abs',
  'floor','round','trunc','max','min','all','resolve','reject','then','keys',
  'stringify','parse','now','isInteger','from','of','concat','sort','reverse',
  'includes','startsWith','endsWith','toUpperCase','toLowerCase','charCodeAt',
  'fromCharCode','repeat','substring','substr','splice','shift','unshift','pop',
  'var','let','const','Error','TypeError','else','do','try','finally','throw',
  'isNaN','Set','Map','Intl','RegExp','Symbol','BigInt','structuredClone']);

let helpers = 0;
for (const fm of src.matchAll(/^function (\w*Script)\(/gm)) {
  const st = src.indexOf('return `', fm.index);
  if (st < 0) continue;
  const to = src.indexOf('\n`;', st);
  if (to < 0) continue;
  const body = src.slice(st + 8, to);

  const defined = new Set([
    ...[...body.matchAll(/function (\w+)\s*\(/g)].map(x => x[1]),
    ...[...body.matchAll(/var (\w+)\s*=/g)].map(x => x[1]),
    ...[...body.matchAll(/function\s*\w*\s*\(([^)]*)\)/g)]
      .flatMap(x => x[1].split(',').map(a => a.trim()))
      .filter(Boolean),
  ]);

  const called = [...body.matchAll(/(^|[^.\w$])([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)]
    .map(x => x[2]);

  const missing = [...new Set(called)].filter(
    (n) => !defined.has(n) && !COMMON.has(n) && !src.includes('window.' + n + ' ='));

  if (missing.length) {
    helpers++;
    console.log('FAIL دالة غير معرّفة — ' + fm[1] + ': ' + missing.join(', '));
  }
}

let ids = 0;
{
  const declared = new Set(
    [...src.matchAll(/\bid="([A-Za-z][\w-]*)"/g)].map((m) => m[1]),
  );
  const runtimeBuilt = new Set(
    [...src.matchAll(/\bid="([A-Za-z][\w-]*)"/g)].map((m) => m[1]),
  );

  for (const m of src.matchAll(/^function \w*Script\(/gm)) {
    const st = src.indexOf('return `', m.index);
    if (st < 0) continue;
    const to = src.indexOf('\n`;', st);
    if (to < 0) continue;
    const body = src.slice(st + 8, to);

    const used = new Set(
      [...body.matchAll(/getElementById\(\s*'([A-Za-z][\w-]*)'\s*\)/g)].map((x) => x[1]),
    );
    for (const id of used) {
      if (declared.has(id) || runtimeBuilt.has(id)) continue;
      ids++;
      console.log('FAIL معرّف غير موجود في أي قالب — ' + id);
    }
  }
}

// ── ⚠ شرطة مائلة مفردة جوّه قالب سكربت ──
//
// ⚠ الفحص ده اتضاف بعد عطل ضيّع ساعة.
//
// `\d` في المصدر بتوصل للمتصفح كـ`d`، لأن القالب النصي بياكل
// الشرطة. فـ`/^(\d+)$/` بتبقى `/^(d+)$/` — تعبير نمطي **سليم
// نحويًا** بيدوّر على حرف d بدل رقم.
//
// ⚠ وعشان كده الفحص النحوي فوق أعمى عنه تمامًا: هو بيفك الهروب
// الأول (زي المتصفح) وبعدين بيحلّل، والناتج بيتحلّل سليم.
// الغلط في **المعنى** مش في الكتابة.
//
// الأعراض كانت: الكاشير بيكتب 4000 والإجمالي بيفضل صفر، بلا أي
// رسالة خطأ. ونفس الغلطة كانت في فحص الآيمي وفحص التاريخ.
//
// القاعدة: أي `\` لازم توصل للمتصفح تتكتب `\\` في المصدر.
// و`\u0660` استثناء — القالب بيحوّلها للحرف نفسه وده مقبول.
let slashes = 0;

// ⚠ القايمة بتضم الثوابت المشتركة كمان. الغلطة اللي عدّت كانت
// في ثابت، والفحص كان بيبصّ على الدوال بس.
const SPANS = [];
for (const m of src.matchAll(/^function (\w*Script)\(/gm)) {
  const st = src.indexOf('return `', m.index);
  if (st < 0) continue;
  const to = src.indexOf('\n`;', st);
  if (to > st) SPANS.push([m[1], st + 8, to]);
}
for (const m of src.matchAll(/^const (\w+_JS) = `/gm)) {
  const st = m.index + m[0].length;
  const to = src.indexOf('\n`;', st);
  if (to > st) SPANS.push([m[1], st, to]);
}

for (const [label, spanFrom, spanTo] of SPANS) {
  const raw = src.slice(spanFrom, spanTo);
  const base = src.slice(0, spanFrom).split('\n').length;

  raw.split('\n').forEach((line, i) => {
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;

    // شرطة مفردة: مش مسبوقة ولا متبوعة بشرطة تانية
    const singles = [...line.matchAll(/(?<!\\)\\(?!\\)(.)/g)];
    for (const s1 of singles) {
      // \u و \x بيتحوّلوا لحروف صحيحة، وده مقبول
      if (s1[1] === 'u' || s1[1] === 'x') continue;
      slashes++;
      console.log('FAIL شرطة مفردة (هتتاكل قبل المتصفح) — '
        + label + ' السطر ' + (base + i) + ': ' + t.slice(0, 70));
      break;
    }
  });
}

// ══ الخلاصة + كود الخروج ══
//
// ⚠ `process.exit(1)` هو اللي بيخلّي البوّابة على السيرفر تحمرّ.
// من غيره الرسالة بتتطبع والسيرفر بيقول "تمام" ويكمّل نشر.
const total = bad + scope + ticks + helpers + ids + slashes;

console.log(total
  ? '\n🔴 ' + total + ' مشكلة'
  : '\n✅ كل السكربتات سليمة نحويًا ونطاقيًا');

process.exit(total ? 1 : 0);
