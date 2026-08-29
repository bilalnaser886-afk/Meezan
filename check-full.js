const fs = require('fs'), vm = require('vm');

/**
 * ⚠ الخطوة دي هي اللي كانت ناقصة، وفوّتت غلطة كسرت الموقع.
 *
 * الملف قالب نصي في TypeScript. يعني `\n` المكتوبة في المصدر
 * بتتحوّل **سطر جديد حقيقي** قبل ما توصل للمتصفح.
 *
 * الفاحص كان بيقرا المصدر الخام، فكان شايف `\n` كحرفين سليمين
 * جوّه نص — وبيقول "سليم". والمتصفح كان بيشوف سطر جديد جوّه نص
 * أحادي، يعني نص مفتوح، يعني SyntaxError.
 *
 * فلازم نعالج الهروب زي ما TypeScript بتعالجه، وبعدين نفحص.
 */
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
      default: return g;   // \\ · \` · \' · \" · \$
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

const src = fs.readFileSync(process.argv[2], 'utf8');
const names = [...src.matchAll(/^function (\w*Script)\(/gm)].map(m => m[1]);
let bad = 0;

for (const n of names) {
  const i = src.indexOf('function ' + n + '(');
  const s = src.indexOf('return `', i);
  const e = src.indexOf('\n`;\n}', s);
  if (s < 0 || e < 0) { console.log('WARN  ' + n); continue; }
  try { new vm.Script(unescapeTemplate(strip(src.slice(s + 8, e)))); }
  catch (err) { bad++; console.log('FAIL نحوي ' + n + ': ' + err.message); }
}

// ── backtick داخل تعليقات القوالب ──
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
        console.log('FAIL backtick في تعليق — السطر ' + (base + i));
      }
    }
  }
}

// ── فحص النطاق ──
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

// ── دوال منادَاة وهي مش معرّفة في نفس السكربت ──
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

console.log((bad || scope || ticks || helpers)
  ? '\n🔴 ' + (bad + scope + ticks + helpers) + ' مشكلة'
  : '\n✅ كل السكربتات سليمة نحويًا ونطاقيًا');
