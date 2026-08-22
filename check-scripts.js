// فاحص نحوي للجافاسكربت المضمّن في pages.ts
//
// ⚠ نهاية القالب = "\n`;\n}" أول مرة بعد الفتح — مش آخر backtick
// في الملف. الغلطة دي خلّت الفاحص يقرا كود TypeScript بعد الدالة.
const fs = require('fs'), vm = require('vm');

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
  if (s < 0 || e < 0) { console.log('⚠️  ' + n); continue; }
  try { new vm.Script(strip(src.slice(s + 8, e))); console.log('✅ ' + n); }
  catch (err) { bad++; console.log('❌ ' + n + ': ' + err.message); }
}
// ── فحص الـ backtick داخل تعليقات القوالب ──
//
// ⚠ backtick جوّه **تعليق** داخل قالب نصي بيقفل القالب، والخطأ
// بيشاور على سطر بعيد تمامًا عن السبب. وقعنا فيه مرتين.
//
// ملاحظات على الحدود:
//   • backtick جوّه ${...} سليم — قالب متداخل
//   • القوالب اللي في سطر واحد مالهاش تعليقات، فمستبعدة
// عشان كده بنفحص السكربتات الكبيرة بس: ثوابت _JS ودوال *Script.
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
        console.log('❌ backtick في تعليق داخل قالب — السطر ' + (base + i));
      }
    }
  }
}

// ── فحص النطاق: متغيّر مستخدم في قالب سكربت وهو مش معرّف عنده ──
//
// ⚠ ده بيمسك نوع غلط الفحص النحوي أعمى عنه تمامًا: الكتابة
// سليمة، بس الاسم مش موجود. tsc بيمسكه — وإحنا مش قادرين
// نشغّله من الموبايل.
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
  const bad = [...new Set(refs)].filter(r =>
    !known.has(r) && !src.includes('const ' + r) && !src.includes('function ' + r));
  if (bad.length) { scope++; console.log('❌ نطاق — ' + m[1] + ': ' + bad.join(', ')); }
}

console.log((bad || scope || ticks)
  ? '\n🔴 ' + (bad + scope + ticks) + ' مشكلة'
  : '\nكل السكربتات سليمة نحويًا ونطاقيًا');
