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
console.log(bad ? '\n🔴 ' + bad + ' فيه خطأ' : '\nكل السكربتات سليمة');
