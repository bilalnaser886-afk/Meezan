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
 * كود الخمول وقفل الشاشة — مشترك بين لوحة التحكم والخزنة.
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

    // ═══════════════════════════════════════════════════════════
    //  مولّد QR — بلا مكتبات، بلا إنترنت
    //
    //  ══ ليه مكتوب بإيدنا؟ ══
    //  مفيش QR جاهز في المتصفح (BarcodeDetector بتقرا وما بتكتبش).
    //  والمكتبات الجاهزة معناها طلب شبكة وقت الطباعة — والطابعة
    //  بتشتغل في محل ممكن يكون النت فيه فاصل.
    //
    //  نفس مبدأ barcodeSvg فوق بالظبط: الرسم محلّي بالكامل.
    //
    //  ══ الإعدادات ══
    //  نمط البايت · تصحيح مستوى M · النسخ من 1 لـ 10.
    //  معرّف المنتج (36 حرف) بيقع في النسخة 3 = مربع 29×29.
    //
    //  ⚠ المستوى M معناه إن الكود بيتقرا حتى لو 15% منه اتخربش
    //  أو اتوسّخ. وده مش رفاهية على ملصق بيقعد في محل.
    // ═══════════════════════════════════════════════════════════
  var QR_ECC_M_BLOCKS = {
    // version: [totalCodewords, eccPerBlock, group1Blocks, g1Data, group2Blocks, g2Data]
    1: [26, 10, 1, 16, 0, 0],
    2: [44, 16, 1, 28, 0, 0],
    3: [70, 26, 1, 44, 0, 0],
    4: [100, 18, 2, 32, 0, 0],
    5: [134, 24, 2, 43, 0, 0],
    6: [172, 16, 4, 27, 0, 0],
    7: [196, 18, 4, 31, 0, 0],
    8: [242, 22, 2, 38, 2, 39],
    9: [292, 22, 3, 36, 2, 37],
    10: [346, 26, 4, 43, 1, 44]
  };

  var ALIGN_POS = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]
  };

  // ── حساب جالوا 256 ──
  var GF_EXP = new Array(512), GF_LOG = new Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      GF_EXP[i] = x; GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (var j = 255; j < 512; j++) GF_EXP[j] = GF_EXP[j - 255];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }

  function rsGenerator(degree) {
    var poly = [1];
    for (var i = 0; i < degree; i++) {
      var next = new Array(poly.length + 1).fill(0);
      for (var j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
      }
      poly = next;
    }
    return poly;
  }

  function rsEncode(data, eccLen) {
    var gen = rsGenerator(eccLen);
    var res = new Array(eccLen).fill(0);
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ res[0];
      res.shift(); res.push(0);
      for (var j = 0; j < gen.length - 1; j++) {
        res[j] ^= gfMul(gen[j + 1], factor);
      }
    }
    return res;
  }

  function pickVersion(byteLen) {
    for (var v = 1; v <= 10; v++) {
      var spec = QR_ECC_M_BLOCKS[v];
      var dataCw = spec[2] * spec[3] + spec[4] * spec[5];
      var lenBits = v < 10 ? 8 : 16;
      var needBits = 4 + lenBits + byteLen * 8;
      if (needBits <= dataCw * 8) return v;
    }
    return 0;
  }

  // ══ نمط الحروف والأرقام ══
  //
  // 45 رمز بس (أرقام وحروف كبيرة وشوية علامات)، بس حرفين منهم
  // بيتكتبوا في 11 بتّة بدل 16. يعني توفير 30%.
  //
  // ⚠ والتوفير ده هو كل الحكاية: بينزّل الرمز من نسخة 3
  // (29 مربع) لنسخة 1 (21 مربع). ومربعات أقل = كل مربع أكبر
  // = الطابعة بتطبعه بعدد نقط صحيح بدل ما تقرّب.
  var ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

  function isAlnum(text) {
    for (var i = 0; i < text.length; i++) {
      if (ALNUM.indexOf(text.charAt(i)) < 0) return false;
    }
    return text.length > 0;
  }

  function pickVersionAlnum(len) {
    var caps = { 1: 20, 2: 38, 3: 61, 4: 90, 5: 122, 6: 154, 7: 178, 8: 221, 9: 262, 10: 311 };
    for (var v = 1; v <= 10; v++) if (len <= caps[v]) return v;
    return 0;
  }

  function buildCodewords(bytes, version) {
    var spec = QR_ECC_M_BLOCKS[version];
    var eccLen = spec[1];
    var dataCw = spec[2] * spec[3] + spec[4] * spec[5];

    var bits = [];
    function push(val, len) {
      for (var i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }

    if (typeof bytes === 'string') {
      push(2, 4);
      push(bytes.length, version < 10 ? 9 : 11);
      for (var a = 0; a + 1 < bytes.length; a += 2) {
        push(ALNUM.indexOf(bytes.charAt(a)) * 45 + ALNUM.indexOf(bytes.charAt(a + 1)), 11);
      }
      if (bytes.length % 2) push(ALNUM.indexOf(bytes.charAt(bytes.length - 1)), 6);
    } else {
      push(4, 4);                                 // نمط البايت
      push(bytes.length, version < 10 ? 8 : 16);
      for (var i = 0; i < bytes.length; i++) push(bytes[i], 8);
    }

    // منهي + حشو للبايت
    var term = Math.min(4, dataCw * 8 - bits.length);
    push(0, term);
    while (bits.length % 8 !== 0) bits.push(0);

    var data = [];
    for (var b = 0; b < bits.length; b += 8) {
      var v = 0;
      for (var k = 0; k < 8; k++) v = (v << 1) | bits[b + k];
      data.push(v);
    }
    var pad = [0xec, 0x11], pi = 0;
    while (data.length < dataCw) { data.push(pad[pi % 2]); pi++; }

    // تقسيم لبلوكات
    var blocks = [], eccBlocks = [], idx = 0;
    function take(count, size) {
      for (var n = 0; n < count; n++) {
        var chunk = data.slice(idx, idx + size);
        idx += size;
        blocks.push(chunk);
        eccBlocks.push(rsEncode(chunk, eccLen));
      }
    }
    take(spec[2], spec[3]);
    if (spec[4]) take(spec[4], spec[5]);

    // تشبيك
    var out = [], maxData = Math.max(spec[3], spec[5] || 0);
    for (var c = 0; c < maxData; c++) {
      for (var bl = 0; bl < blocks.length; bl++) {
        if (c < blocks[bl].length) out.push(blocks[bl][c]);
      }
    }
    for (var e = 0; e < eccLen; e++) {
      for (var bl2 = 0; bl2 < eccBlocks.length; bl2++) out.push(eccBlocks[bl2][e]);
    }
    return out;
  }

  function makeMatrix(version) {
    var size = version * 4 + 17;
    var m = [], reserved = [];
    for (var r = 0; r < size; r++) {
      m.push(new Array(size).fill(0));
      reserved.push(new Array(size).fill(false));
    }

    function finder(row, col) {
      for (var r = -1; r <= 7; r++) {
        for (var c = -1; c <= 7; c++) {
          var rr = row + r, cc = col + c;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          var on = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                   (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                   (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          m[rr][cc] = on ? 1 : 0;
          reserved[rr][cc] = true;
        }
      }
    }
    finder(0, 0); finder(0, size - 7); finder(size - 7, 0);

    // توقيت
    for (var i = 8; i < size - 8; i++) {
      m[6][i] = i % 2 === 0 ? 1 : 0; reserved[6][i] = true;
      m[i][6] = i % 2 === 0 ? 1 : 0; reserved[i][6] = true;
    }

    // محاذاة
    var pos = ALIGN_POS[version];
    for (var a = 0; a < pos.length; a++) {
      for (var b = 0; b < pos.length; b++) {
        var pr = pos[a], pc = pos[b];
        if (reserved[pr][pc]) continue;
        for (var dr = -2; dr <= 2; dr++) {
          for (var dc = -2; dc <= 2; dc++) {
            m[pr + dr][pc + dc] =
              (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) ? 1 : 0;
            reserved[pr + dr][pc + dc] = true;
          }
        }
      }
    }

    // وحدة داكنة + حجز معلومات الصيغة
    m[size - 8][8] = 1; reserved[size - 8][8] = true;
    for (var f = 0; f <= 8; f++) {
      if (!reserved[8][f]) reserved[8][f] = true;
      if (!reserved[f][8]) reserved[f][8] = true;
    }
    for (var g = 0; g < 8; g++) {
      reserved[8][size - 1 - g] = true;
      reserved[size - 1 - g][8] = true;
    }
    return { m: m, reserved: reserved, size: size };
  }

  function placeData(grid, codewords) {
    var m = grid.m, reserved = grid.reserved, size = grid.size;
    var bitIdx = 0, total = codewords.length * 8;
    var col = size - 1, up = true;

    while (col > 0) {
      if (col === 6) col--;
      for (var n = 0; n < size; n++) {
        var row = up ? size - 1 - n : n;
        for (var s = 0; s < 2; s++) {
          var c = col - s;
          if (reserved[row][c]) continue;
          var bit = 0;
          if (bitIdx < total) {
            bit = (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
          }
          bitIdx++;
          m[row][c] = bit;
        }
      }
      up = !up;
      col -= 2;
    }
  }

  function maskFn(id, r, c) {
    switch (id) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    }
  }

  function applyMask(grid, id) {
    var out = [];
    for (var r = 0; r < grid.size; r++) {
      out.push(grid.m[r].slice());
      for (var c = 0; c < grid.size; c++) {
        if (!grid.reserved[r][c] && maskFn(id, r, c)) out[r][c] ^= 1;
      }
    }
    return out;
  }

  function formatBits(maskId) {
    // ECC M = 00
    var data = (0 << 3) | maskId;
    var rem = data;
    for (var i = 0; i < 10; i++) {
      rem = (rem << 1);
      if (rem & 0x400) rem ^= 0x537;
    }
    return ((data << 10) | rem) ^ 0x5412;
  }

  function placeFormat(matrix, size, maskId) {
    var bits = formatBits(maskId);
    for (var i = 0; i < 15; i++) {
      var bit = (bits >> i) & 1;
      // النسخة الأولى حوالين الزاوية الشمال-فوق
      if (i < 6) matrix[8][i] = bit;
      else if (i === 6) matrix[8][7] = bit;
      else if (i === 7) matrix[8][8] = bit;
      else if (i === 8) matrix[7][8] = bit;
      else matrix[14 - i][8] = bit;
      // النسخة التانية
      if (i < 8) matrix[size - 1 - i][8] = bit;
      else matrix[8][size - 15 + i] = bit;
    }
    matrix[size - 8][8] = 1;
  }

  function penalty(matrix, size) {
    var score = 0, r, c, i;
    // 1) خطوط متتالية
    for (r = 0; r < size; r++) {
      for (var dir = 0; dir < 2; dir++) {
        var run = 1, prev = -1;
        for (c = 0; c < size; c++) {
          var v = dir === 0 ? matrix[r][c] : matrix[c][r];
          if (v === prev) { run++; if (run === 5) score += 3; else if (run > 5) score++; }
          else { run = 1; prev = v; }
        }
      }
    }
    // 2) مربعات 2×2
    for (r = 0; r < size - 1; r++) {
      for (c = 0; c < size - 1; c++) {
        var a = matrix[r][c];
        if (a === matrix[r][c + 1] && a === matrix[r + 1][c] && a === matrix[r + 1][c + 1]) score += 3;
      }
    }
    // 3) نمط 1011101 مع فراغ
    var pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    var pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    function match(get, len) {
      for (var s = 0; s + 11 <= len; s++) {
        var ok1 = true, ok2 = true;
        for (var k = 0; k < 11; k++) {
          var v = get(s + k);
          if (v !== pat1[k]) ok1 = false;
          if (v !== pat2[k]) ok2 = false;
        }
        if (ok1 || ok2) score += 40;
      }
    }
    for (r = 0; r < size; r++) {
      (function (row) { match(function (i2) { return matrix[row][i2]; }, size); })(r);
      (function (col) { match(function (i2) { return matrix[i2][col]; }, size); })(r);
    }
    // 4) نسبة الداكن
    var dark = 0;
    for (r = 0; r < size; r++) for (c = 0; c < size; c++) dark += matrix[r][c];
    var pct = (dark * 100) / (size * size);
    score += Math.floor(Math.abs(pct - 50) / 5) * 10;
    return score;
  }

  function qrMatrix(text) {
    // ⚠ الاختيار تلقائي ومفيش حاجة بتضيع: القارئ بيعرف النمط
    // من أول 4 بتّات جوّه الرمز نفسه. فالرموز القديمة اللي
    // اتطبعت بنمط البايت تفضل مقروءة عادي.
    if (isAlnum(text)) {
      var av = pickVersionAlnum(text.length);
      if (av) {
        var acw = buildCodewords(text, av);
        var ag = makeMatrix(av);
        placeData(ag, acw);
        var ab = null, abs = Infinity;
        for (var am = 0; am < 8; am++) {
          var ac = applyMask(ag, am);
          placeFormat(ac, ag.size, am);
          var asc = penalty(ac, ag.size);
          if (asc < abs) { abs = asc; ab = ac; }
        }
        return { matrix: ab, size: ag.size, version: av };
      }
    }

    var bytes = [];
    for (var i = 0; i < text.length; i++) {
      var cp = text.charCodeAt(i);
      if (cp < 128) bytes.push(cp);
      else if (cp < 2048) { bytes.push(192 | (cp >> 6), 128 | (cp & 63)); }
      else { bytes.push(224 | (cp >> 12), 128 | ((cp >> 6) & 63), 128 | (cp & 63)); }
    }
    var version = pickVersion(bytes.length);
    if (!version) return null;

    var codewords = buildCodewords(bytes, version);
    var grid = makeMatrix(version);
    placeData(grid, codewords);

    var best = null, bestScore = Infinity;
    for (var mk = 0; mk < 8; mk++) {
      var cand = applyMask(grid, mk);
      placeFormat(cand, grid.size, mk);
      var sc = penalty(cand, grid.size);
      if (sc < bestScore) { bestScore = sc; best = cand; }
    }
    return { matrix: best, size: grid.size, version: version };
  }

  function qrSvg(text, sizeMm) {
    var res = qrMatrix(String(text || ''));
    if (!res) return '';
    // ⚠ الهامش الصامت 4 مربعات — ده اللي المواصفة بتطلبه.
    // كان 2، والقارئ بيتعب في تحديد حدود الرمز من غيره.
    var q = 4, dim = res.size + q * 2, rects = '';
    for (var r = 0; r < res.size; r++) {
      for (var c = 0; c < res.size; c++) {
        if (res.matrix[r][c]) {
          rects += '<rect x="' + (c + q) + '" y="' + (r + q) + '" width="1" height="1"/>';
        }
      }
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + sizeMm + 'mm" height="' + sizeMm +
      'mm" viewBox="0 0 ' + dim + ' ' + dim + '" shape-rendering="crispEdges" fill="#000">' +
      '<rect x="0" y="0" width="' + dim + '" height="' + dim + '" fill="#fff"/>' + rects + '</svg>';
  }

  window.qrSvg = qrSvg;

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
  window.printHtml = function (inner, pageMm) {
    var root = document.getElementById('print-root');
    if (!root) return;

    // ══ ⚠ مقاس الورقة بيتحقن وقت الطباعة، مش مكتوب في الأنماط ══
    //
    // القاعدة @page واحدة للصفحة كلها، ومينفعش تتغيّر حسب اللي
    // بتطبعه. والفاتورة والملصق مقاسهم مختلف تمامًا.
    //
    // فبنحطّ عنصر أنماط مؤقت قبل الطباعة ونشيله بعدها. لو
    // سبناه، أول فاتورة بعد ملصق هتتطبع على ورقة ٣٧ مم.
    var sizeTag = document.getElementById('print-page-size');
    if (sizeTag) sizeTag.remove();
    if (pageMm) {
      sizeTag = document.createElement('style');
      sizeTag.id = 'print-page-size';
      // ⚠⚠ تصفير @page **مش كفاية**، ودي الغلطة اللي طلّعت
      // الملصق على ورقتين.
      //
      // @page بتصفّر هامش **الورقة**. لكن body عنده هامش
      // افتراضي من المتصفح (8px كل جنب) وهو حاجة تانية خالص.
      // على ورقة 37 مم، الـ16px دول بياكلوا 4.2 مم — فالمساحة
      // بتبقى 32.8، والملصق 37، فبيفيض والمتصفح بيدفع ورقة
      // تانية للي فاض.
      //
      // ⚠ والقاعدة العامة: بنصفّر بـ!important عشان أنماط
      // التطبيق (اللي بتتحمّل قبلنا) ما تغلبناش.
      sizeTag.textContent =
        '@page{size:' + pageMm[0] + 'mm ' + pageMm[1] + 'mm;margin:0}' +
        'html,body{margin:0 !important;padding:0 !important;' +
        'width:auto !important;background:#fff !important}' +
        '#print-root{margin:0 !important;padding:0 !important;' +
        'width:' + pageMm[0] + 'mm !important}' +
        // ⚠ الملصق نفسه من غير أي هامش خارجي: أي مليمتر هنا
        // بيتزوّد على الـ37 وبيرجّع نفس المشكلة.
        '.pr-label{margin:0 !important}';
      document.head.appendChild(sizeTag);
    }

    root.innerHTML = inner;
    // مهلة قصيرة عشان المتصفح يرسم المحتوى قبل ما يفتح الحوار
    setTimeout(function () {
      window.print();
      setTimeout(function () {
        root.innerHTML = '';
        var tag = document.getElementById('print-page-size');
        if (tag) tag.remove();
      }, 400);
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
    // ⚠ مصدرين مش واحد.
    //
    // المكتبة دي هي **الطريق الوحيد** للمسح على الأيفون (مفيش
    // كاشف مدمج في محرك سفاري). فلو المصدر الأول مقفول — شبكة
    // محل، أو مانع إعلانات، أو المصدر نفسه واقع — الماسح
    // بيتعطّل خالص.
    //
    // ⚠ ولاحظ إن الفشل هنا بيبان: بنرمي رسالة واضحة. الحاجة
    // الوحيدة اللي بتتقبل السكوت هي الإطار اللي مفيهوش باركود.
    var SOURCES = [
      'https://cdn.jsdelivr.net/npm/@zxing/library@0.21.3/umd/index.min.js',
      'https://unpkg.com/@zxing/library@0.21.3/umd/index.min.js'
    ];

    zxingReady = new Promise(function (resolve, reject) {
      var at = 0;
      function attempt() {
        if (at >= SOURCES.length) { reject(new Error('cdn')); return; }
        var tag = document.createElement('script');
        tag.src = SOURCES[at++];
        tag.onload = function () {
          if (window.ZXing) resolve(window.ZXing);
          else attempt();
        };
        tag.onerror = function () { attempt(); };
        document.head.appendChild(tag);
      }
      attempt();
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
        // ⚠ مخرج يدوي دايمًا موجود.
        //
        // الماسح بيعتمد على كاميرا وإضاءة ومكتبة من الإنترنت —
        // تلات حاجات ممكن تخذلك والزبون واقف قدامك. الزرار ده
        // بيخلّي أسوأ حالة "اكتبه بإيدك" مش "اقفل وارجع بعدين".
        '<button class="btn-mini" type="button" data-scan-manual>اكتبه بإيدك</button>' +
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

    var manualValue = null;
    overlay.querySelector('[data-scan-manual]').addEventListener('click', function () {
      var typed = prompt('اكتب الرقم:');
      if (typed && typed.trim()) { manualValue = typed.trim(); }
      cleanup();
    });

    try {
      // ══ ⚠ الدقة مطلوبة صراحةً، والافتراضي مش كفاية ══
      //
      // من غير طلب، المتصفح بيدّي 640×480 غالبًا. ومربع الرمز
      // على الملصق نصف مليمتر — فبيوصل الكاميرا **بيكسلين**،
      // والقارئ محتاج تلاتة على الأقل.
      //
      // يعني الماسح كان بيشتغل صح وبيبصّ على صورة مالهاش معنى.
      //
      // ⚠ وبنطلب المفضّل مش الإجباري: لو الكاميرا ما تقدرش، بتدّي أقرب
      // حاجة بدل ما ترفض وتسيبنا بلا كاميرا خالص.
      stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: 'environment',
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          // التركيز المستمر — الملصق بيتقرا من 10 سم، والكاميرا
          // بتفضل مركّزة على البعيد لو ما طلبناش
          focusMode: 'continuous'
        }
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
        var nativeWorked = await new Promise(function (resolve) {
          var fails = 0;
          var timer = setInterval(async function () {
            if (stopped) { clearInterval(timer); resolve(null); return; }
            try {
              var found = await det.detect(video);
              fails = 0;
              if (found && found.length) {
                clearInterval(timer);
                resolve(found[0].rawValue);
              }
            } catch (e) {
              // ⚠ الفشل المتكرر معناه إن الكاشف المدمج مش
              // شغّال فعليًا (صيغة مش مدعومة، أو منّفذ ناقص).
              // من غير العدّاد ده كان بيفضل يلفّ للأبد والزرار
              // ساكت — والسكوت أوحش من الرفض.
              fails++;
              if (fails >= 12) { clearInterval(timer); resolve(null); }
            }
          }, 220);
        });

        if (nativeWorked) { cleanup(); return nativeWorked; }
        // ⚠ نفس معالجة الكتابة اليدوية في المسارين. لو حطّيناها
        // في واحد بس، الزرار يشتغل على الأيفون ويسكت على
        // الأندرويد — وده أوحش من إنه مش موجود خالص.
        if (manualValue) { cleanup(); return manualValue; }
        if (stopped) throw new Error('أُلغي المسح.');
        // ما اشتغلش — بنكمّل للمكتبة تحت
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

    // ══ ⚠ بنسحب الإطارات بإيدنا، ومش بنسلّم الفيديو للمكتبة ══
    //
    // ══ الغلطة اللي كانت هنا ══
    // كنا بننادي decodeFromVideoElement. الدالة دي بتستنّى
    // إشارة إن الفيديو **بدأ يشتغل** — وإحنا شغّلناه بإيدنا
    // فوق بـplay(). فالإشارة حصلت **قبل** ما المكتبة تستنّاها،
    // وهي فضلت مستنّية حاجة عدّت خلاص.
    //
    // النتيجة: الكاميرا بتفتح، والصورة بتبان، والحلقة **ما
    // بتبدأش أصلاً**. ومفيش رسالة خطأ لأن مفيش حاجة فشلت —
    // فيه حاجة ما ابتدتش.
    //
    // تشبيه: تقول للمدرب "نبّهني أول ما الجرس يرنّ" بعد ما رنّ.
    //
    // ⚠ الحل: نرسم الإطار على لوحة إحنا مالكينها، وننادي
    // القارئ عليها. مفيش أي اعتماد على دورة حياة الفيديو.
    var hints = new Map();
    hints.set(ZX.DecodeHintType.POSSIBLE_FORMATS, [
      ZX.BarcodeFormat.QR_CODE,
      ZX.BarcodeFormat.CODE_128,
      ZX.BarcodeFormat.CODE_39,
      ZX.BarcodeFormat.EAN_13,
      ZX.BarcodeFormat.EAN_8,
      ZX.BarcodeFormat.UPC_A,
      ZX.BarcodeFormat.ITF
    ]);
    // ⚠ محاولة أعمق لكل إطار. أبطأ، بس إحنا بنفحص 4 إطارات في
    // الثانية مش 60 — فالبطء مش محسوس والفرق في القراءة كبير.
    hints.set(ZX.DecodeHintType.TRY_HARDER, true);

    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');
    var reader = new ZX.BrowserMultiFormatReader(hints);
    var hintEl = overlay.querySelector('.scan-hint');

    return await new Promise(function (resolve, reject) {
      var frames = 0;

      var timer = setInterval(function () {
        if (stopped) {
          clearInterval(timer);
          // ⚠ لو كتبه بإيده، ده نجاح مش إلغاء
          if (manualValue) resolve(manualValue);
          else reject(new Error('أُلغي المسح.'));
          return;
        }

        var w = video.videoWidth, h = video.videoHeight;
        // الإطار لسه ما وصلش — نستنّى من غير ما نعدّ محاولة
        if (!w || !h) return;

        canvas.width = w;
        canvas.height = h;
        ctx.drawImage(video, 0, 0, w, h);

        try {
          var result = reader.decodeFromCanvas(canvas);
          if (result) {
            clearInterval(timer);
            var value = result.getText();
            cleanup();
            resolve(value);
            return;
          }
        } catch (e) {
          // ⚠ المكتبة بترمي استثناء لكل إطار مفيهوش باركود.
          // ده السلوك الطبيعي مش عطل — بنتجاهله ونكمّل.
        }

        // ⚠ تلميحة بعد 6 ثواني بدل شاشة صامتة.
        // الماسح اللي بيفضل مفتوح من غير ما يقول حاجة بيخلّي
        // الواحد يفتكر إنه باظ ويقفله.
        frames++;
        if (frames === 24 && hintEl) {
          hintEl.textContent = 'قرّب الكاميرا 10 سم وثبّتها، وخلّي الإضاءة على الرمز.';
        }
      }, 250);
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
  // ⚠ الوزن 700 في JetBrains Mono اتضاف عشان **الملصق**.
  //
  // السريال والسعر بيتكتبوا بالخط ده، والملصق بيطلبهم عريضين.
  // من غير الوزن ده المتصفح بيزوّر العرض بنفسه (بيتخّن الحروف
  // برمجيًا) — وعلى الطابعة الحرارية التزوير بيطلع مطخطخ لأن
  // التخانة المزوّرة مش بتقع على حدود النقط.
  'https://fonts.googleapis.com/css2?family=Reem+Kufi:wght@600&family=El+Messiri:wght@500;600;700&family=Alexandria:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap';

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
 * مع المبيعات، الخزنة مع الحركات، الراتب مع السُلف. الرمز نفسه
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
 * الشركات اللي بتبني بضاعة لغيرها بتسيب توقيعها **جوّه** المنتج،
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
        <span class="tabbar-icon" aria-hidden="true">▦</span>البضاعة
      </a>`
    : ''}
  ${access.showTreasury
    ? html`<a href="/treasury" ${active === 'treasury' ? raw('aria-current="page"') : ''}>
        <span class="tabbar-icon" aria-hidden="true">₤</span>الخزنة
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
// ══════════ الأرقام إنجليزي في النظام كله ══════════
//
// ══ المشكلة ══
// لوحة المفاتيح العربية على الموبايل بتكتب ٠١٢٣ افتراضيًا.
// والخادم بيطبّعها في دالة الفلوس، بس المستخدم بيفضل
// شايف رقم عربي في الخانة — فمش عارف إيه اللي هيتحفظ.
//
// ⚠ وأوحش من كده: الحقول اللي مش بتعدّي على دالة الفلوس
// (السريال · الموديل · التليفون) بتتحفظ **بالعربي زي ما هي**،
// فبيبقى عندك سريال "١٢٣" وسريال "123" وهما نفس الجهاز.
//
// ══ الحل ══
// التحويل بيحصل **وقت الكتابة** في كل خانة في النظام. اللي
// بتشوفه هو اللي هيتحفظ.
//
// ⚠ وبيحافظ على مكان المؤشر. من غير كده، الكتابة في نص النص
// كانت بترمي المؤشر لآخر الخانة بعد كل حرف.
(function () {
  var AR = /[\u0660-\u0669\u06F0-\u06F9]/;

  function toLatin(text) {
    return String(text)
      .replace(/[\u0660-\u0669]/g, function (d) {
        return String(d.charCodeAt(0) - 0x0660);
      })
      .replace(/[\u06F0-\u06F9]/g, function (d) {
        return String(d.charCodeAt(0) - 0x06F0);
      });
  }

  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!el || (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA')) return;
    if (typeof el.value !== 'string' || !AR.test(el.value)) return;

    // ⚠ الطول ما بيتغيّرش (رقم برقم)، فمكان المؤشر بيفضل صحيح.
    var at = el.selectionStart;
    el.value = toLatin(el.value);
    try { el.setSelectionRange(at, at); } catch (err) { /* حقل ما بيدعمش التحديد */ }
  });
})();

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
  // ══ ⚠ البيع والبضاعة والخزنة **مش هنا** عن قصد ══
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

  // ⚠ التقرير بعد الخزنة عن قصد: الخزنة بتتفتح كل يوم،
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
      <span class="tile-note">ديون عليك</span>
    </a>`);

    // ⚠ جنب الموردين مباشرةً، والوصف بيفرّق بينهم بكلمة واحدة:
    // "عليك" و"ليك". الاتنين دفتر ديون، والخلط بينهم بيخلّي
    // الواحد يفتح الشاشة الغلط ويفتكر الأرقام بتاعته.
    tiles.push(html`<a class="tile" href="/shops">
      <span class="tile-label">حساب المحلات</span>
      <span class="tile-note">ديون ليك</span>
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
        اختر البضاعة، وحدّد الخزنة، وأتمم الفاتورة.<br>
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
      // شاشة البضاعة — الشريط تنبيه مش تقرير.
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

// ═══════════════════ 5) الخزنة ═══════════════════

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

  /** صاحب المحل — بيضيف خزن ويختار الفرع */
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
      ? html`<p class="muted">لا توجد خزن بعد.</p>`
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
   *   بالفرع  → كل فرع فيه كام، ومقسّمة على خزنه
   *   الإجمالي → المجموع
   */
  const summaryHtml = html`
    <div class="balances">
      ${data.summary.byType.map(
        (t) => html`<div class="bal-card">
          <span class="bal-name">${t.label}</span>
          <span class="bal-meta">${t.count} خزنة</span>
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
    title: 'الخزنة',
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
          <summary>تحويل بين الخزن</summary>
          <div class="panel-body">
            <p class="muted">
              اكتب المبلغ الذي خرج والمبلغ الذي وصل. الفرق بينهما يُحسب عمولة تلقائيًا.
            </p>

            <div class="field">
              <label class="field-label" for="tr-from">من خزنة</label>
              <select class="field-input" id="tr-from">
                ${data.summary.rows
                  .filter((r) => r.isActive)
                  .map((r) => html`<option value="${r.treasuryId}">${treasuryLabel(r)}</option>`)}
              </select>
            </div>

            <div class="field">
              <label class="field-label" for="tr-to">إلى خزنة</label>
              <select class="field-input" id="tr-to">
                ${data.summary.rows
                  .filter((r) => r.isActive)
                  .map((r) => html`<option value="${r.treasuryId}">${treasuryLabel(r)}</option>`)}
              </select>
              <p class="field-hint">لا بد أن تكون الخزنتان في نفس الفرع.</p>
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
          <summary>إضافة خزنة</summary>
          <div class="panel-body">
            <p class="muted">
              كل وسيلة دفع خزنة مستقلة. يمكن إنشاء أكثر من واحدة من النوع نفسه —
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
              <label class="field-label" for="tz-name">اسم الخزنة</label>
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

           صاحب المحل بيشوف خزن **كل فروعه** في قايمة واحدة،
           وكلها اسمها "نقدي" بعد توحيد التسمية. فبيسجّل مصروف
           فرع على خزنة فرع تاني — والحركة بتعدي عادي، لأن
           صاحب المحل من حقه فعلاً يصرف من أي خزنة.

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
            <p class="field-hint">تظهر لك خزن هذا الفرع وحدها.</p>
          </div>`
        : ''}

      <div class="field">
        <label class="field-label" for="mv-treasury">الخزنة</label>
        <select class="field-input" id="mv-treasury" required>
          ${data.balances.map((b) => {
            // ⚠ الفرع بيتقرا من `summary.rows` مش من `balances`.
            // الاتنين بيوصفوا نفس الخزن، بس الملخّص وحده اللي
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

          <!-- ══ ⚠ «شراء بضاعة» متشالة **مؤقتًا** ══
               الرجوع = شيل التعليق عن السطر اللي تحت. وبس.

               ⚠ ومتشالة بالتعليق مش بالمسح عن قصد: كل منطقها
               (خانات الصنف والكمية والمورّد، ومسار /api/purchases)
               لسه مكانه وشغّال. مسحه كان هيخلّي الرجوع شغل نص
               ساعة بدل سطر.

               ⚠⚠ وطول ما هي متشالة: مفيش طريقة تسجّل شرا بضاعة
               من شاشة الخزنة خالص. سبب الصرف «شراء بضاعة» مخفي
               من قايمة الأسباب لأن النوع ده كان موجود.
               الطريق الوحيد دلوقتي: شاشة البضاعة ← إضافة منتج ←
               التكلفة «اتدفعت». -->
          <!-- <option value="PURCHASE">شراء بضاعة</option> -->

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
        <!-- ⚠ الزرار لمن يقدر يعتمد المصروفات بس.

             سبب الصرف مش بيان على الحركة — هو بند في قائمة
             الدخل، وتفصيل المصروفات بيتجمّع بيه.

             لو كل موظّف زوّد بند، هتلاقي "نثرية" و"نثريات"
             و"فطار" و"فطار الصبح" — والتقرير يبقى عشرين سطر
             بجنيهات وصاحب المحل يبطّل يقراه. -->
        ${data.canApprove
          ? html`<button class="btn-mini" type="button" id="reason-add">
              + سبب جديد
            </button>`
          : ''}
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
          <option value="IN">زيادة في الخزنة</option>
          <option value="OUT">نقص في الخزنة</option>
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
        التوريد يتم من شاشة البضاعة.
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
   * ⚠ مش مع الصفحة: أغلب فتحات شاشة الخزنة مصروف أو سُلفة،
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

  // ── سبب صرف جديد ──
  //
  // ⚠ الزرار موجود في الشاشة لمن يقدر يعتمد بس، والخادم بيفحص
  // تاني. إخفاء الزرار مش حماية — أي حد يقدر ينادي المسار من
  // المتصفح على طول.
  (function () {
    var addBtn = document.getElementById('reason-add');
    var reasonEl = document.getElementById('mv-reason');
    if (!addBtn || !reasonEl) return;

    addBtn.addEventListener('click', async function () {
      var name = prompt('اسم سبب الصرف الجديد؟');
      if (name === null) return;
      name = name.trim();
      if (!name) return;

      addBtn.disabled = true;
      try {
        var res = await fetch('/api/treasury/expense-reasons', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ name: name })
        });
        var data = await res.json();
        if (!res.ok || !data.ok) {
          say((data.error && data.error.message) || 'تعذّر إضافة السبب.', false);
          return;
        }

        // ⚠ بنضيف الخيار ونختاره على طول بدل تحديث الصفحة.
        //
        // المستخدم واقف في نص تسجيل حركة: المبلغ مكتوب والخزنة
        // متختارة. التحديث كان هيمسح شغله عشان يضيف سبب.
        var opt = document.createElement('option');
        opt.value = data.id;
        opt.textContent = name;
        reasonEl.appendChild(opt);
        reasonEl.value = data.id;
        say('اتضاف السبب.', true);
      } catch (err) {
        say('تعذّر الاتصال بالخادم.', false);
      } finally {
        addBtn.disabled = false;
      }
    });
  })();

  // ── الفرع يضيّق قايمة الخزن ──
  //
  // ⚠ الخزن بتتشال من القايمة مش بتتخبّى بس. «hidden» على
  // «option» مش مضمون في كل المتصفحات، وخزنة شكلها مختارة وهي
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

      // لو المختار بقى من فرع تاني، ننقل لأول خزنة صالحة
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
    // واحدة: حركة الخزنة وبيانها. لو بعتناه لمسار الحركات
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

  // ══════════ التحويل بين الخزن ══════════
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
        say('اختر خزنتين مختلفتين.', false);
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

  // ══════════ إضافة خزنة ══════════
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
        say('اكتب اسم الخزنة.', false);
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
  /**
   * ⚠ الحقول التلاتة الأخيرة كانت موجودة في الخادم وما كانتش
   * بتتبعت للشاشة. من غيرها، البيع كان بيوري كومة مسطّحة
   * والبضاعة عندها أدراج — نفس البضاعة بمنظّمين مختلفين.
   */
  products: Array<{
    id: string;
    name: string;
    productType: 'device' | 'accessory';
    serialNumber: string | null;
    /** null = يطلب النظام السعر يدويًا وقت البيع */
    pricePiastres: number | null;
    quantityOnHand: number;
    branchId: string;
    categoryId: string | null;
    modelId: string | null;
    colorId: string | null;
    /** مشتقّ مش مسجّل — الشريط بيتبني من الصفوف الموجودة */
    storageCapacity: string | null;
    customsCleared: boolean;
  }>;
  /**
   * سجلات الفلترة — نفس اللي في شاشة البضاعة بالحرف.
   *
   * ⚠ ومفيش زرار «+» في أي شريط منهم هنا، وده مقصود: البيع
   * مش مكان إنشاء درج ولا موديل ولا لون. الكاشير بيختار من
   * الموجود، والإنشاء قرار تنظيم مكانه شاشة البضاعة.
   */
  categories: Array<{ id: string; name: string; parentId: string | null }>;
  models: Array<{ id: string; name: string; family: string | null }>;
  colors: Array<{ id: string; name: string; hex: string | null }>;
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
  /**
   * حسابات المحلات — لخروج البضاعة أجل.
   *
   * ⚠ الاسم والمعرّف بس، بلا أرصدة. الشاشة دي بتخرّج بضاعة،
   * مش بتعرض ديون — والرصيد معلومة مالية مالهاش لزوم هنا.
   */
  shopAccounts: Array<{ id: string; name: string }>;
  /** supplier.manage — بيتحكم في ظهور قسم الخروج أجل */
  canConsign: boolean;
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
 * • البضاعة مربّعات كبيرة مش قايمة: الضغط بالإبهام على شاشة
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
        <p class="empty-title">لا توجد بضاعة متاحة</p>
        <p class="empty-note">
          إمّا أن البضاعة لم تُضَف بعد، أو أن الكميات نفدت.<br>
          يضيفها المدير ويورّدها من شاشة البضاعة.
        </p>
      </div>`
    : html`<div class="prod-grid" id="prod-grid">
        ${data.products.map(
          (p) => html`<button class="prod-btn" type="button"
            data-add="${p.id}"
            data-name="${p.name}"
            data-branch="${p.branchId}"
            data-price="${p.pricePiastres === null ? '' : String(p.pricePiastres)}"
            data-max="${String(p.quantityOnHand)}"
            data-type="${p.productType}"
            data-cat="${p.categoryId ?? '__none__'}"
            data-model="${p.modelId ?? '__none__'}"
            data-color="${p.colorId ?? '__none__'}"
            data-storage="${p.storageCapacity ?? '__none__'}"
            data-customs="${p.customsCleared ? 'true' : 'false'}"
            data-searchable="${[p.name, p.serialNumber ?? ''].join(' ')}">
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
        لا توجد خزنة متاحة لفرعك، ولا يمكن إتمام فاتورة من دونها. راجع المالك لإضافة خزنة للفرع.
      </span></div>`
    : ''}

  ${data.canConsign
    ? html`<!-- ══ ⚠ خروج بضاعة أجل — دفتر مستقل عن البيع ══

         البضاعة بتخرج من المخزون، والدين بيتسجّل على المحل،
         و**قائمة الدخل ما بتشوفش حاجة**.

         يعني بضاعة بمية ألف تخرج النهاردة وتقرير الشهر بيقول
         إنك ما بعتش. الربح بيظهر لما المحل يسدّد.

         ⚠ وبين الخروج والسداد، البضاعة مش في المخزون ومش في
         الإيراد — هي في المكان التالت. وشاشة حساب المحلات هي
         المكان ده. لو اتسابت شهر، البضاعة بتضيع من الحسبة.

         ⚠ وقبل إتمام البيع عن قصد: الاتنين بياخدوا من نفس
         السلة، والخروج قرار مختلف عن البيع — فلازم يبان
         قبل ما الإيد تمتد لزرار "تم البيع". -->
      <details class="panel">
        <summary>خروج بضاعة أجل</summary>
        <div class="panel-body">
          <p class="field-hint">
            البضاعة تخرج من المخزون ويُفتح بها دين على المحل.
            لا تدخل المبيعات ولا الأرباح — تظهر في «حساب المحلات».
          </p>

          <div class="field">
            <label class="field-label" for="cg-shop">المحل</label>
            <select class="field-input" id="cg-shop">
              <option value="">— اختر المحل —</option>
              ${data.shopAccounts.map(
                (sh) => html`<option value="${sh.id}">${sh.name}</option>`,
              )}
            </select>
            <button class="btn-mini" type="button" id="cg-shop-add">+ محل جديد</button>
          </div>

          <!-- ⚠ السلة نفسها هي سلة البيع.
               سلّتين منفصلتين معناهم إن الموظّف يحطّ في وحدة
               ويضغط زرار التانية — والشاشة تقول "السلة فاضية"
               وهو شايفها مليانة. -->
          <p class="field-hint" id="cg-cart">السلة فاضية — أضِف أصناف من القائمة تحت.</p>

          <div class="field">
            <label class="field-label" for="cg-note">ملاحظة (اختياري)</label>
            <input class="field-input" id="cg-note" type="text" maxlength="500"
              autocomplete="off" placeholder="اتفاق أو ميعاد سداد">
          </div>

          <button class="btn-mini" type="button" id="cg-go">خروج</button>
        </div>
      </details>`
    : ''}

  <details class="panel" open>
    <summary>إتمام البيع</summary>
    <div class="panel-body">
      <!-- ══ الفرع — لصاحب المحل وحده ══

           ⚠ الخانة دي بتحلّ عطل حقيقي، مش تحسين شكل.

           صاحب المحل بيشوف بضاعة **كل فروعه** في شاشة واحدة،
           وخزن كل فروعه. فكان بيحطّ منتج من فرع ويختار خزنة
           فرع تاني — ودالة قاعدة البيانات بترفض بحق.

           كان فيه ملاحظة مكتوبة تحت الخزنة بتقوله "اختر خزنة
           نفس الفرع". والملاحظة مش حاجز: مفيش حد بيقرا سطر
           رمادي وهو ماسك سلة قدّام زبون.

           دلوقتي الفرع بيتقفل من فوق، والشاشة كلها بتضيق عليه —
           بضاعةه وخزنه. الغلطة بقت **مش ممكنة** بدل ما تكون
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
              تظهر لك بضاعة هذا الفرع وخزنه وحدها. تغيير الفرع يفرّغ السلة.
            </p>
          </div>`
        : ''}

      <div class="field">
        <label class="field-label" for="pos-treasury">الخزنة</label>
        <select class="field-input" id="pos-treasury" ${hasTreasury ? '' : raw('disabled')}>
          ${data.treasuries.map(
            (t) => html`<option value="${t.treasuryId}" data-branch="${t.branchId}">${t.name}</option>`,
          )}
        </select>
        <p class="field-hint">
          تُقرأ وسيلة الدفع من الخزنة نفسها — نقدي، فيزا، إنستاباي.
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

      <!-- ══ ملاحظة الفاتورة ══
           ⚠ الكلام اللي بيتقال على الكاونتر ومالوش خانة:
           "اتفقنا يرجع يغيّر اللون" · "فيه خربوشة ووافق".

           بيضيع دلوقتي، وأول خلاف بعد شهر مفيش حاجة مكتوبة —
           والموظّف اللي باع يمكن يكون مشي.

           ⚠ وما تكتبش فيها فلوس. "دفع 500 والباقي بكرة" ملاحظة
           مفيدة، بس الرقم ده مش داخل أي حساب. -->
      <div class="field">
        <label class="field-label" for="pos-note">ملاحظات (اختياري)</label>
        <input class="field-input" id="pos-note" type="text" maxlength="500"
          autocomplete="off" placeholder="اتفاق أو حالة الجهاز">
        <p class="field-hint">تتسجّل على الفاتورة. مش مكان للمبالغ.</p>
      </div>

      <button class="btn-primary" id="pos-submit" type="button" disabled>تم البيع</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>البضاعة</summary>
    <div class="panel-body">
      ${hasProducts
        ? html`<!-- ══ الأدراج — نفس شاشة البضاعة ══

               ⚠ الشرايط في مكان واحد وبتتبدّل، مش نسخة في كل
               تبويب. نسختين معناهم إن العلامة على الاتنين ممكن
               تختلف — والكاشير يشوف «أسود» مختار في مكان
               و«الكل» في مكان تاني.

               ⚠ ومفيش زرار «+» في أي شريط، على عكس شاشة
               البضاعة. البيع مش مكان إنشاء درج ولا لون. -->
          <div class="tools">
            <button class="tool" type="button" data-postool="cat">
              درج الإكسسوار والمكملات
            </button>
            <button class="tool" type="button" data-postool="iph">درج الآيفون</button>
            <button class="tool" type="button" data-postool="and">درج الأندرويد</button>
            <button class="tool" type="button" data-postool="flt">فلتر</button>
          </div>

          <!-- ⚠ أدوات الفلتر بتتغيّر بالدرج المفتوح:
                 الإكسسوار → اللون · الموديل
                 الأجهزة   → اللون · المساحة · الضريبة
               والمساحة والضريبة مالهمش معنى على جراب. -->
          <div class="tools" id="pos-filter-tools" hidden>
            <button class="tool" type="button" data-possub="color">اللون</button>
            <button class="tool" type="button" data-possub="model" data-for="accessory">
              الموديل
            </button>
            <button class="tool" type="button" data-possub="storage" data-for="device">
              المساحة
            </button>
            <button class="tool" type="button" data-possub="customs" data-for="device">
              الضريبة
            </button>
          </div>

          <div class="row-wrap" id="pos-row-cat" hidden>
            <div class="drawers" id="pos-drawers">
              <button class="drawer" type="button" data-posdrawer="" data-on>الكل</button>
              ${data.categories
                .filter((c) => c.parentId === null)
                .map(
                  (section) => html`${data.categories
                    .filter((d) => d.parentId === section.id)
                    .map(
                      (d) => html`<button class="drawer" type="button"
                        data-posdrawer="${d.id}">${d.name}</button>`,
                    )}`,
                )}
              <button class="drawer" type="button" data-posdrawer="__none__">غير مصنّف</button>
            </div>
          </div>

          <div class="row-wrap" id="pos-row-model" hidden>
            <div class="drawers" id="pos-models">
              <button class="drawer" type="button" data-posmodel="" data-on>الكل</button>
              ${data.models.map(
                (m) => html`<button class="drawer" type="button" data-posmodel="${m.id}"
                  data-family="${m.family ?? '__none__'}">${m.name}</button>`,
              )}
              <button class="drawer" type="button" data-posmodel="__none__">بلا موديل</button>
            </div>
          </div>

          <div class="row-wrap" id="pos-row-color" hidden>
            <div class="drawers" id="pos-colors">
              <button class="drawer" type="button" data-poscolor="" data-on>الكل</button>
              ${data.colors.map(
                (c) => html`<button class="drawer" type="button" data-poscolor="${c.id}">
                  ${c.hex ? html`<span class="dot" style="background:${c.hex}"></span>` : ''}
                  ${c.name}
                </button>`,
              )}
              <button class="drawer" type="button" data-poscolor="__none__">بلا لون</button>
            </div>
          </div>

          <!-- ══ المساحة والضريبة — مشتقّة مش مسجّلة ══
               مالهمش سجل: أعمدة على المنتج نفسه، فالشرايط
               بتتبني من البضاعة المعروضة وقت التحميل. -->
          <div class="row-wrap" id="pos-row-storage" hidden>
            <div class="drawers" id="pos-storages"></div>
          </div>

          <div class="row-wrap" id="pos-row-customs" hidden>
            <div class="drawers" id="pos-customs"></div>
          </div>

          <div class="field">
            <input class="field-input" id="pos-search" type="search"
              placeholder="ابحث بالاسم أو السريال" autocomplete="off">
          </div>
          <p class="field-hint" id="pos-empty-note">
            افتح درج أو ابحث عشان تشوف البضاعة.
          </p>`
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

                      <label class="field-label" for="ret-tre-${s.id}">الخزنة</label>
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

  /**
   * رسالة في شريط الإشعار.
   *
   * ⚠ الشاشة كانت بتكتب في العنصر مباشرةً في أربع أماكن،
   * وكل مرة بتضبط الإخفاء واللون بإيدها. الدالة دي
   * بتوحّدهم — من غيرها أي مكان جديد بينسى واحدة منهم،
   * والرسالة بتظهر بلون النجاح وهي فشل.
   */
  function posSay(message, ok) {
    if (!boxEl || !textEl) return;
    boxEl.hidden = false;
    if (ok) boxEl.setAttribute('data-tone', 'ok');
    else boxEl.removeAttribute('data-tone');
    textEl.textContent = message;
    boxEl.scrollIntoView({ block: 'nearest' });
  }

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
    // ⚠ ملخّص لوحة الخروج بيتحدّث مع كل رسم للسلة.
    // لو حدّثناه في مكان واحد بس، الموظّف يشيل صنف ويلاقي
    // اللوحة لسه بتقول الإجمالي القديم.
    if (typeof paintConsignCart === 'function') paintConsignCart();
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
  var emptyNote = document.getElementById('pos-empty-note');

  // ══════════ حالة الفلاتر ══════════
  //
  // ⚠ نفس الأبعاد اللي في شاشة البضاعة بالحرف، وبنفس أسماء
  // السمات على الصفوف. ده مقصود: يوم ما نوحّد المحرّكين، مفيش
  // حاجة في القوالب هتحتاج تتغيّر.
  var activeMode = '';
  var activeFamily = '';
  var activeDrawer = '';
  var activeModel = '';
  var activeColor = '';
  var activeStorage = '';
  var activeCustoms = '';

  /**
   * المصفاة الواحدة.
   *
   * ⚠ الفرع والبحث والفلاتر كلهم بيتحكّموا في نفس الخاصية.
   * لو كل واحد كتبها لوحده، آخر واحد يشتغل بيدهس على التاني —
   * تبحث فيرجع منتج من فرع تاني، أو تغيّر الفرع فيرجع اللي
   * البحث خبّاه. فالقرار بيتاخد مرة واحدة من كلهم مع بعض.
   */
  function applyFilters() {
    var q = search ? search.value.trim().toLowerCase() : '';
    var branch = branchEl ? branchEl.value : '';

    var btns = document.querySelectorAll('[data-add]');
    var shown = 0;

    for (var i = 0; i < btns.length; i++) {
      var el = btns[i];
      var hay = (el.getAttribute('data-searchable') || el.getAttribute('data-name') || '')
        .toLowerCase();

      var okText = !q || hay.indexOf(q) !== -1;
      var okBranch = !branch || el.getAttribute('data-branch') === branch;
      var okDrawer = !activeDrawer
        || (el.getAttribute('data-cat') || '__none__') === activeDrawer;
      var okModel = !activeModel
        || (el.getAttribute('data-model') || '__none__') === activeModel;
      var okColor = !activeColor
        || (el.getAttribute('data-color') || '__none__') === activeColor;
      var okStorage = !activeStorage
        || (el.getAttribute('data-storage') || '__none__') === activeStorage;
      var okCustoms = !activeCustoms
        || (el.getAttribute('data-customs') || 'false') === activeCustoms;
      var okMode = !activeMode || el.getAttribute('data-type') === activeMode;

      // ══ ⚠ العيلة بتتقرا من **الموديل** مش من المنتج ══
      //
      // المنتج مالوش عمود عيلة، وموديله هو اللي معلّم. فبنجيب
      // موديل الصفّ وندوّر على عيلته في الشريط.
      //
      // ودي اللي بتخلّي تصنيف موديل واحد ينقل كل أجهزته
      // وإكسسواراته للدرج الصح في نفس اللحظة.
      var okFamily = true;
      if (activeFamily) {
        var rowModel = el.getAttribute('data-model') || '';
        var chip = rowModel && rowModel !== '__none__'
          ? document.querySelector('#pos-models [data-posmodel="' + rowModel + '"]')
          : null;
        okFamily = !!chip && chip.getAttribute('data-family') === activeFamily;
      }

      // ══ ⚠ البضاعة مقفولة لحد ما تفتح درج ══
      //
      // قايمة بكل البضاعة من غير درج مفتوح مش قايمة — دي كومة،
      // والكاشير بيمرّر فيها بدل ما يختار.
      //
      // ⚠ والبحث بيفتحها: لو كتبت حاجة، إنت عارف بتدوّر على
      // إيه — فالكومة بتبقى نتيجة مش كومة.
      var browsing = !!activeMode || !!activeDrawer || !!q;

      var match = browsing && okText && okBranch && okMode && okFamily
        && okDrawer && okModel && okColor && okStorage && okCustoms;

      el.hidden = !match;
      if (match) shown++;
    }

    // ⚠ السطر الإرشادي بيختفي أول ما يبان أي منتج. سيبانه
    // فوق نتيجة موجودة بيخلّيه يقرا كإنه رسالة خطأ.
    if (emptyNote) {
      emptyNote.hidden = shown > 0;
      emptyNote.textContent = browsing
        ? 'مفيش بضاعة مطابقة للفلاتر دي.'
        : 'افتح درج أو ابحث عشان تشوف البضاعة.';
    }
  }

  // ══════════ الشرايط ══════════

  /** رجّع صفّ لـ«الكل» */
  function posClearRow(id, attr) {
    var el = document.getElementById(id);
    if (!el) return;
    var chips = el.querySelectorAll('.drawer');
    for (var i = 0; i < chips.length; i++) {
      if (chips[i].getAttribute(attr) === '') chips[i].setAttribute('data-on', '');
      else chips[i].removeAttribute('data-on');
    }
  }

  function posWireRow(el, attr, onPick) {
    if (!el) return;
    el.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('.drawer') : null;
      if (!chip || !chip.hasAttribute(attr)) return;

      var all = el.querySelectorAll('.drawer');
      for (var i = 0; i < all.length; i++) all[i].removeAttribute('data-on');
      chip.setAttribute('data-on', '');

      onPick(chip.getAttribute(attr) || '');
      posPaintTools();
      applyFilters();
    });
  }

  /**
   * ⚠ شرايح الموديل بتتفلتر بالعيلة.
   *
   * درج الآيفون بيوري موديلات الآيفون بس. من غير كده، بتفتح
   * الدرج وتلاقي قايمة سامسونج قدّامك — والدرج يبقى اسم على
   * قايمة مش درج.
   */
  function posPaintFamilyChips() {
    var box = document.getElementById('pos-models');
    if (!box) return;
    var chips = box.querySelectorAll('[data-family]');
    for (var i = 0; i < chips.length; i++) {
      var fam = chips[i].getAttribute('data-family');
      chips[i].hidden = !!activeFamily && fam !== activeFamily;
    }
  }

  /**
   * ⚠ المساحة والضريبة مالهمش سجل — بيتبنوا من البضاعة المعروضة.
   *
   * والصفّ بيتعلّم فاضي لو مفيش قيم، عشان زرّاره ما يفتحش صفّ
   * فاضي — والزرار اللي بيفتح فراغ بيخلّي الواحد يفتكر إن فيه عطل.
   */
  function posBuildDerived(rowId, listId, attr, chipAttr, label) {
    var row = document.getElementById(rowId);
    var list = document.getElementById(listId);
    if (!row || !list) return;

    var btns = document.querySelectorAll('[data-add]');
    var seen = [];
    for (var i = 0; i < btns.length; i++) {
      var v = btns[i].getAttribute(attr);
      if (!v || v === '__none__') continue;
      if (seen.indexOf(v) === -1) seen.push(v);
    }
    if (!seen.length) { row.setAttribute('data-empty', '1'); return; }

    seen.sort();
    var out = '<button class="drawer" type="button" ' + chipAttr + '="" data-on>الكل</button>';
    for (var k = 0; k < seen.length; k++) {
      var text = label ? label(seen[k]) : seen[k];
      out += '<button class="drawer" type="button" ' + chipAttr + '="'
        + seen[k] + '">' + text + '</button>';
    }
    list.innerHTML = out;
    row.removeAttribute('data-empty');
  }

  // ══════════ شريط الأدوات ══════════
  //
  // ⚠ صفّ شرايط واحد ظاهر في المرة. الخمسة المفتوحين بياخدوا
  // نص الشاشة والبضاعة تختفي تحت.
  var posFilterTools = document.getElementById('pos-filter-tools');
  var posOpenRow = '';

  var POS_ROWS = {
    cat: 'pos-row-cat', model: 'pos-row-model', color: 'pos-row-color',
    storage: 'pos-row-storage', customs: 'pos-row-customs'
  };

  function posShowRow(key) {
    for (var k in POS_ROWS) {
      var el = document.getElementById(POS_ROWS[k]);
      if (el) el.hidden = true;
    }
    if (!key) { posOpenRow = ''; return; }
    var target = document.getElementById(POS_ROWS[key]);
    if (!target) { posOpenRow = ''; return; }
    if (target.getAttribute('data-empty') === '1') { posOpenRow = ''; return; }
    target.hidden = false;
    posOpenRow = key;
  }

  /** أي أدوات فلتر تبان — حسب الدرج المفتوح */
  function posSyncFilterTools() {
    if (!posFilterTools) return;
    var subs = posFilterTools.querySelectorAll('[data-possub]');
    for (var i = 0; i < subs.length; i++) {
      var only = subs[i].getAttribute('data-for');
      subs[i].hidden = !!only && !!activeMode && only !== activeMode;
    }
  }

  /**
   * العلامات.
   *
   * ⚠ الزرار بيفضل معلّم طول ما فلتره شغّال حتى لو صفّه مقفول.
   * الفلتر الشغّال ومخفي بيخلّي الكاشير يفتكر إن نص البضاعة اتمسح.
   */
  function posPaintTools() {
    var on = {
      cat: activeMode === 'accessory',
      iph: activeMode === 'device' && activeFamily === 'IPHONE',
      and: activeMode === 'device' && activeFamily === 'ANDROID',
      color: !!activeColor,
      model: !!activeModel,
      storage: !!activeStorage,
      customs: !!activeCustoms
    };
    on.flt = on.color || on.model || on.storage || on.customs;

    var all = document.querySelectorAll('.tool');
    for (var i = 0; i < all.length; i++) {
      var key = all[i].getAttribute('data-postool') || all[i].getAttribute('data-possub');
      if (!key) continue;
      if (on[key]) all[i].setAttribute('data-on', '');
      else all[i].removeAttribute('data-on');
    }
  }

  var posToolsEl = document.querySelector('[data-postool]');
  if (posToolsEl && posToolsEl.parentNode) {
    posToolsEl.parentNode.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-postool]') : null;
      if (!btn) return;
      var key = btn.getAttribute('data-postool');

      if (key === 'flt') {
        if (!posFilterTools) return;
        var closing = !posFilterTools.hidden;
        posFilterTools.hidden = closing;

        // ══ ⚠ القفل بيلغي الفلاتر، مش بيخبّيها ══
        //
        // الفلتر اللي بيتخبّى وهو شغّال بيسيب الكاشير قدّام
        // شاشة فاضية بلا سبب ظاهر. فقفل الفلتر بقى هو زرار
        // الإلغاء نفسه — مخرج واحد معروف.
        //
        // ⚠ والدرج ما بيتلغيش معاهم: هو مش تحت الفلتر، وله
        // زراره وضغطة تانية عليه بترجّع الكل.
        if (closing) {
          activeColor = ''; activeModel = '';
          activeStorage = ''; activeCustoms = '';
          posClearRow('pos-colors', 'data-poscolor');
          posClearRow('pos-models', 'data-posmodel');
          posClearRow('pos-storages', 'data-storage');
          posClearRow('pos-customs', 'data-customs');
          posShowRow('');
          posPaintTools();
          applyFilters();
        }

        posSyncFilterTools();
        return;
      }

      var mode = key === 'cat' ? 'accessory' : 'device';
      var family = key === 'iph' ? 'IPHONE' : (key === 'and' ? 'ANDROID' : '');

      if (activeMode === mode && activeFamily === family) {
        activeMode = ''; activeFamily = '';
        posShowRow('');
      } else {
        activeMode = mode;
        activeFamily = family;
        posShowRow(mode === 'accessory' ? 'cat' : 'model');
        posPaintFamilyChips();

        if (mode === 'accessory') {
          // ⚠ فلاتر النوع التاني بتتصفّى مع تغيير الدرج.
          // «مساحة 256» شغّالة وإنت في درج الجرابات بتخلّي
          // الشاشة فاضية بلا سبب ظاهر.
          activeStorage = ''; activeCustoms = '';
          posClearRow('pos-storages', 'data-storage');
          posClearRow('pos-customs', 'data-customs');
        } else {
          activeDrawer = '';
          posClearRow('pos-drawers', 'data-posdrawer');
          // ⚠ والموديل المختار بيتصفّى لو مش من نفس العيلة —
          // وإلا بتفتح درج الآيفون وموديل سامسونج لسه مختار،
          // والنتيجة صفر بلا سبب ظاهر.
          if (activeModel) {
            var still = document.querySelector(
              '#pos-models [data-posmodel="' + activeModel + '"][data-family="' + family + '"]',
            );
            if (!still) { activeModel = ''; posClearRow('pos-models', 'data-posmodel'); }
          }
        }
      }

      posSyncFilterTools();
      posPaintTools();
      applyFilters();
    });
  }

  if (posFilterTools) {
    posFilterTools.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-possub]') : null;
      if (!btn) return;
      var key = btn.getAttribute('data-possub');
      posShowRow(posOpenRow === key ? '' : key);
    });
  }

  // ⚠ المشتقّة بتتبني قبل الربط — الشرايط لسه مش موجودة وقت التحميل.
  posBuildDerived('pos-row-storage', 'pos-storages', 'data-storage', 'data-storage', null);
  posBuildDerived('pos-row-customs', 'pos-customs', 'data-customs', 'data-customs',
    function (v) { return v === 'true' ? 'خالص' : 'ضريبة'; });

  posWireRow(document.getElementById('pos-drawers'), 'data-posdrawer',
    function (v) { activeDrawer = v; });
  posWireRow(document.getElementById('pos-models'), 'data-posmodel',
    function (v) { activeModel = v; });
  posWireRow(document.getElementById('pos-colors'), 'data-poscolor',
    function (v) { activeColor = v; });
  posWireRow(document.getElementById('pos-storages'), 'data-storage',
    function (v) { activeStorage = v; });
  posWireRow(document.getElementById('pos-customs'), 'data-customs',
    function (v) { activeCustoms = v; });

  posSyncFilterTools();
  posPaintTools();

  // ⚠ خزن الفروع التانية بتتشال من القايمة مش بتتخبّى بس.
  // «hidden» على «<option>» مش مضمون في كل المتصفحات، والخانة
  // المعطّلة اللي شكلها مختارة بتخلّي الموظّف يبعت خزنة غلط.
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

    // لو المختار دلوقتي بقى من فرع تاني، ننقل لأول خزنة صالحة
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
      // عشانه: منتج من فرع وخزنة من فرع تاني، والقاعدة بترفض
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

  // ══════════ خروج بضاعة أجل ══════════
  //
  // ⚠ بيقرا من **نفس السلة** بتاعة البيع.
  //
  // سلّتين منفصلتين كانوا هيخلّوا الموظّف يحطّ في وحدة ويضغط
  // زرار التانية — والشاشة تقول "السلة فاضية" وهو شايفها مليانة.
  var cgGo = document.getElementById('cg-go');
  var cgCart = document.getElementById('cg-cart');

  /** ملخّص السلة جوّه لوحة الخروج — بيتحدّث مع كل تغيير */
  function paintConsignCart() {
    if (!cgCart) return;
    var ids = Object.keys(cart);
    if (ids.length === 0) {
      cgCart.textContent = 'السلة فاضية — أضِف أصناف من القائمة تحت.';
      return;
    }
    var total = 0, count = 0;
    for (var i = 0; i < ids.length; i++) {
      var l = cart[ids[i]];
      // ⚠ السعر اليدوي بيتحسب هنا كمان. المنتج اللي مالوش سعر
      // مسجّل بيخرج بالسعر اللي الموظّف كتبه — زي البيع بالظبط.
      var unit = l.price === null ? Number(String(l.manual || '0').replace(/[^0-9.]/g, '')) * 100 : l.price;
      total += unit * l.qty;
      count += l.qty;
    }
    cgCart.textContent = count + ' قطعة · الإجمالي ' + money(total) + ' ج.م';
  }

  if (cgGo) {
    cgGo.addEventListener('click', async function () {
      var shopEl = document.getElementById('cg-shop');
      if (!shopEl || !shopEl.value) { posSay('اختر المحل.', false); return; }

      var ids = Object.keys(cart);
      if (ids.length === 0) { posSay('السلة فاضية.', false); return; }

      var lines = [];
      for (var i = 0; i < ids.length; i++) {
        var line = cart[ids[i]];
        // ⚠ السعر لازم يتبعت كنص زي البيع — دالة الفلوس في
        // الخادم بتقبل الأرقام العربية وبترفض السالب.
        var priceText = line.price === null
          ? String(line.manual || '')
          : String(line.price / 100);
        if (!priceText || priceText === '0') {
          posSay('فيه صنف بلا سعر. اكتب السعر قبل الخروج.', false);
          return;
        }
        lines.push({ productId: ids[i], quantity: line.qty, unitPrice: priceText });
      }

      cgGo.disabled = true;
      cgGo.textContent = 'جارٍ التسجيل…';
      try {
        var res = await fetch(
          '/api/shops/' + encodeURIComponent(shopEl.value) + '/consign',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
              items: lines,
              note: document.getElementById('cg-note').value || null
            })
          }
        );
        var out = await res.json().catch(function () { return null; });
        if (!res.ok || !out || !out.ok) {
          posSay((out && out.error && out.error.message) || 'تعذّر تسجيل الخروج.', false);
          return;
        }
        posSay('خرجت البضاعة — رصيد المحل الآن ' + money(out.newBalance) + ' ج.م.', true);
        setTimeout(function () { window.location.reload(); }, 1200);
      } catch (err) {
        posSay('تعذّر الاتصال بالخادم.', false);
      } finally {
        cgGo.disabled = false;
        cgGo.textContent = 'خروج';
      }
    });
  }

  var cgAdd = document.getElementById('cg-shop-add');
  if (cgAdd) {
    cgAdd.addEventListener('click', async function () {
      var name = prompt('اسم المحل؟');
      if (name === null) return;
      if (name.trim().length < 2) { posSay('اسم المحل قصير.', false); return; }
      var phone = prompt('رقم المسؤول؟ (اختياري)');
      if (phone === null) return;

      try {
        var res = await fetch('/api/shops', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ name: name.trim(), phone: phone.trim() || null })
        });
        var out = await res.json().catch(function () { return null; });
        if (!res.ok || !out || !out.ok) {
          posSay((out && out.error && out.error.message) || 'تعذّر إضافة المحل.', false);
          return;
        }
        // ⚠ تحديث كامل: المحل الجديد لازم يظهر في القائمة هنا
        // وفي شاشة حساب المحلات مع بعض.
        window.location.reload();
      } catch (err) {
        posSay('تعذّر الاتصال بالخادم.', false);
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
      // السعر اليدوي بيتبعت للبضاعة اللي مالهاش سعر بس.
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
          warrantyDays: warrantyValue(),
          note: document.getElementById('pos-note').value || null
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
    if (!tre || !tre.value) { retSay(id, 'اختر الخزنة.', false); return; }

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
      : 'تأكيد الاسترجاع؟ الفلوس هتطلع من الخزنة والبضاعة هتروح لرفّ المراجعة.';
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


// ═══════════════════ 6) شاشة البضاعة ═══════════════════

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
   * أدراج البضاعة — شجرة على مستويين.
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
    /**
     * عيلة الجهاز. null = غير مصنّف.
     *
     * ⚠ دي اللي بتحدّد الموديل يظهر في أنهي درج. والموديل
     * بيفضل **صف واحد** — الجهاز وجرابه بيشاوروا عليه سوا.
     */
    family: 'IPHONE' | 'ANDROID' | null;
    sortOrder: number;
    deviceCount: number;
    accessoryCount: number;
  }>;
  /**
   * سجل الألوان — البُعد التالت.
   *
   * ⚠ `hex` للنقطة الملوّنة. الموظّف بيدوّر على الجهاز اللي شافه،
   * والشكل أسرع من الاسم في القراءة.
   */
  colors: Array<{
    id: string;
    name: string;
    hex: string | null;
    sortOrder: number;
    isSystem: boolean;
    productCount: number;
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
    /** لون المنتج. null = غير محدّد. */
    colorId: string | null;
  }>;
  /**
   * سجل الموردين — لقايمة مصدر الشراء.
   *
   * ⚠ أسماء بس بلا أي رقم مالي. المندوب بيختار المورّد من غير
   * ما يشوف إنت مديون له بكام — نفس الفصل اللي في `suppliers.ts`.
   */
  suppliers: Array<{ id: string; name: string }>;
  /** supplier.manage — بيتحكم في ظهور زرار إضافة مورّد بس */
  canManageSuppliers: boolean;
  /**
   * خزن الفرع — للسداد وقت الإضافة.
   *
   * ⚠ الاسم والمعرّف بس، بلا أرصدة. الرصيد معلومة مالية
   * والمندوب مش محتاجها عشان يقول "دفعت من الدرج".
   */
  treasuries: Array<{ id: string; name: string }>;
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
 * شاشة البضاعة.
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
          <p class="empty-title">لا توجد بضاعة بعد</p>
          <p class="empty-note">
            ${data.canEdit
              ? 'ابدأ بإضافة أول منتج من القسم أعلاه.'
              : 'يضيف المديرُ البضاعةِ.'}
          </p>
        </div>`
      : html`${data.products.map((p) => {
          const isDevice = p.productType === 'device';
          const priceLabel =
            p.pricePiastres === null ? 'بلا سعر' : `${formatPiastres(p.pricePiastres)} ج.م`;

          return html`<div class="prod-row" data-row="${p.id}" data-pid="${p.id}"
            data-searchable="${p.name} ${p.serialNumber ?? ''}${
              isDevice && !p.serialNumber && p.serialUnavailable ? ' بدون سريال' : ''}"
            data-name="${p.name}" data-serial="${p.serialNumber ?? ''}"
            data-price="${p.pricePiastres === null ? '' : formatPiastres(p.pricePiastres)}"
            data-storage="${p.storageCapacity ?? ''}"
            data-battery="${p.batteryHealth === null ? '' : String(p.batteryHealth)}"
            data-customs="${p.customsCleared ? 'true' : 'false'}"
            data-cat="${p.categoryId ?? '__none__'}"
            data-model="${p.modelId ?? '__none__'}"
            data-color="${p.colorId ?? '__none__'}"
            data-type="${p.productType}"
            data-nosn="${p.serialUnavailable ? 'true' : 'false'}"
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

              <!-- ⚠ الشارة ظاهرة على الصفّ نفسه مش جوّه لوحة
                   التعديل. الهدف إنك تدوّر بعينك في المخزون
                   وتلاقيها من بره — شارة مخفية جوّه لوحة
                   بتتفتح بضغطة = شارة مش موجودة. -->
              ${isDevice && !p.serialNumber && p.serialUnavailable
                ? html`<span class="type-tag" data-type="nosn">بدون سريال</span>`
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

                    <!-- ══ ⚠ خانة «مصدر الشراء» اتشالت من هنا ══
                         كانت نص حر، وملف ٤٢ حوّل المصدر لمورّد
                         مسجّل عشان السؤال «إيه اللي جه من أحمد؟»
                         يتجاوب.
                         وسيبانها هنا كان بيخلّي فيه مصدرين لنفس
                         المعلومة: سجل مرتّب للفلوس، ونص حر جنبه —
                         والاتنين بيختلفوا يوم ما.
                         ⚠ العمود نفسه ما اتمسحش من القاعدة: الصفوف
                         القديمة لسه بتعرض مصدرها في سطر الملخّص. -->

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
                <option value="accessory">إكسسوار ومكملات</option>
                <option value="device">جهاز</option>
              </select>
            </div>

            <!-- ══ نوع الجهاز — للأجهزة بس ══
                 ⚠ ده اللي بيحدّد الدرج **وبيفلتر الموديلات**
                 في نفس اللحظة. الجهاز بيروح لدرجه من غير خطوة
                 تانية، ولا قايمة موديلات مخلوطة. -->
            <div class="field" id="np-family-field" hidden>
              <label class="field-label" for="np-family">نوع الجهاز</label>
              <select class="field-input" id="np-family">
                <option value="IPHONE">آيفون</option>
                <option value="ANDROID">أندرويد</option>
              </select>
            </div>

            <!-- ══ اسم المنتج — للإكسسوار بس ══
                 ⚠ اتشال من الأجهزة عن قصد.
                 اسم الجهاز بقى **اسم الموديل** تلقائيًا، وكتابته
                 بإيد كان بيدّي نفس الجهاز اسمين مختلفين حسب مين
                 سجّله — و"12 برو ماكس" و"ايفون ١٢ برومكس" بيبقوا
                 صنفين في أي تجميع. -->
            <div class="field" id="np-name-field">
              <label class="field-label" for="np-name">اسم المنتج</label>
              <input class="field-input" id="np-name" type="text" maxlength="80">
            </div>

            <!-- ══ الموديل — بحث بدل قايمة ══
                 ⚠ القايمة المنسدلة بقت ٤٤ موديل بعد بذرة
                 الآيفون، والنزول فيها كل مرة أطول من كتابة
                 الرقم نفسه.
                 دلوقتي بتكتب «13» فبيتصفّى لأربع شرايط وتدوس
                 على واحدة.
                 ⚠ والخانة المخفية تحت هي اللي بتتبعت فعلاً:
                 المعرّف مش النص. فمستحيل تسجّل جهاز بموديل
                 مكتوب بإيدك ومش في السجل. -->
            <div class="field">
              <label class="field-label" for="np-model-q">الموديل</label>
              <input class="field-input" id="np-model-q" type="text"
                autocomplete="off" maxlength="40"
                placeholder="اكتب جزء من الاسم — مثال: 13">
              <input type="hidden" id="np-model">
              <div class="drawers" id="np-model-picks"></div>
              <p class="field-hint" id="np-model-hint">
                اختر من الشرايط. مش موجود؟ اضغط «+ موديل جديد».
              </p>
            </div>

            <!-- ══ اللون ══
                 ⚠ للنوعين. الجراب الأحمر غير الأزرق، ودي أشيع
                 حاجة الزبون بيسأل عنها على الكاونتر. -->
<div class="field" id="np-serial-field" hidden>
              <label class="field-label" for="np-serial">الرقم التسلسلي</label>
              <input class="field-input" id="np-serial" type="text" dir="ltr"
                autocomplete="off" maxlength="64">
              <!-- ⚠ نفس ماسح خانة البحث بالظبط، مش ماسح تاني.
                   window.scanBarcode معرّفة مرة واحدة في السكربت
                   المشترك؛ نسخة تانية هنا كانت هتخلّي سلوك
                   الكاميرا يختلف بين شاشتين في نفس الصفحة. -->
              <button class="btn-mini" type="button" id="np-serial-scan">مسح بالكاميرا</button>
              <!-- ══ ⚠ "غير متاح" خيار مش خانة فاضية ══
                   الفرق بين الاتنين هو الفرق بين غياب وقرار.
                   الخانة الفاضية بتسيب سؤال معلّق: نسي، ولا
                   الجهاز فعلاً مالوش؟ والعلامة بتقول: حد بصّ
                   وقرّر وسجّل.

                   نفس تفريقة صحة البطارية: فاضي = ما اتقاسش،
                   وصفر = بطارية خربانة. -->
              <label class="field-label" style="display:flex;gap:8px;align-items:center">
                <input type="checkbox" id="np-nosn"> الرقم التسلسلي غير متاح
              </label>
              <!-- ⚠ التلميحة دي بتوفّر مكتبة قراءة أرقام حجمها
                   ١٥ ميجا. الشاشتين مكتوبين بالاسم عن قصد: من
                   غير الاسم، الموظّف بيفتح شاشة "حول" اللي
                   مفيهاش باركود ويقول إن الماسح باظ. -->
              <p class="field-hint">
                الماسح بيقرا الباركود. في الآيفون افتح:
                الإعدادات ← عام ← حول ← مشاركة معرّفات الجهاز —
                فيها باركود تحت الـIMEI.
                ولو الرقم مكتوب بلا باركود، دوس مطوّل في الخانة
                واختار «مسح النص».
              </p>
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
            <!-- ══ ⚠ خانة كتابة مع قايمة اقتراحات، مش قايمة منسدلة ══

                 السبب إن سجل الموديلات بيكبر. قايمة فيها ستين
                 موديل على موبايل = تمرير طويل في كل إضافة.

                 دلوقتي بتكتب أول حرف أو رقم والقايمة بتضيق.
                 ولو كتبت غلط، مفيش اقتراحات — فتفتح القايمة
                 وتدوّر زي الأول. مفيش طريق مسدود.

                 ⚠ والقايمة بتتفلتر بنوع الجهاز المختار فوق،
                 فموديلات سامسونج ما بتظهرش وإنت بتسجّل آيفون. -->
            <div class="field">
              <label class="field-label" for="np-color">اللون</label>
              <select class="field-input" id="np-color">
                <option value="">— بدون لون —</option>
                ${data.colors.map(
                  (c) => html`<option value="${c.id}">${c.name}</option>`,
                )}
                <!-- ⚠ الإضافة آخر خيار **جوّه** القايمة مش زرار
                     تحتها. الزرار المستقل كان بياخد سطر كامل في
                     شاشة فيها اتناشر حقل، والعين بتعدّي عليه. -->
                <option value="__add__">+ إضافة لون</option>
              </select>
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
              <!-- ⚠ فاضية مش صفر.
                   الصفر المكتوب مسبقًا بيخلّي الموظّف يمسحه قبل
                   ما يكتب في كل إضافة — والنتيجة "05" لو نسي. -->
              <input class="field-input" id="np-qty" type="text" inputmode="numeric"
                dir="ltr" placeholder="0">
            </div>

            <div class="field">
              <label class="field-label" for="np-cost">التكلفة</label>
              <input class="field-input" id="np-cost" type="text" inputmode="decimal"
                dir="ltr" autocomplete="off">
              <p class="field-hint">
                إلزامية. جالك بلا تكلفة؟ اكتب صفر — الصفر المكتوب قرار،
                والخانة الفاضية نسيان.
              </p>
            </div>

            <!-- ══ ⚠ تسوية التكلفة — بتظهر لما تكتب رقم بس ══

                 السبب إن السؤال ده مالوش معنى بلا تكلفة، وخانة
                 ظاهرة ومالهاش معنى بتتساب على قيمتها الافتراضية
                 من غير ما حد يقراها.

                 ⚠ والاختيار ده **بيحرّك فلوس فعلاً**:
                   مدفوعة → بتطلع من الخزنة اللي تختارها
                   على الحساب → بتتسجّل دين على المورّد

                 والاتنين بيتكتبوا مع المنتج في معاملة واحدة جوّه
                 قاعدة البيانات. لو اتفصلوا، بيبقى عندك جهاز بلا
                 دين أو دين بلا جهاز — والاتنين بيبانوا كأنهم نجاح. -->
            <div id="np-settle-box" hidden>
              <div class="field">
                <label class="field-label" for="np-settle">التكلفة دي</label>
                <select class="field-input" id="np-settle">
                  <option value="NONE">— تسجيل مخزون بس، بلا حركة فلوس —</option>
                  <option value="PAID">اتدفعت من الخزنة</option>
                  <option value="CREDIT">على حساب المورّد (دين)</option>
                </select>
              </div>

              <div class="field" id="np-treasury-field" hidden>
                <label class="field-label" for="np-treasury">الخزنة</label>
                <select class="field-input" id="np-treasury">
                  ${data.treasuries.map(
                    (t) => html`<option value="${t.id}">${t.name}</option>`,
                  )}
                </select>
                <p class="field-hint">
                  المبلغ = التكلفة × الكمية، وبيخرج من الخزنة دي فورًا.
                </p>
              </div>

              <p class="field-hint" id="np-settle-hint" hidden>
                هيتسجّل دين على المورّد المختار فوق بقيمة التكلفة × الكمية.
              </p>
            </div>

            <!-- ══ ⚠ مصدر الشراء بقى مورّد مسجّل، مش نص حر ══

                 كان خانة كتابة. يعني "أحمد للموبايلات" و"احمد
                 للموبايلات" مصدرين مختلفين في أي تجميع — والسؤال
                 "إيه اللي جه من أحمد؟" ما بيتجاوبش.

                 ⚠ ودي **نفس الغلطة** اللي ملف ٢٢ اتكتب عشانها
                 وحلّها للديون، وفضلت موجودة على البضاعة.

                 والزرار بيضيف المورّد **في السجل** على طول، فبيظهر
                 في شاشة الموردين وحساباتهم من غير أي خطوة تانية. -->
            <div class="field">
              <label class="field-label" for="np-supplier">مصدر الشراء</label>
              <select class="field-input" id="np-supplier">
                <!-- ⚠ «غير محدّد» بقى «اختر» — الفرق مش لغوي.
                     الأولى بتقرا كإجابة مشروعة، والتانية بتقول
                     إن فيه خطوة لسه ناقصة.
                     ومشتريها من زبون؟ فيه صف اسمه «شراء من زبون». -->
                <option value="">— اختر المصدر —</option>
                ${data.suppliers.map(
                  (sp) => html`<option value="${sp.id}">${sp.name}</option>`,
                )}
                <!-- ⚠ الخيار بيظهر لمن يملك صلاحية إدارة الموردين
                     بس. إنشاء المورّد على مسار الموردين، والمندوب
                     مالوش الصلاحية — فالخيار كان هيرفض عنده بلا
                     سبب ظاهر.

                     ⚠ وإخفاؤه مش حماية، هو **صدق في الواجهة**.
                     الحراسة الحقيقية على المسار زي ما هي. -->
                ${data.canManageSuppliers
                  ? html`<option value="__add__">+ إضافة مورّد</option>`
                  : ''}
              </select>
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
              <label class="field-label" for="np-entry">تاريخ الدخول</label>
              <input class="field-input" id="np-entry" type="date" dir="ltr"
                value="${data.today}" max="${data.today}">
            </div>

            <button class="btn-primary" id="addbtn" type="submit">إضافة المنتج</button>
          </form>
        </div>
      </details>`;

  return shell({
    title: 'البضاعة',
    tenantName: data.tenantName,
    script: productsScript(
      data.idleTimeoutSeconds,
      data.idleWarningSeconds,
      data.idleAction,
      data.tenantName,
      data.models.map((m) => ({
        id: m.id,
        name: m.name,
        brand: m.brand,
        family: m.family,
      })),
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
      <!-- ══ شريط الأدوات ══

           ⚠ اتغيّر من **خمس صفوف مفتوحة** لأدوات بتتفتح عند
           الطلب. الخمس صفوف كانت بتاخد نص الشاشة والمخزون
           يختفي تحت.

           ══ درجين لا واحد ══
           الإكسسوار بيتنظّم بالصنف (جراب · شاحن)، والأجهزة
           بتتنظّم بالموديل. دول تصنيفين مختلفين لنوعين مختلفين،
           فحشرهم في درج واحد كان بيخلّي نص الشرايط بلا معنى
           لنص المخزون.

           ⚠ والدرج **بيفلتر النوع كمان** مش بيفتح شرايط وبس.
           لو فتحت درج الأجهزة وفضلت شايف الإكسسوار، الدرج بيبقى
           اسم على قايمة مش درج.

           ⚠ والزرار بيتعلّم بـ«data-on» وهو **مقفول** كمان،
           لأن الفلتر شغّال ومخفي بيخلّي المستخدم يفتكر إن نص
           المخزون اتمسح. -->
      <div class="tools">
        <button class="tool" type="button" data-tool="cat">
          درج الإكسسوار والمكملات
        </button>
        <!-- ══ ⚠ درجين للأجهزة مش واحد ══
             الدرجين بيفلتروا **بعيلة الموديل** مش بحاجة على
             المنتج نفسه. يعني الجهاز بيقع في الدرج بتاع موديله.

             ⚠ والجهاز اللي موديله غير مصنّف (أو مالوش موديل)
             ما بيظهرش في الدرجين — بيظهر في «الكل». وده مقصود:
             الدرج بيقول "دول الآيفونات"، وحطّ فيه حاجة مش
             متأكدين منها بيخلّي العدّ كذب. -->
        <button class="tool" type="button" data-tool="iph">
          درج الآيفون
        </button>
        <button class="tool" type="button" data-tool="and">
          درج الأندرويد
        </button>
        <button class="tool" type="button" data-tool="flt">فلتر</button>
      </div>

      <!-- ⚠ أدوات الفلتر بتتغيّر بالدرج المفتوح:
             الإكسسوار → اللون · الموديل
             الأجهزة   → اللون · المساحة · الضريبة
           والمساحة والضريبة مالهمش معنى على جراب. -->
      <div class="tools" id="filter-tools" hidden>
        <button class="tool" type="button" data-sub="color">اللون</button>
        <button class="tool" type="button" data-sub="model" data-for="accessory">
          الموديل
        </button>
        <button class="tool" type="button" data-sub="storage" data-for="device">
          المساحة
        </button>
        <button class="tool" type="button" data-sub="customs" data-for="device">
          الضريبة
        </button>
      </div>

      <!-- ⚠ الشرايط في مكان واحد وبتتبدّل، مش نسخة في كل قايمة.
           نسختين من نفس الشريط معناهم إن العلامة على الاتنين
           ممكن تختلف — والمستخدم يشوف "أسود" مختار في مكان
           و"الكل" في مكان تاني. -->
      <div class="row-wrap" id="row-cat" hidden>
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
          <button class="drawer" type="button" data-drawer="__none__">غير مصنّف</button>
          ${data.canEdit
            ? html`<button class="drawer" type="button" data-add-drawer>+</button>`
            : ''}
        </div>
      </div>

      <div class="row-wrap" id="row-model" hidden>
        <div class="drawers" id="models">
          <button class="drawer" type="button" data-model="" data-on>الكل</button>
          ${data.models.map(
            (m) => html`<button class="drawer" type="button" data-model="${m.id}"
              data-family="${m.family ?? '__none__'}">
              ${m.name}
              <!-- ⚠ رقمين منفصلين: أجهزة · إكسسوار. رقم مجمّع
                   كان هيقول "٧" ومش هتعرف سبع أجهزة ولا سبع جرابات. -->
              <span class="drawer-n">${String(m.deviceCount)}·${String(m.accessoryCount)}</span>
            </button>`,
          )}
          <button class="drawer" type="button" data-model="__none__">بلا موديل</button>
          ${data.canEdit
            ? html`<button class="drawer" type="button" data-add-model>+</button>`
            : ''}
        </div>
      </div>

      <div class="row-wrap" id="row-color" hidden>
        <div class="drawers" id="colors">
          <button class="drawer" type="button" data-color="" data-on>الكل</button>
          ${data.colors.map(
            (c) => html`<button class="drawer" type="button" data-color="${c.id}">
              ${c.hex ? html`<span class="dot" style="background:${c.hex}"></span>` : ''}
              ${c.name}
              <span class="drawer-n">${String(c.productCount)}</span>
            </button>`,
          )}
          <button class="drawer" type="button" data-color="__none__">بلا لون</button>
          ${data.canEdit
            ? html`<button class="drawer" type="button" data-add-color>+</button>`
            : ''}
        </div>
      </div>

      <!-- ══ المساحة والضريبة — مشتقّة مش مسجّلة ══

           ⚠ التنين دول مالهمش سجل، وده قرار مكتوب.

           storage_capacity و customs_cleared أعمدة على المنتج من
           ملفَي ٢١ و٢٣. فالشرايط بتتبني من الصفوف الموجودة.

           والفرق: الدرج واللون والموديل **بتتختار** وقت الإضافة،
           فمحتاجة سجل يمنع التكرار. المساحة بتتكتب على المنتج
           خلاص، والشريط بيعرض اللي موجود فعلاً.

           ⚠ ومفيش عدّ عليهم عن قصد: القايمة محدودة بـ500 صف،
           والعدّ من المعروض كان هيكذب أول ما المخزون يعدّي الحد. -->
      <div class="row-wrap" id="row-storage" hidden>
        <div class="drawers" id="storages"></div>
      </div>

      <div class="row-wrap" id="row-customs" hidden>
        <div class="drawers" id="customs"></div>
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
  /**
   * سجل الموديلات — عشان قايمة الاقتراحات تتفلتر بنوع الجهاز.
   *
   * ⚠ بيتمرّر للسكربت مش بيتقرا من الـDOM. قراءة الشرايط كانت
   * هتربط النموذج بشريط الفلترة — وأول ما شريط يتخفي أو يتغيّر
   * ترتيبه، النموذج بيقع معاه.
   */
  models: Array<{ id: string; name: string; brand: string | null; family: string | null }>,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var SHOP_NAME = ${JSON.stringify(shopName)};
  var ALL_MODELS = ${JSON.stringify(models)};

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
  // لو جبناه لكل البضاعة مع الصفحة، هتبقى عشرين نداء زيادة
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
    var entryEl = document.getElementById('entry-' + id);

    var body = {};
    if (serialEl) body.serialNumber = serialEl.value;
    // ⚠ المصدر مابقاش بيتبعت خالص. الخانة اتشالت من القالب،
    // ولو سبنا السطر ده كان هيبعت قيمة فاضية ويفضّي العمود
    // في كل حفظ — يعني يمسح مصدر الصفوف القديمة بصمت.
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
    // الجهاز درجه بيتحدّد من عيلة موديله.
    if (catField) catField.hidden = isDevice;

    // ══ نوع الجهاز والاسم — واحد بيظهر والتاني بيختفي ══
    //
    // ⚠ اسم الجهاز بقى **اسم الموديل** تلقائيًا. وكتابته بإيد
    // كانت بتدّي نفس الجهاز اسمين مختلفين حسب مين سجّله، و"12
    // برو ماكس" و"ايفون ١٢ برومكس" بيبقوا صنفين في أي تجميع.
    var famField = document.getElementById('np-family-field');
    var nameField = document.getElementById('np-name-field');
    if (famField) famField.hidden = !isDevice;
    if (nameField) nameField.hidden = isDevice;

    paintModelList();
  }

  /**
   * قايمة اقتراحات الموديلات.
   *
   * ⚠ بتتفلتر بنوع الجهاز للأجهزة، وبتوري **الكل** للإكسسوار.
   *
   * السبب إن الجراب ممكن يكون لآيفون أو لسامسونج — فحصره في
   * عيلة واحدة كان هيمنعك تسجّل نص بضاعتك. أما الجهاز نفسه
   * فبينتمي لعيلة واحدة بالتعريف.
   */
  /**
   * بناء قايمة الموديلات.
   *
   * ⚠ بتتبني بالجافاسكربت مش في القالب، لأنها بتتغيّر لما
   * تبدّل بين آيفون وأندرويد.
   *
   * ⚠ وغير المصنّف بيظهر للإكسسوار بس. لو ظهر في درج الآيفون،
   * بتسجّل جهاز على موديل إحنا مش متأكدين إنه آيفون — والعدّ
   * في الدرج بيبقى كذب.
   *
   * ⚠ والاختيار الحالي بيتحافظ عليه لو لسه في القايمة. من غير
   * كده، أي تغيير في نوع الجهاز كان بيصفّر الموديل بصمت.
   */
  /**
   * ⚠ تطبيع نص البحث.
   *
   * بيوحّد الأرقام العربية والمسافات وحالة الحروف قبل المقارنة.
   * من غيره: اللي بيكتب «١٣» ما بيلاقيش «13»، واللي بيكتب
   * «13promax» ما بيلاقيش «13 Pro Max» — والاتنين نفس الموديل.
   */
  function normModel(raw) {
    return String(raw || '')
      .replace(/[\u0660-\u0669]/g, function (d) {
        return String(d.charCodeAt(0) - 1632);
      })
      .replace(/[\u06f0-\u06f9]/g, function (d) {
        return String(d.charCodeAt(0) - 1776);
      })
      .toLowerCase()
      .replace(/\s+/g, '');
  }

  /**
   * ⚠ تهريب النص قبل الحقن.
   *
   * أسماء الموديلات بيكتبها المستخدم، وحقنها في innerHTML من
   * غير تهريب بيخلّي علامة أقلّ من واحدة تكسر الشريط كله.
   */
  function escModel(raw) {
    return String(raw || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function modelLabel(m) {
    return m.brand ? m.brand + ' — ' + m.name : m.name;
  }

  /**
   * بناء شرايط الموديلات.
   *
   * ⚠ بتتفلتر بحاجتين مع بعض: نوع الجهاز، واللي مكتوب في خانة
   * البحث. والنتيجة بتتعرض كشرايط زي أدراج الشاشة الرئيسية —
   * نفس المكوّن اللي المستخدم متعوّد عليه، وحجم لمسة مريح.
   *
   * ⚠ وغير المصنّف بيظهر للإكسسوار بس. لو ظهر في درج الآيفون،
   * بتسجّل جهاز على موديل إحنا مش متأكدين إنه آيفون — والعدّ
   * في الدرج بيبقى كذب.
   *
   * ⚠ والاختيار بيتلغى لوحده لو خرج من الفلتر (بدّلت من آيفون
   * لأندرويد مثلاً). سيبانه كان بيخلّي الخانة المخفية شايلة
   * موديل مش ظاهر قدّامك — وده أسوأ من التصفير الصامت.
   */
  function paintModelList() {
    var box = document.getElementById('np-model-picks');
    var hid = document.getElementById('np-model');
    var q = document.getElementById('np-model-q');
    if (!box || !hid) return;

    var isDevice = typeEl && typeEl.value === 'device';
    var famEl = document.getElementById('np-family');
    var want = isDevice && famEl ? famEl.value : '';
    var term = normModel(q ? q.value : '');

    // ⚠ المختار الأول: لو خرج من الفلتر بيتلغى قبل الرسم.
    if (hid.value) {
      var still = null;
      for (var k = 0; k < ALL_MODELS.length; k++) {
        if (ALL_MODELS[k].id !== hid.value) continue;
        if (!want || ALL_MODELS[k].family === want) still = ALL_MODELS[k];
        break;
      }
      if (!still) { hid.value = ''; if (q) q.value = ''; term = ''; }
    }

    var out = '';
    var shown = 0;
    var exact = '';

    // ⚠ «بدون موديل» للإكسسوار وحده — الجهاز إلزامي، والخادم
    // بيرفضه برضه لو الشاشة اتخطّت.
    if (!isDevice) {
      out += '<button type="button" class="drawer" data-pick=""'
        + (hid.value ? '' : ' data-on="1"') + '>بدون موديل</button>';
    }

    for (var i = 0; i < ALL_MODELS.length; i++) {
      var m = ALL_MODELS[i];
      if (want && m.family !== want) continue;

      var label = modelLabel(m);
      var norm = normModel(label);
      if (term && norm.indexOf(term) < 0) continue;

      // ⚠ سقف احترازي. الشريط أفقي وبيتمرّر، لكن مية زرار
      // بتبطّئ الرسم على موبايل قديم — والمستخدم اللي محتاج
      // أكتر من أربعين نتيجة محتاج يكتب حرف كمان مش يمرّر.
      if (shown >= 40) break;

      if (norm === term) exact = m.id;

      out += '<button type="button" class="drawer" data-pick="' + m.id + '"'
        + (m.id === hid.value ? ' data-on="1"' : '') + '>'
        + escModel(label) + '</button>';
      shown++;
    }

    if (shown === 0) {
      out += '<span class="field-hint">مفيش موديل بالاسم ده.</span>';
    }

    out += '<button type="button" class="drawer" data-add-drawer="1"'
      + ' data-pick="__add__">+ موديل جديد</button>';

    box.innerHTML = out;

    // ⚠ التطابق التام بيختار لوحده.
    //
    // من غيره: بنحطّ اسم الموديل في الخانة بعد ما تدوس عليه،
    // وأول حرف بعدها بيلغي الاختيار — فترجع تدوس تاني على نفس
    // الشريط اللي هو الوحيد الظاهر. حلقة مغلقة صغيرة ومزعجة.
    if (exact && !hid.value) hid.value = exact;
  }

  /** اختيار موديل من شريط — بيملا الخانة المخفية وخانة البحث */
  function pickModel(id) {
    var hid = document.getElementById('np-model');
    var q = document.getElementById('np-model-q');
    if (!hid) return;

    hid.value = id || '';

    var label = '';
    for (var i = 0; i < ALL_MODELS.length; i++) {
      if (ALL_MODELS[i].id === id) { label = modelLabel(ALL_MODELS[i]); break; }
    }
    if (q) q.value = label;

    paintModelList();
  }

  if (typeEl) { typeEl.addEventListener('change', syncType); syncType(); }

  var familyEl = document.getElementById('np-family');
  if (familyEl) familyEl.addEventListener('change', paintModelList);

  // ══════════ خانة بحث الموديل ══════════
  //
  // ⚠ الكتابة بتلغي الاختيار القديم.
  //
  // من غير كده: تختار «13 Pro»، تمسح وتكتب «14»، والخانة
  // المخفية لسه شايلة الـ13 برو. تدوس حفظ فيتسجّل جهاز باسم
  // مش اللي قدّامك على الشاشة — وده أوحش من رسالة رفض.
  var modelQEl = document.getElementById('np-model-q');
  if (modelQEl) {
    modelQEl.addEventListener('input', function () {
      var hid = document.getElementById('np-model');
      if (hid) hid.value = '';
      paintModelList();
    });
  }

  // ══════════ تسوية التكلفة ══════════
  //
  // ⚠ الصندوق بيظهر لما تكتب تكلفة بس. السؤال مالوش معنى بلا
  // رقم، والخانة الظاهرة بلا معنى بتتساب على قيمتها الافتراضية
  // من غير ما حد يقراها.
  var costEl = document.getElementById('np-cost');
  var settleBox = document.getElementById('np-settle-box');
  var settleEl = document.getElementById('np-settle');
  var treasuryField = document.getElementById('np-treasury-field');
  var settleHint = document.getElementById('np-settle-hint');

  function syncSettle() {
    if (!costEl || !settleBox) return;
    var hasCost = costEl.value.trim() !== '' && costEl.value.trim() !== '0';
    settleBox.hidden = !hasCost;

    // ⚠ إخفاء الصندوق بيرجّع الاختيار للحياد كمان.
    // لو سبناه على "اتدفعت" وهو مخفي، الموظّف يمسح التكلفة
    // ويفتكر إنه ألغى السداد — والحركة بتتسجّل برضه.
    if (!hasCost && settleEl) settleEl.value = 'NONE';

    var mode = settleEl ? settleEl.value : 'NONE';
    if (treasuryField) treasuryField.hidden = mode !== 'PAID';
    if (settleHint) settleHint.hidden = mode !== 'CREDIT';
  }

  if (costEl) costEl.addEventListener('input', syncSettle);
  if (settleEl) settleEl.addEventListener('change', syncSettle);
  syncSettle();

  // ══════════ أزرار الإضافة جوّه النموذج ══════════
  //
  // ⚠ التلاتة بيضيفوا في **السجل** مش في النموذج بس.
  //
  // يعني المورّد اللي بتضيفه هنا بيظهر في شاشة الموردين
  // وحساباتهم فورًا، والموديل بيظهر في شرايط الفلترة. لو
  // كانوا بيتضافوا في القايمة المحلية بس، كنّا هنبقى عندنا
  // بيانات موجودة في شاشة ومش موجودة في اللي جنبها.
  //
  // ⚠ وكلهم بيعملوا تحديث للصفحة بعد النجاح. التحديث مزعج،
  // بس البديل إننا نحقن الخيار في مكان واحد وننسى الشرايط
  // والقوايم التانية — وده بيسيب الشاشة بتقول حاجتين.
  async function addToRegistry(url, body, label) {
    try {
      var res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      });
      var data = await res.json();
      if (!res.ok || !data.ok) {
        say((data.error && data.error.message) || ('تعذّر إضافة ' + label + '.'), false);
        return false;
      }
      window.location.reload();
      return true;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return false;
    }
  }

  // ══════════ خيار «الإضافة» جوّه القوايم ══════════
  //
  // ⚠ التلاتة (موديل · لون · مورّد) بقوا **آخر خيار في القايمة**
  // بدل زرار مستقل تحت الخانة.
  //
  // السبب إن كل زرار كان بياخد سطر كامل في شاشة فيها اتناشر
  // حقل، والعين بتعدّي عليه. وجوّه القايمة بيظهر لما تفتحها
  // بس — يعني وقت ما تكون بتدوّر فعلاً.
  //
  // ⚠ والقايمة بترجع لاختيارها القديم لو ألغيت الإضافة. من غير
  // كده، الإلغاء كان بيسيبها على "+ إضافة" وهي مش قيمة صالحة.
  var lastPick = {};

  document.addEventListener('change', async function (e) {
    var sel = e.target;
    if (!sel || !sel.id) return;
    // ⚠ الموديل خرج من هنا: بقى شرايط مش قايمة منسدلة، فمفيش
    // حدث التغيير يتنادى عليه أصلاً. إضافته في معالج الضغط تحت.
    if (sel.id !== 'np-color' && sel.id !== 'np-supplier') return;

    if (sel.value !== '__add__') { lastPick[sel.id] = sel.value; return; }
    sel.value = lastPick[sel.id] || '';

    if (sel.id === 'np-color') {
      var cname = prompt('اسم اللون؟');
      if (cname === null || !cname.trim()) return;
      await addToRegistry('/api/products/colors', { name: cname.trim() }, 'اللون');
      return;
    }

    if (sel.id === 'np-supplier') {
      var sname = prompt('اسم المورّد؟');
      if (sname === null || !sname.trim()) return;
      var sphone = prompt('رقم التليفون؟ (اختياري)');
      if (sphone === null) return;
      await addToRegistry(
        '/api/suppliers',
        { name: sname.trim(), phone: sphone.trim() || null },
        'المورّد'
      );
      return;
    }
  });

  // ══════════ ضغط شرايط الموديل ══════════
  //
  // ⚠ معالج واحد على الحاوية مش على كل شريط.
  //
  // الشرايط بتتعاد بناءها مع كل حرف بتكتبه، وأي مستمع متعلّق
  // على شريط بيموت مع الرسمة اللي بعدها. الحاوية ثابتة.
  var modelPicksEl = document.getElementById('np-model-picks');
  if (modelPicksEl) {
    modelPicksEl.addEventListener('click', async function (e) {
      var hit = e.target.closest ? e.target.closest('[data-pick]') : null;
      if (!hit) return;

      var pid = hit.getAttribute('data-pick');

      if (pid !== '__add__') { pickModel(pid); return; }

      // ⚠ الاسم المكتوب في خانة البحث بيتقدّم كاقتراح.
      // اللي وصل لـ«موديل جديد» غالبًا كتب اسمه ومالقهوش،
      // وإعادة كتابته من الأول شغل مكرر بلا سبب.
      var typed = modelQEl ? modelQEl.value.trim() : '';
      var mname = prompt('اسم الموديل الجديد؟', typed);
      if (mname === null || !mname.trim()) return;

      // ⚠ العيلة من نوع الجهاز المختار فوق — السؤال هنا تكرار
      // لحاجة الشاشة عارفاها.
      var fam = null;
      if (typeEl && typeEl.value === 'device' && familyEl) fam = familyEl.value;

      await addToRegistry('/api/products/models', { name: mname.trim(), family: fam }, 'الموديل');
    });
  }

  // ══════════ فحص رقم الـIMEI ══════════
  //
  // ══ الفكرة ══
  // آخر رقم في الـIMEI **محسوب** من الأربعتاشر اللي قبله
  // بمعادلة ثابتة (Luhn). يعني الرقم بيشهد على نفسه: أي خانة
  // اتكتبت غلط أو اتقرت غلط بتكسر الحساب.
  //
  // تشبيه: وزن الملاكم قبل النزال. مش بيقول هيكسب، بيقول إنه
  // في الفئة الصح. الرقم الغلط بيسقط في الميزان قبل الحلبة.
  //
  // ⚠ بيشتغل على **١٥ رقم بالظبط** وبس. سريالات تانية في
  // النظام (إكسسوار، أجهزة قديمة، أرقام داخلية) مالهاش الشكل
  // ده، وفحصها كان هيطلّع إنذار كاذب على رقم سليم تمامًا —
  // والإنذار الكاذب بيخلّي الواحد يبطّل يقرا الإنذارات.
  function luhnOk(raw) {
    var digits = String(raw || '').replace(/\D/g, '');
    if (digits.length !== 15) return true;   // مش بشكل IMEI — مش شغلنا

    var sum = 0;
    for (var i = 0; i < 15; i++) {
      // من الشمال: الخانات في المواضع الفردية (الثانية، الرابعة…)
      // بتتضاعف. ولو الناتج بقى خانتين، بنجمع الخانتين.
      var d = Number(digits.charAt(i));
      if (i % 2 === 1) { d = d * 2; if (d > 9) d = d - 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }

  // ── الخانة والسريال بيتحكموا في بعض ──
  //
  // ⚠ السريال بيغلب العلامة، مش العكس. لو المستخدم علّم "غير
  // متاح" وبعدين مسح باركود، الرقم موجود قدامنا فعلاً — الصح
  // إنه يتسجّل والعلامة تتشال لوحدها.
  //
  // والخادم بيعمل نفس القاعدة بالظبط. السطور دي راحة للعين
  // مش حماية؛ الحماية عند البيانات.
  var noSnEl = document.getElementById('np-nosn');
  var serialInput = document.getElementById('np-serial');

  function syncNoSerial() {
    if (!noSnEl || !serialInput) return;
    serialInput.disabled = noSnEl.checked;
    if (noSnEl.checked) serialInput.value = '';
  }
  if (noSnEl) { noSnEl.addEventListener('change', syncNoSerial); syncNoSerial(); }
  if (serialInput) {
    serialInput.addEventListener('input', function () {
      if (noSnEl && noSnEl.checked && serialInput.value.trim()) {
        noSnEl.checked = false;
        syncNoSerial();
      }
    });
  }

  // ── مسح السريال وقت الإضافة ──
  //
  // ⚠ نفس حارس زرار البحث: لو السكربت المشترك ما اتحمّلش،
  // الزرار كان هيسكت من غير أي رسالة — والسكوت أوحش من الرفض.
  var serialScanBtn = document.getElementById('np-serial-scan');
  if (serialScanBtn) {
    serialScanBtn.addEventListener('click', async function () {
      try {
        if (typeof window.scanBarcode !== 'function') {
          say('الماسح غير متاح على هذا المتصفح.', false);
          return;
        }
        var scanned = await window.scanBarcode();
        if (!scanned) return;
        var serialEl = document.getElementById('np-serial');
        if (!serialEl) return;
        // ⚠ الماسح بيشيل العلامة كمان. من غير السطرين دول،
        // الخانة بتفضل متعلّمة والحقل معطّل — فالرقم المقروء
        // بيتكتب في مكان مش هيتبعت أصلاً.
        var flag = document.getElementById('np-nosn');
        if (flag && flag.checked) { flag.checked = false; }
        serialEl.disabled = false;
        serialEl.value = scanned;
        serialEl.focus();

        // ⚠ بنملا الخانة **وبعدين** ننبّه، مش نرفض ونمسح.
        // القراءة الغلط بتبقى خانة واحدة غالبًا، وتصليحها أسهل
        // بكتير من إعادة المسح من الأول. الرمي كان هيضيّع
        // أربعتاشر رقم صح عشان واحد غلط.
        if (!luhnOk(scanned)) {
          say('الرقم اتقرا، بس فحص الـIMEI مش مظبوط. راجعه.', false);
        }
      } catch (err) {
        say(err && err.message ? err.message : 'تعذّر المسح.', false);
      }
    });
  }

  var form = document.getElementById('addf');
  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var btn = document.getElementById('addbtn');
      var msg = document.getElementById('addmsg');
      var msgText = document.getElementById('addmsg-text');
      var branch = document.getElementById('np-branch');
      var isDevice = typeEl && typeEl.value === 'device';

      // ══ الموديل ══
      //
      // ⚠ القيمة بقت **معرّف** مباشرةً من القايمة، مش نص محتاج
      // تطابق. الاقتراحات القديمة كانت بتفشل على أي حرف ناقص
      // والموديل قدّامك في القايمة.
      var modelInput = document.getElementById('np-model');
      var modelId = modelInput ? modelInput.value : '';
      if (modelId === '__add__') modelId = '';

      var modelName = '';
      for (var mi = 0; mi < ALL_MODELS.length; mi++) {
        if (ALL_MODELS[mi].id === modelId) { modelName = ALL_MODELS[mi].name; break; }
      }

      // ⚠ الموديل إلزامي للجهاز، لأن اسم الجهاز بيتولد منه.
      // من غيره الجهاز بيتسجّل بلا اسم وما يظهرش في أي بحث.
      if (isDevice && !modelId) {
        say('اختر الموديل من الشرايط — اسم الجهاز بيتولّد منه.', false);
        // ⚠ المؤشر بيروح لخانة **البحث**. الخانة اللي جنبها
        // مخفية، ونقل المؤشر عليها ما بيعملش حاجة — فالرسالة كانت
        // هتظهر والمستخدم مش عارف يكتب فين.
        var modelQ = document.getElementById('np-model-q');
        if (modelQ) modelQ.focus();
        return;
      }

      // ══ ⚠ التكلفة والمصدر إلزاميين ══
      //
      // الفحص هنا **راحة مش حراسة**: الخادم بيرفض الاتنين
      // برضه. الفايدة إن الرسالة بتوصل من غير رحلة شبكة،
      // والمؤشر بيروح للخانة الناقصة على طول.
      var costVal = document.getElementById('np-cost');
      if (costVal && costVal.value.trim() === '') {
        say('اكتب التكلفة. لو الجهاز جالك بلا تكلفة، اكتب صفر.', false);
        costVal.focus();
        return;
      }

      var supVal = document.getElementById('np-supplier');
      if (supVal && !supVal.value) {
        say('اختر مصدر الشراء. مشتريها من زبون؟ اختر «شراء من زبون».', false);
        supVal.focus();
        return;
      }

      // ══ ⚠ فحص الرقم قبل الإرسال ══
      //
      // بيشتغل على أي سريال ١٥ رقم مهما جه منين: مكتوب بإيدك،
      // ممسوح بالكاميرا، أو ملزوق. القاعدة إن الفحص يقعد جنب
      // **الإرسال** مش جنب طريقة الإدخال — وإلا كل طريقة جديدة
      // بتضاف بكرة هتعدّي من غير فحص.
      //
      // ⚠ وتحذير مش منع. فيه أجهزة سريالها ١٥ رقم وهو مش IMEI
      // أصلاً، والرفض القاطع كان هيقفل عليك جهاز سليم ومفيش
      // طريقة تعدّي. فبنسأل، وإنت بتقرّر.
      if (isDevice && !(noSnEl && noSnEl.checked)) {
        var typedSerial = document.getElementById('np-serial').value;
        if (!luhnOk(typedSerial)) {
          var goOn = confirm(
            'الرقم ده مش مطابق لفحص الـIMEI — يعني غالبًا فيه خانة غلط.' +
            '\\n\\n' +
            'تكمّل الإضافة برضه؟'
          );
          if (!goOn) { document.getElementById('np-serial').focus(); return; }
        }
      }

      btn.disabled = true;
      btn.textContent = 'جارٍ الإضافة…';

      try {
        var res = await fetch('/api/products', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            // ⚠ اسم الجهاز = اسم الموديل. للإكسسوار بيتكتب بإيد.
            name: isDevice ? modelName : document.getElementById('np-name').value,
            productType: typeEl ? typeEl.value : 'accessory',
            serialNumber: isDevice && !(noSnEl && noSnEl.checked)
              ? document.getElementById('np-serial').value
              : null,
            // ⚠ بتتبعت للجهاز بس. الإكسسوار مالوش سريال أصلاً،
            // فـ"غير متاح" عليه جملة بلا معنى — والخادم بيرفضها.
            serialUnavailable: isDevice && !!(noSnEl && noSnEl.checked),
            // ⚠ المورّد بمعرّفه، مش باسمه كنص.
            // الاسم بيتقرا من السجل وقت العرض — فلو التاجر
            // غيّر اسمه، كل بضاعةه بتتحدّث لوحدها.
            supplierId: document.getElementById('np-supplier').value || null,
            // ⚠ التسوية بتتبعت مع نفس الطلب مش في نداء تاني.
            // نداءين معناهم إن الفشل بين الاتنين بيسيب جهاز
            // بلا دين أو دين بلا جهاز.
            settle: settleEl ? settleEl.value : 'NONE',
            treasuryId: (settleEl && settleEl.value === 'PAID')
              ? document.getElementById('np-treasury').value
              : null,
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
            modelId: modelId || null,
            colorId: document.getElementById('np-color').value || null
          })
        });
        var data = await res.json().catch(function () { return null; });

        msg.hidden = false;
        if (res.ok) {
          msg.setAttribute('data-tone', 'ok');
          msgText.textContent = 'تمت إضافة المنتج.';

          // ══ ⚠ الملصق بيتعرض **قبل** التحديث، ودي التفصيلة كلها ══
          //
          // الملصق بيتبني من القيم اللي في النموذج قدامنا دلوقتي.
          // لو حدّثنا الصفحة الأول واستنّينا الصفّ يظهر، كنا
          // هنحتاج نعرف معرّف المنتج الجديد ونستنّى الرسم —
          // وأي تأخير هيخلّي السؤال يطلع بعد ما الشاشة اتغيّرت.
          //
          // ⚠ والرفض قرار كامل مش تأجيل: لو قال لأ، الصفحة
          // بتتحدّث عادي والزرار على الصفّ لسه موجود يطبع منه
          // في أي وقت. فمفيش حاجة بتضيع.
          try {
            // ⚠⚠ المعرّف بيتاخد من المتغيّر data اللي اتقري فوق،
            // مش بنداء تاني لـ res.json().
            //
            // ══ الغلطة اللي كانت هنا ══
            // كنت بنادي res.json() تاني. وجسم الاستجابة **مجرى
            // بيتقرا مرة واحدة** — التانية بترمي استثناء، والاستثناء
            // كان بيروح للـcatch تحت فيختفي سؤال الطباعة خالص.
            //
            // والأوحش إن الرسالة اللي كانت بتظهر ("تعذّر تجهيز
            // الملصق") صحيحة تمامًا وبتشاور على المكان الغلط —
            // فالواحد يقعد يدوّر في كود الملصق والغلط في القراءة.
            //
            // تشبيه: زي ما تشرب كوباية وترجع تدوّر على نفس المية
            // فيها. مش هتلاقيها — وهي اتشربت مش ضاعت.
            var newId = data && data.id ? data.id : '';

            var wantLabel = confirm('تمت الإضافة. تطبع ملصق للمنتج؟');
            if (wantLabel) {
              window.printHtml(labelHtml({
                id: newId,
                name: isDevice ? modelName : document.getElementById('np-name').value,
                // ⚠ فاضي لو "غير متاح" — والملصق بيطلع بالرمز
                // من غير سطر السريال. الرمز نفسه موجود دايمًا،
                // فالجهاز بيتمسح عادي حتى وهو بلا رقم.
                serial: isDevice && !(noSnEl && noSnEl.checked)
                  ? document.getElementById('np-serial').value.trim()
                  : '',
                isDevice: isDevice,
                storage: isDevice ? document.getElementById('np-storage').value : '',
                battery: isDevice ? document.getElementById('np-battery').value : '',
                customs: isDevice
                  && document.getElementById('np-customs').value === 'true',
                entry: document.getElementById('np-entry').value || '',
                price: document.getElementById('np-price').value || ''
              }), [LABEL_W_MM, LABEL_H_MM]);
              // مهلة تكفي حوار الطباعة يفتح قبل ما الصفحة تروح
              setTimeout(function () { window.location.reload(); }, 2500);
              return;
            }
          } catch (labelErr) {
            // ⚠ فشل الملصق ما يصحّش يبلّع نجاح الإضافة.
            // المنتج **اتسجّل فعلاً** في القاعدة؛ ورقة ما طلعتش
            // مسألة تانية خالص، وبتتحل بزرار الطباعة على الصفّ.
            say('تمت الإضافة، لكن تعذّر تجهيز الملصق.', false);
          }

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
      // فشل قراءة الرفّ ما يصحّش يعطّل شاشة البضاعة كلها
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
      // فشل القراءة ما يصحّش يعطّل شاشة البضاعة
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
  // ⚠ الفلترة في المتصفح مش على الخادم. الصفحة محمّلة البضاعة
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
  var activeColor = '';
  // '' = الكل · 'accessory' = درج الإكسسوار · 'device' = درج الأجهزة
  var activeMode = '';
  // '' = كل العيلات · 'IPHONE' · 'ANDROID'
  var activeFamily = '';
  var activeStorage = '';

  /**
   * إخفاء شرايح الموديلات اللي مش من العيلة المفتوحة.
   *
   * ⚠ إخفاء مش تعطيل. الشريحة المعطّلة بتفضل واخدة مكان في
   * شريط ضيق أصلاً، والمستخدم بيفضل يمرّر على حاجات ما يقدرش
   * يضغطها.
   *
   * ⚠ و«بلا موديل» بيفضل ظاهر دايمًا: الأجهزة اللي لسه ما
   * اتصنّفتش لازم يبقى ليها طريق توصلها بيه.
   */
  function paintFamilyChips() {
    var box = document.getElementById('models');
    if (!box) return;
    var chips = box.querySelectorAll('[data-family]');
    for (var i = 0; i < chips.length; i++) {
      var fam = chips[i].getAttribute('data-family');
      chips[i].hidden = !!activeFamily && fam !== activeFamily;
    }
  }
  var activeCustoms = '';

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
      var okColor = !activeColor
        || (row.getAttribute('data-color') || '__none__') === activeColor;
      var okStorage = !activeStorage
        || (row.getAttribute('data-storage') || '__none__') === activeStorage;
      var okCustoms = !activeCustoms
        || (row.getAttribute('data-customs') || 'false') === activeCustoms;
      // ⚠ الدرج بيفلتر النوع كمان مش بيفتح شرايط وبس. من غير
      // ده، "درج الأجهزة" بيفضل شايف الإكسسوار — يبقى اسم على
      // قايمة مش درج.
      var okMode = !activeMode || row.getAttribute('data-type') === activeMode;

      // ══ ⚠ العيلة بتتقرا من **الموديل** مش من المنتج ══
      //
      // المنتج مالوش عمود عيلة، وموديله هو اللي معلّم. فبنجيب
      // موديل الصفّ وندوّر على عيلته في الشريط.
      //
      // ⚠ ودي مش لفّة زيادة — دي اللي بتخلّي تصنيف موديل واحد
      // ينقل **كل** أجهزته وإكسسواراته للدرج الصح في نفس
      // اللحظة. لو العيلة كانت متخزّنة على المنتج، كنّا هنحتاج
      // نعدّي على كل صف كل مرة تصنّف موديل.
      var okFamily = true;
      if (activeFamily) {
        var rowModel = row.getAttribute('data-model') || '';
        var chip = rowModel
          ? document.querySelector('#models [data-model="' + rowModel + '"]')
          : null;
        okFamily = !!chip && chip.getAttribute('data-family') === activeFamily;
      }

      // ══ ⚠ المخزون مقفول لحد ما تفتح درج ══
      //
      // قايمة بكل البضاعة من غير أي درج مفتوح مش قايمة —
      // دي كومة. والموظّف بيمرّر فيها بدل ما يختار.
      //
      // ⚠ والبحث بيفتحها: لو كتبت حاجة في خانة البحث، إنت
      // عارف بتدوّر على إيه — فالكومة بتبقى نتيجة مش كومة.
      var browsing = !!activeMode || !!activeDrawer || !!q;

      // ⚠ الستة كلهم بـ"و". كل شريط بيضيّق اللي قبله، فـ
      // "جرابات" + "١٢ برو ماكس" + "أسود" = الجراب الأسود
      // للـ١٢ برو ماكس بالظبط.
      var match = browsing && okText && okMode && okFamily && okDrawer && okModel
        && okColor && okStorage && okCustoms;
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
      var anyFilter = q || activeMode || activeDrawer || activeModel
        || activeColor || activeStorage || activeCustoms || activeFamily;
      searchNote.textContent = anyFilter ? shown + ' نتيجة' : DEFAULT_NOTE;
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

  /**
   * ══════════ مصنع صفوف الشرايط ══════════
   *
   * ⚠ خمس صفوف بنفس السلوك بالحرف: امسح العلامة من الكل، حطّها
   * على المضغوط، غيّر المتغيّر، أعِد الفلترة.
   *
   * كتابته خمس مرات معناه إن أي تصليح مستقبلي لازم يتعمل خمس
   * مرات — واللي بينُسى بيفضل شغّال بالغلط.
   */
  function wireRow(el, attr, onPick) {
    if (!el) return;
    el.addEventListener('click', function (e) {
      var chip = e.target.closest ? e.target.closest('.drawer') : null;
      if (!chip || !chip.hasAttribute(attr)) return;

      var all = el.querySelectorAll('.drawer');
      for (var i = 0; i < all.length; i++) all[i].removeAttribute('data-on');
      chip.setAttribute('data-on', '');

      onPick(chip.getAttribute(attr) || '');
      runSearch();
    });
  }

  /**
   * ══════════ الصفوف المشتقّة ══════════
   *
   * ⚠ المساحة والضريبة مالهمش سجل — بيتبنوا من الصفوف نفسها.
   *
   * والصفّ بيتخفي لو مفيش قيم، عشان المحل اللي ما بيسجّلش مساحات
   * ما يشوفش صفّ فاضي بيقفل شاشته من غير فايدة.
   */
  function buildDerived(rowId, listId, attr, chipAttr, label) {
    var row = document.getElementById(rowId);
    var list = document.getElementById(listId);
    if (!row || !list) return;

    var rows = document.querySelectorAll('.prod-row[data-searchable]');
    var seen = [];
    for (var i = 0; i < rows.length; i++) {
      var v = rows[i].getAttribute(attr);
      if (!v || v === '__none__') continue;
      if (seen.indexOf(v) === -1) seen.push(v);
    }
    // ⚠ الصفّ الفاضي بيتعلّم عشان «showRow» ما تفتحهوش.
    // زرار بيفتح صفّ فاضي بيخلّي المستخدم يفتكر إن فيه عطل.
    if (!seen.length) { row.setAttribute('data-empty', '1'); return; }

    seen.sort();
    var html = '<button class="drawer" type="button" ' + chipAttr + '="" data-on>الكل</button>';
    for (var k = 0; k < seen.length; k++) {
      var text = label ? label(seen[k]) : seen[k];
      html += '<button class="drawer" type="button" ' + chipAttr + '="'
        + seen[k] + '">' + text + '</button>';
    }
    list.innerHTML = html;
    // ⚠ بيفضل مخفي — الزرار هو اللي بيفتحه، مش البناء.
    row.removeAttribute('data-empty');
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

        // ══ ⚠ العيلة: بتتاخد من الدرج المفتوح لو فيه واحد ══
        //
        // إنت واقف في درج الآيفون وبتضيف موديل — يبقى بديهي
        // إنه آيفون. السؤال هنا كان هيبقى تكرار لحاجة الشاشة
        // عارفاها.
        //
        // ⚠ ولو مفيش درج مفتوح (إنت في «الكل» أو في درج
        // الإكسسوار)، بنسأل — لأن ساعتها مفيش أي دليل، والتخمين
        // بيحطّ الموديل في درج غلط وهو شكله سليم.
        var family = activeFamily;
        if (!family) {
          var pick = prompt('العيلة؟ اكتب 1 للآيفون · 2 للأندرويد · سيبها فاضية لو مش متأكد');
          if (pick === null) return;
          pick = pick.trim();
          if (pick === '1') family = 'IPHONE';
          else if (pick === '2') family = 'ANDROID';
          else family = null;
        }

        try {
          var res = await fetch('/api/products/models', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
              name: name,
              brand: brand.trim() || null,
              family: family
            })
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
      paintTools();
      runSearch();
    });
  }

  // ══════════ شرائط الألوان ══════════
  var colorsEl = document.getElementById('colors');
  if (colorsEl) {
    colorsEl.addEventListener('click', async function (e) {
      var chip = e.target.closest ? e.target.closest('.drawer') : null;
      if (!chip) return;

      // ─── لون جديد ───
      if (chip.hasAttribute('data-add-color')) {
        var name = prompt('اسم اللون؟');
        if (name === null) return;
        name = name.trim();
        if (!name) return;

        // ⚠ الكود اختياري. لو اتساب فاضي بيتعرض بالاسم وبس —
        // وده أحسن من نقطة سودا بتخلّي المستخدم يفتكر إنه أسود.
        var hex = prompt('كود اللون؟ (اختياري — بصيغة #RRGGBB)');
        if (hex === null) hex = '';

        try {
          var res = await fetch('/api/products/colors', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ name: name, hex: hex.trim() || null })
          });
          var data = await res.json();
          if (!res.ok || !data.ok) {
            say((data.error && data.error.message) || 'تعذّر إضافة اللون.', false);
            return;
          }
          window.location.reload();
        } catch (err) {
          say('تعذّر الاتصال بالخادم.', false);
        }
        return;
      }

      // ─── اختيار لون ───
      if (!chip.hasAttribute('data-color')) return;
      var all = colorsEl.querySelectorAll('.drawer');
      for (var j = 0; j < all.length; j++) all[j].removeAttribute('data-on');
      chip.setAttribute('data-on', '');

      activeColor = chip.getAttribute('data-color') || '';
      paintTools();
      runSearch();
    });
  }

  /**
   * ══════════ شريط الأدوات ══════════
   *
   * ⚠ صفّ شرايط واحد ظاهر في المرة. الخمسة المفتوحين كانوا
   * بياخدوا نص الشاشة.
   *
   * ══ والعلامة على الزرار مش على الشريط وحده ══
   * الفلتر الشغّال ومخفي بيخلّي المستخدم يفتكر إن نص المخزون
   * اتمسح. فالزرار بيفضل معلّم طول ما فلتره شغّال، حتى لو
   * صفّه مقفول.
   */
  var toolsEl = document.querySelector('.tools');
  var filterTools = document.getElementById('filter-tools');
  var openRow = '';

  var ROWS = {
    cat: 'row-cat', dev: 'row-model',
    color: 'row-color', model: 'row-model',
    storage: 'row-storage', customs: 'row-customs'
  };

  function showRow(key) {
    for (var k in ROWS) {
      var el = document.getElementById(ROWS[k]);
      if (el) el.hidden = true;
    }
    // ⚠ المساحة والضريبة صفوفهم بتفضل مخفية لو مبنيتش أصلاً
    // (يعني مفيش منتج ليه مساحة). الشريط الفاضي أوحش من غيابه.
    if (!key) { openRow = ''; return; }
    var target = document.getElementById(ROWS[key]);
    if (!target) { openRow = ''; return; }
    if (target.getAttribute('data-empty') === '1') { openRow = ''; return; }
    target.hidden = false;
    openRow = key;
  }

  /** أي أدوات فلتر تبان — حسب الدرج المفتوح */
  function syncFilterTools() {
    if (!filterTools) return;
    var subs = filterTools.querySelectorAll('[data-sub]');
    for (var i = 0; i < subs.length; i++) {
      var only = subs[i].getAttribute('data-for');
      subs[i].hidden = !!only && !!activeMode && only !== activeMode;
    }
  }

  /** العلامات: الوضع الشغّال + كل فلتر ليه قيمة */
  function paintTools() {
    var on = {
      cat: activeMode === 'accessory',
      dev: activeMode === 'device',
      color: !!activeColor,
      model: !!activeModel,
      storage: !!activeStorage,
      customs: !!activeCustoms
    };
    // ⚠ وزرار الفلتر نفسه بيتعلّم لو أي أداة تحته شغّالة.
    // من غير كده، المستخدم مش هيعرف إن فيه حاجة تتلغي —
    // والزرار اللي بيلغي لازم يقول إن فيه حاجة تُلغى.
    on.flt = on.color || on.model || on.storage || on.customs;

    var all = document.querySelectorAll('.tool');
    for (var i = 0; i < all.length; i++) {
      var key = all[i].getAttribute('data-tool') || all[i].getAttribute('data-sub');
      if (on[key]) all[i].setAttribute('data-on', '');
      else all[i].removeAttribute('data-on');
    }
  }

  if (toolsEl) {
    toolsEl.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-tool]') : null;
      if (!btn) return;
      var key = btn.getAttribute('data-tool');

      if (key === 'flt') {
        if (!filterTools) return;
        var closing = !filterTools.hidden;
        filterTools.hidden = closing;

        // ══ ⚠ القفل بيلغي الفلاتر، مش بيخبّيها ══
        //
        // الفلتر اللي بيتخبّى وهو شغّال بيسيب المستخدم قدّام
        // شاشة فاضية بلا سبب ظاهر — "٠ نتيجة" ومفيش حاجة
        // مكتوبة توضّح ليه.
        //
        // فقفل الفلتر بقى هو زرار الإلغاء نفسه. مخرج واحد
        // معروف بدل ما المستخدم يفتح كل أداة ويرجّعها "الكل"
        // واحدة واحدة.
        //
        // ⚠ والدرج **ما بيتلغيش** معاهم. هو مش تحت الفلتر —
        // له زراره وضغطة تانية عليه بترجّع الكل.
        if (closing) {
          activeColor = ''; activeModel = '';
          activeStorage = ''; activeCustoms = '';
          clearRow('colors', 'data-color');
          clearRow('models', 'data-model');
          clearRow('storages', 'data-storage');
          clearRow('customs', 'data-customs');
          showRow('');
          paintTools();
          runSearch();
        }

        syncFilterTools();
        return;
      }

      // ─── التلات أدراج ───
      var mode = key === 'cat' ? 'accessory' : 'device';
      // ⚠ العيلة بتتحدّد من الزرار. درج الإكسسوار مالوش عيلة
      // لأن الجراب ممكن يكون لآيفون أو لأندرويد — فبيشوف الكل.
      var family = key === 'iph' ? 'IPHONE' : (key === 'and' ? 'ANDROID' : '');

      if (activeMode === mode && activeFamily === family) {
        // ضغطة تانية = رجوع للكل
        activeMode = '';
        activeFamily = '';
        showRow('');
      } else {
        activeMode = mode;
        activeFamily = family;
        // ⚠ الدرجين بيفتحوا **نفس الشريط** (شريط الموديلات)،
        // والفرق إن الشرايح بتتفلتر بالعيلة. شريطين منفصلين
        // كانوا هيبقوا نسختين من نفس القايمة — ونسختين معناهم
        // إن العلامة على الاتنين ممكن تختلف.
        showRow(mode === 'accessory' ? 'cat' : 'model');
        paintFamilyChips();

        if (mode === 'accessory') {
          // ⚠ فلاتر النوع التاني بتتصفّى مع تغيير الدرج.
          // "مساحة 256" شغّالة وإنت في درج الجرابات بتخلّي
          // الشاشة فاضية بلا سبب ظاهر.
          activeStorage = ''; activeCustoms = '';
          clearRow('storages', 'data-storage');
          clearRow('customs', 'data-customs');
        } else {
          activeDrawer = '';
          clearRow('drawers', 'data-drawer');
          // ⚠ والموديل المختار بيتصفّى كمان لو مش من نفس
          // العيلة — وإلا بتفتح درج الآيفون وموديل سامسونج
          // لسه مختار، والنتيجة صفر بلا سبب ظاهر.
          if (activeModel) {
            var still = document.querySelector(
              '#models [data-model="' + activeModel + '"][data-family="' + family + '"]',
            );
            if (!still) { activeModel = ''; clearRow('models', 'data-model'); }
          }
        }
      }

      syncFilterTools();
      paintTools();
      runSearch();
    });
  }

  /** رجّع صفّ لـ"الكل" */
  function clearRow(id, attr) {
    var el = document.getElementById(id);
    if (!el) return;
    var chips = el.querySelectorAll('.drawer');
    for (var i = 0; i < chips.length; i++) {
      if (chips[i].getAttribute(attr) === '') chips[i].setAttribute('data-on', '');
      else chips[i].removeAttribute('data-on');
    }
  }

  if (filterTools) {
    filterTools.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-sub]') : null;
      if (!btn) return;
      var key = btn.getAttribute('data-sub');
      showRow(openRow === key ? '' : key);
    });
  }

  // ══════════ المساحة والضريبة ══════════
  //
  // ⚠ بيتبنوا من الصفوف قبل ما نربطهم — الشرايط لسه مش موجودة
  // في الصفحة وقت التحميل.
  buildDerived('row-storage', 'storages', 'data-storage', 'data-storage', null);
  buildDerived('row-customs', 'customs', 'data-customs', 'data-customs',
    function (v) { return v === 'true' ? 'خالص' : 'ضريبة'; });

  wireRow(document.getElementById('storages'), 'data-storage',
    function (v) { activeStorage = v; paintTools(); });
  wireRow(document.getElementById('customs'), 'data-customs',
    function (v) { activeCustoms = v; paintTools(); });

  // ⚠ الضريبة قيمتها على الصف "false" للي مش خالص، مش فاضية.
  // فشريط "الكل" قيمته فاضية والفلتر بيتخطّى — وده صح.

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

        // ══ ⚠ الرمز اللي على الملصق فيه **معرّف المنتج** ══
        //
        // والمعرّف ده مش مكتوب في نصّ البحث على الصفوف (ولا
        // المفروض يتكتب — محدش بيدوّر بيه بإيده). فلو حطّيناه
        // في الخانة على طول، الفلترة هترجّع صفر نتايج والموظّف
        // هيقول إن الماسح باظ.
        //
        // فبندوّر عليه كصفّ الأول. لقيناه؟ نروح له مباشرةً.
        // ملقناش؟ يبقى ده باركود عادي (سريال جهاز، أو كود
        // إكسسوار من المصنع) ويكمّل بحث نصّي زي الأول.
        // ⚠ الرمز فيه المختصر مش المعرّف الكامل، فمينفعش نقارن
        // مباشرةً. بندوّر على الصفّ اللي مختصره يطابق.
        var direct = document.querySelector('[data-pid="' + code + '"]');
        if (!direct) {
          var wanted = String(code).replace(/-/g, '').toUpperCase();
          var rows = document.querySelectorAll('[data-pid]');
          for (var ri = 0; ri < rows.length; ri++) {
            if (shortCode(rows[ri].getAttribute('data-pid')) === wanted) {
              direct = rows[ri];
              break;
            }
          }
        }
        if (direct) {
          searchEl.value = '';
          runSearch();
          direct.scrollIntoView({ block: 'center' });
          // ⚠ وميض قصير: من غيره الصفّ بيوصل لنص الشاشة ومفيش
          // حاجة بتقول "ده هو". وسط عشرين صفّ متشابه، الوصول
          // من غير إشارة = إنك لسه بتدوّر.
          direct.setAttribute('data-found', 'true');
          setTimeout(function () { direct.removeAttribute('data-found'); }, 1800);
          return;
        }

        // بنحطّه في خانة البحث وبنشغّل الفلترة — نفس ما لو
        // اتكتب بالماسح الموصول بالكمبيوتر
        searchEl.value = code;
        runSearch();
      } catch (err) {
        say(err && err.message ? err.message : 'تعذّر المسح.', false);
      }
    });
  }

  // ══════════ الرمز المختصر ══════════
  //
  // ⚠ الرمز على الملصق فيه **أول 16 خانة** من معرّف المنتج،
  // مش المعرّف كامل. والسبب مقاس مش كسل.
  //
  // المعرّف الكامل 36 حرف وفيه حروف صغيرة وشرط — فبيحتاج نمط
  // البايت ونسخة 3 (29 مربع). والـ16 خانة بحروف كبيرة بتقع
  // في نمط الحروف والأرقام ونسخة 1 (21 مربع).
  //
  // ══ والاختصار مش بيضيّع حاجة ══
  // 16 خانة ست عشرية = 64 بتّة = رقم بين صفر و18 كوينتليون.
  // احتمال إن منتجين في نفس المحل ياخدوا نفس الأول 16 خانة
  // أقل من احتمال إن الشهاب يقع على المحل.
  //
  // ⚠ ولسه ثابت: مشتق من المعرّف اللي ما بيتغيّرش، فالملصق
  // المطبوع النهاردة يفضل شغّال بعد سنة.
  function shortCode(id) {
    return String(id || '').replace(/-/g, '').toUpperCase().slice(0, 16);
  }

  // ══════════ مقاس الملصق ══════════
  //
  // ⚠ **الأربع أرقام دي هي كل اللي تغيّره لو الطابعة اتغيّرت.**
  // القيم دلوقتي مظبوطة على ٣٧ × ٢٥ مم.
  //
  // ⚠ واختيار الطابعة نفسها مش من هنا — ده حوار الطباعة بتاع
  // المتصفح. اللي إحنا بنتحكم فيه هو **مقاس الورقة**، ولازم
  // يطابق اللي مضبوط في الطابعة وإلا هتطلع مقصوصة أو مزاحة.
  var LABEL_W_MM = 37;
  var LABEL_H_MM = 25;
  // ⚠ ضلع مربّع الـQR.
  //
  // كان 12 وطلّع الملصق على ورقتين: المحتوى بقى 32 مم على ورقة
  // 25، فالطابعة دفعت ورقة تانية. النسخة دي محسوبة تقعد في
  // 24.5 مم — فاضل نص مليمتر بس.
  //
  // ⚠ ومتكبّروش من غير ما تصغّر حاجة تانية. كل مليمتر هنا
  // محجوز، وأي زيادة بترجّع مشكلة الورقتين.
  //
  // ══ ⚠ الرقم ده محسوب، مش مختار بالذوق ══
  //
  // طابعة 203dpi نقطتها 0.125 مم. والرمز 21 مربع + 4 هامش
  // صامت = 25 مربع.
  //
  //     9.375 مم ÷ 25 مربع = 0.375 مم للمربع = **3 نقط بالظبط**
  //
  // ⚠ وده اللي كان ناقص. قبل كده كان 2.3 نقطة للمربع، فالطابعة
  // كانت بتقرّب: مربع ياخد نقطتين واللي جنبه ياخد تلاتة. النتيجة
  // مربعات مش متساوية — وده اللي كان مبوّظ شكل الرمز.
  //
  // ⚠ لو غيّرت الطابعة لـ300dpi، الرقم الصح يبقى 25 × 0.0847 × 3
  // = 6.35 مم. اضرب: (25.4 ÷ dpi) × 3 × 25.
  //
  // ⚠ 29 مربع (21 بيانات + 8 هامش صامت) × 0.375 مم
  //   = **3 نقط لكل مربع** في طابعة 203dpi.
  //
  // والهامش الصامت 4 مربعات زي ما المواصفة بتطلب بدل 2 —
  // القارئ محتاج فراغ أبيض حواليه عشان يعرف فين الرمز بيبتدي،
  // وده كان جزء من سبب إن الملصقات القديمة ما كانتش بتتمسح.
  //
  // ⚠ الرقم ده هو **الفاضل** من الـ25 مم بعد الستة سطور.
  // لو كبّرت أي خط في الأنماط، صغّر الرقم ده بنفس المقدار —
  // وإلا الملصق هيطلع على ورقتين.
  var LABEL_QR_MM = 10.875;

  // ══════════ طباعة الملصق ══════════
  //
  // ⚠ البناء اتفصل في دالة مستقلة عن قراءة الصفّ، والسبب عملي:
  // الملصق بقى بيتطبع من **مكانين** — زرار الصفّ في المخزون،
  // ونافذة التأكيد بعد الإضافة. ووقت الإضافة الصفّ ده **لسه
  // مش موجود** أصلًا لأن الصفحة ما اتحدّثتش.
  //
  // لو سبنا البناء جوّه معالج الضغطة، كنا هنكتبه تاني للنموذج —
  // ونسختين معناهم إن أي تعديل في شكل الملصق بيتنفّذ في واحدة
  // وينسى التانية.
  function labelHtml(o) {
    // ⚠ سطر المواصفات بيتبني من الموجود بس. الحقل الفاضي ما
    // بيطبعش شرطة ولا "غير محدّد" — سطر فيه فراغات بيخلّي
    // الزبون يسأل، والملصق النضيف بيجاوب لوحده.
    var specs = [];
    if (o.storage) specs.push(o.storage);
    if (o.battery) specs.push('بطارية ' + o.battery + '٪');
    // ══ ⚠ الضريبة بتظهر بالحالتين ══
    //
    // كانت بتظهر لما تكون خالصة بس، والغياب كان بيتقرا غلط:
    // الزبون بيشوف ملصق مالوش سطر ضريبة ويفترض إنها خالصة.
    // السكوت هنا مش حياد — هو إجابة، وإجابة غلط.
    //
    // ⚠ وللأجهزة بس. الإكسسوار مالوش جمرك أصلًا، وسطر
    // "غير خالص" عليه هيخوّف زبون بلا سبب.
    if (o.isDevice) specs.push(o.customs ? 'ضريبة خالص' : 'ضريبة غير خالصة');

    var specHtml = '';
    for (var k = 0; k < specs.length; k++) specHtml += '<span>' + specs[k] + '</span>';

    // ══════════ الرمز: QR على معرّف المنتج ══════════
    //
    // ══ ⚠ ليه المعرّف مش السريال؟ ══
    // المعرّف بيتولد مرة واحدة يوم ما المنتج يتضاف، وما بيتغيّرش
    // أبدًا. فالملصق اللي طبعته النهاردة يفضل شغّال حتى لو كتبت
    // السريال بكرة أو عدّلته بعد شهر.
    //
    // لو الرمز كان على السريال، كان كل تعديل يخلّي الملصق
    // المطبوع يشاور على حاجة مش موجودة — وإنت مش هتعرف غير
    // لما تمسحه ومايجيش حاجة.
    //
    // ══ ⚠ وليه QR مش باركود خطي؟ ══
    // مسألة مقاس، مش ذوق. الـIMEI ١٥ خانة في Code 39 بياخد
    // حوالي ٤٩١ وحدة عرض. على ملصق ٣٧ مم الخط الرفيع بيطلع
    // ٠.١٤ مم، والماسح محتاج ٠.١٩ على الأقل — يعني بيتطبع
    // شكله تمام وما بيتقراش.
    //
    // الـQR بيحطّ نفس المعلومة في مربّع، وبيتظبط في ١٢ مم
    // بمساحة واسعة. وكاميرا الموبايل بتقراه أحسن أصلًا.
    //
    // ⚠ وكل منتج بقى ليه رمز — حتى الإكسسوار اللي مالوش سريال.
    var codeBlock = '';
    if (o.id) codeBlock = window.qrSvg(shortCode(o.id), LABEL_QR_MM);

    // السريال بيتكتب **كنص** تحت الرمز لو موجود، عشان تقارنه
    // بعينك بالمكتوب على الجهاز من غير ما تمسح.
    var serialLine = o.serial
      ? '<div class="pr-label-code">' + o.serial + '</div>'
      : '';

    // ⚠ التاريخ بيتوحّد هنا مش عند المنادي.
    // الصفّ بيبعته متنسّق (٣٠ / ٠٨ / ٢٠٢٦) والنموذج بيبعته خام
    // (2026-08-30). من غير السطور دي، نفس الملصق بيطلع بشكلين
    // حسب إنت طبعته منين — والاختلاف ده بيخلّي الواحد يشكّ.
    var entryText = String(o.entry || '');
    if (/^\d{4}-\d{2}-\d{2}$/.test(entryText)) {
      var parts = entryText.split('-');
      entryText = parts[2] + ' / ' + parts[1] + ' / ' + parts[0];
    }

    // ⚠ المقاس بيتحطّ على العنصر نفسه مش في ملف الأنماط.
    // السبب إن نفس القيمة لازم تروح لـ@page كمان (تحت في
    // printHtml). قيمة واحدة في مكان واحد = مستحيل يختلفوا.
    // ══ ⚠ الارتفاع مفروض على العنصر، مش مسيوب للمحتوى ══
    //
    // ده الفرق بين "المفروض يقعد" و"مستحيل يخرج". الحسابات
    // فوق بتخلّيه يقعد، والسطر ده بيضمنه: أي سطر يطول يوم ما
    // (اسم منتج طويل، مواصفات زيادة) بيتقص عند الحد بدل ما
    // يدفع ورقة تانية.
    //
    // ⚠ والقص أرحم من الورقتين: ملصق ناقص سطر بيتقرا، وملصق
    // متقسّم على ورقتين بيتقطع نصين ويتحطّ في الزبالة.
    // ══ ⚠ الترتيب عمود واحد — والمقايضة مكتوبة هنا ══
    //
    // كل حاجة فوق بعض. الشكل ده أوضح في القراءة بالعين، بس
    // تمنه إن الارتفاع (25 مم) بيتقسّم على ستة سطور، والرمز
    // بياخد **اللي فاضل** منهم.
    //
    // ⚠ يعني أي تكبير في أي خط تحت بيصغّر الرمز مباشرةً.
    // بالخطوط الكبيرة كان الرمز هيبقى 7.9 مم ومربعه 2.2 نقطة —
    // وده تحت حدّ القراءة. فالخطوط مضبوطة عشان الرمز يقعد
    // على 10.875 مم بالظبط.
    return '<div class="pr-doc pr-label" style="width:' + LABEL_W_MM +
      'mm;height:' + LABEL_H_MM + 'mm">' +
      '<div class="pr-label-shop">' + SHOP_NAME + '</div>' +
      '<div class="pr-label-name">' + (o.name || '') + '</div>' +
      codeBlock +
      serialLine +
      (specHtml ? '<div class="pr-label-spec">' + specHtml + '</div>' : '') +
      '<div class="pr-label-foot">' +
        '<span>' + entryText + '</span>' +
        '<span>' + (o.price ? o.price + ' ج.م' : '') + '</span>' +
      '</div>' +
    '</div>';
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-label]') : null;
    if (!btn) return;

    var row = document.querySelector('[data-pid="' + btn.getAttribute('data-label') + '"]');
    if (!row) return;

    var serial = row.getAttribute('data-serial') || '';

    window.printHtml(labelHtml({
      id: row.getAttribute('data-pid') || '',
      name: row.getAttribute('data-name') || '',
      serial: serial,
      isDevice: row.getAttribute('data-type') === 'device',
      storage: row.getAttribute('data-storage') || '',
      battery: row.getAttribute('data-battery') || '',
      customs: row.getAttribute('data-customs') === 'true',
      entry: row.getAttribute('data-entry') || '',
      price: row.getAttribute('data-price') || ''
    }), [LABEL_W_MM, LABEL_H_MM]);
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
 * مفيش مبيعات، مفيش أرباح، مفيش أرصدة خزنة، مفيش مخزون.
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
                          والبضاعة والعملاء والفواتير وحركات الخزنة نهائيًا.
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
          <p class="field-hint">كل فرع يحصل على خزنة نقدية تلقائيًا — بدونها لا يمكن إتمام بيع.</p>
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
        c.movementCount + ' حركة خزنة · ' + c.auditCount + ' سطر تدقيق.';

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
        رصيد الخزنة يقول كم مالًا لديك الآن. هذه القائمة تقول كم ربحت.
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
  /** ⚠ الفرع مع كل خزنة — الشاشة بتفلتر بيه وقت السداد */
  treasuries: Array<{ treasuryId: string; name: string; branchId: string | null }>;
  /**
   * فروع المحل — **فاضية لغير صاحب المحل**.
   *
   * مدير الفرع مالوش اختيار: فرعه بيتاخد من جلسته في كل حركة.
   * وإرسال القايمة له كان هيدّي إحساس كاذب بإنه يقدر يختار.
   */
  branches: Array<{ branchId: string; name: string }>;
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
      data.branches,
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

  <!-- ══ ⚠ السداد السريع فوق كل حاجة ══
       ده الفعل اللي بيتعمل كل يوم: التاجر جه، دفعتله، خلاص.
       وقبل كده كان محتاج تفتح كارت المورّد وتختار النوع وتظبط
       الخزنة — أربع خطوات لفعل واحد.

       ⚠ والأزرار التانية (دين قديم · خصم) فضلت جوّه الكارت،
       لأنها بتحصل مرة كل شهور. المكان الأعلى للأكثر تكرارًا. -->
  <div class="panel">
    <div class="panel-body">
      <label class="field-label" for="pay-sup">سداد سريع</label>
      <select class="field-input" id="pay-sup">
        <option value="">— اختر المورّد —</option>
      </select>

      <label class="field-label" for="pay-amount">المبلغ</label>
      <input class="field-input" id="pay-amount" type="text" inputmode="decimal"
        dir="ltr" placeholder="1500.00" autocomplete="off">

      <!-- ══ الفرع — لصاحب المحل وحده ══
           ⚠ مدير الفرع مش بيشوف الخانة دي خالص: فرعه بيتاخد
           من جلسته، وخزائنه هي الوحيدة الواصلة له أصلاً.

           ⚠ واختيار الفرع بيفلتر الخزائن تحته. من غير كده،
           صاحب المحل بيختار فرع المعادي ويلاقي خزائن فيصل في
           القايمة — والسداد بينزل من دين الفرع الغلط. -->
      <div class="field" id="pay-branch-field" hidden>
        <label class="field-label" for="pay-branch">الفرع</label>
        <select class="field-input" id="pay-branch">
          ${data.branches.map(
            (b) => html`<option value="${b.branchId}">${b.name}</option>`,
          )}
        </select>
      </div>

      <label class="field-label" for="pay-treasury">الخزنة</label>
      <select class="field-input" id="pay-treasury">
        ${data.treasuries.map(
          (t) => html`<option value="${t.treasuryId}">${t.name}</option>`,
        )}
      </select>

      <button class="btn-mini" type="button" id="pay-go">سداد</button>
      <p class="field-hint">
        المبلغ يخرج من الخزنة فورًا وينزل من دين الفرع التابعة له.
      </p>
    </div>
  </div>

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
        السداد يخرج من الخزنة فورًا، ولا يُحتسب مصروفًا في قائمة الدخل —
        تكلفة البضاعة تُحتسب عند بيعها.
      </p>
      <!-- ⚠ البحث بيفلتر الصفوف المعروضة، مش بيطلب من الخادم.
           القايمة كلها موجودة أصلاً في الصفحة، ورحلة شبكة لكل
           حرف كانت هتبطّئ الكتابة بلا فايدة. -->
      <input class="field-input" id="sup-search" type="search"
        placeholder="ابحث باسم المورّد" autocomplete="off">

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
  treasuries: Array<{ treasuryId: string; name: string; branchId: string | null }>,
  /** فاضية لغير صاحب المحل */
  branches: Array<{ branchId: string; name: string }>,
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
  /** آخر قايمة اتحمّلت — بيستخدمها التصدير */
  var LAST_LIST = [];

  // ══════════ الفروع ══════════
  //
  // ⚠ القايمة فاضية لغير صاحب المحل، و**ده هو المفتاح**:
  // كل اختيار فرع في الشاشة بيتفعّل بوجودها. مدير الفرع
  // بيشوف شاشة أبسط لأنه مالوش قرار يتاخد أصلاً.
  var BRANCHES = ${JSON.stringify(branches)};
  var TREASURIES = ${JSON.stringify(treasuries)};
  var IS_OWNER = BRANCHES.length > 0;

  function branchWord(id) {
    for (var i = 0; i < BRANCHES.length; i++) {
      if (BRANCHES[i].branchId === id) return BRANCHES[i].name;
    }
    return null;
  }

  /**
   * سؤال الفرع.
   *
   * ⚠ بيرجّع سلسلة فاضية لغير صاحب المحل — والخادم بياخد فرعه
   * من جلسته ساعتها. السؤال هنا كان هيبقى خانة بإجابة واحدة.
   *
   * ⚠ وبيرجّع null لو ألغى، عشان اللي بينادي يفرّق بين
   * "مالوش اختيار" و"اختار يبطّل".
   */
  function askBranch(title) {
    if (!IS_OWNER) return '';

    var lines = [title, ''];
    for (var i = 0; i < BRANCHES.length; i++) {
      lines.push((i + 1) + ') ' + BRANCHES[i].name);
    }
    lines.push('');
    lines.push('اكتب رقم الفرع:');

    var pick = prompt(lines.join('\\n'), '1');
    if (pick === null) return null;

    var n = parseInt(String(pick).trim(), 10);
    if (!n || n < 1 || n > BRANCHES.length) { say('رقم فرع غير صحيح.', false); return null; }
    return BRANCHES[n - 1].branchId;
  }

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
      // ⚠ نسخة محفوظة للتصدير.
      // التصدير محتاج أرقام المورّد كاملة، وقراءتها من الشاشة
      // كانت هتخلّينا نحلّل نص متنسّق — وأول تغيير في شكل
      // العرض بيكسر الملف بصمت.
      LAST_LIST = list;

      // ملء قايمة السداد السريع
      var paySel = document.getElementById('pay-sup');
      if (paySel) {
        var opts = '<option value="">— اختر المورّد —</option>';
        for (var pi = 0; pi < list.length; pi++) {
          opts += '<option value="' + list[pi].supplierId + '">' +
            list[pi].name + ' — ' + money(list[pi].balancePiastres) + '</option>';
        }
        paySel.innerHTML = opts;
      }
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

        // ⚠ الاسم والتليفون على الصفّ نفسه.
        // البحث والتعديل بيقروا منهم بدل ما يطلبوا من الخادم
        // تاني — البيانات موجودة قدامنا أصلاً.
        row.setAttribute('data-sup-id', sp.supplierId);
        row.setAttribute('data-sup-name', sp.name || '');
        row.setAttribute('data-sup-phone', sp.phone || '');

        var btn = document.createElement('button');
        btn.className = 'btn-mini';
        btn.type = 'button';
        btn.textContent = 'إجراءات';
        btn.setAttribute('data-sup-open', sp.supplierId);
        row.appendChild(btn);

        rows.appendChild(row);

        var panel = document.createElement('div');
        panel.className = 'exit-edit';
        panel.id = 'supp-' + sp.supplierId;
        panel.hidden = true;
        // ══ ⚠ الكارت بقى أزرار أفعال، مش نموذج حركة عام ══
        //
        // كان فيه قايمة "النوع" وخانة مبلغ وزرار تسجيل واحد.
        // والمشكلة إن الأنواع دي بتحصل بأزمنة مختلفة تمامًا:
        // السداد كل أسبوع، والدين القديم مرة واحدة في العمر.
        //
        // نموذج واحد لكل حاجة معناه إنك بتختار من قايمة في كل
        // مرة — وأول اختيار غلط بيسجّل دين مكان سداد، والرصيد
        // بيتحرّك في الاتجاه المعاكس.
        //
        // ⚠ والسداد اتشال من هنا خالص. مكانه فوق في الشريط
        // السريع، لأنه الفعل اليومي.
        panel.innerHTML =
          '<div class="tools">' +
            '<button class="btn-mini" type="button" ' +
              'data-sup-act="DEBT" data-sup-id="' + sp.supplierId + '">دين قديم</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sup-act="DISCOUNT" data-sup-id="' + sp.supplierId + '">خصم</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sup-edit="' + sp.supplierId + '">تعديل البيانات</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sup-csv="' + sp.supplierId + '">تصدير إكسل</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sup-pdf="' + sp.supplierId + '">تصدير PDF</button>' +
          '</div>' +
          branchTable(sp) +
          '<p class="field-hint">' +
            'الرصيد ناتج جمع الحركات، مش رقم مخزّن. تعديله بيتم بدين أو خصم.' +
          '</p>' +
          '<div id="sled-' + sp.supplierId + '">' +
            '<p class="field-hint">جارٍ فتح الدفتر…</p>' +
          '</div>';

        rows.appendChild(panel);
      }
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    }
  }

  /**
   * توزيع الدين على الفروع.
   *
   * ══ ⚠ الفروع **والإجمالي** مع بعض ══
   * ملف ٢٢ خاف من التوزيع عشان "محدش يعرف الإجمالي". والحل
   * مش إنك تختار واحد منهم — إنك توري الاتنين.
   *
   * فوق: سطر لكل فرع. تحت: خط وإجمالي. الصورتين قدّامك.
   *
   * ⚠ ومدير الفرع بيشوف فرعه بس، والإجمالي عنده = فرعه.
   * ده مش إخفاء — ده نطاق: هو مسؤول عن الرقم ده وبيقدر يسدّده،
   * وعرض دين فرع تاني عليه كان هيوريه رقم مالوش عليه سلطة.
   *
   * ⚠ و"غير موزّع" بيبان صراحةً لو موجود. إخفاؤه كان هيخلّي
   * مجموع الفروع أقل من الإجمالي بلا تفسير، والفرق ده هو أول
   * حاجة هتشكّ فيها.
   */
  function branchTable(sp) {
    var list = sp.branches || [];
    if (!list.length) return '';

    var out = '';
    for (var i = 0; i < list.length; i++) {
      var b = list[i];
      var label = b.branchName || '— غير موزّع —';

      out += '<div class="mv-row">' +
        '<div class="mv-main">' +
          '<span class="mv-title">' + escLed(label) + '</span>' +
          '<span class="mv-sub">' +
            'استلمت ' + money(b.debtPiastres) +
            ' · سدّدت ' + money(b.paidPiastres) +
            (b.lastMovement ? ' · آخر حركة ' + b.lastMovement : '') +
          '</span>' +
        '</div>' +
        '<div class="mv-side">' +
          '<span class="mv-amount" data-dir="' +
            (b.balancePiastres > 0 ? 'OUT' : 'IN') + '">' +
            money(b.balancePiastres) +
          '</span>' +
        '</div>' +
      '</div>';
    }

    // ⚠ سطر الإجمالي بيتحسب من نفس القايمة مش من رقم تاني.
    // لو جبناه من مكان مختلف، أول اختلاف بينهم بيخلّي الشاشة
    // تقول رقمين لنفس السؤال.
    var total = 0;
    for (var k = 0; k < list.length; k++) total += list[k].balancePiastres;

    out += '<div class="mv-row">' +
      '<div class="mv-main">' +
        '<span class="mv-title">الإجمالي</span>' +
      '</div>' +
      '<div class="mv-side">' +
        '<span class="mv-amount" data-dir="' + (total > 0 ? 'OUT' : 'IN') + '">' +
          money(total) +
        '</span>' +
      '</div>' +
    '</div>';

    return out;
  }

  // ══════════ الدفتر ══════════
  //
  // ⚠ المجموع لوحده ما بيخليكش تعمل حاجة.
  //
  // "عليك 47,000 لأحمد" رقم بتصدّقه أو تختلف عليه وبس. الدفتر
  // بيرد على الأربع أسئلة اللي بتسألها فعلاً وإنت واقف قدّامه:
  // إمتى · على إيه · مين سجّلها · بكام.

  /**
   * ⚠ تهريب قبل الحقن.
   * أسماء الأجهزة والملاحظات بيكتبها المستخدم، وحقنها في
   * innerHTML من غير تهريب بيخلّي علامة أقلّ من واحدة تكسر
   * الدفتر كله.
   */
  function escLed(raw) {
    return String(raw == null ? '' : raw)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** مفتاح الدور بيتترجم هنا مش في الخادم — الكلمة قرار واجهة */
  function roleWord(key) {
    if (key === 'SUPER_ADMIN') return 'صاحب المحل';
    if (key === 'BRANCH_MANAGER') return 'مدير الفرع';
    if (key === 'STAFF') return 'مندوب مبيعات';
    return 'غير معروف';
  }

  /**
   * رسم سطر واحد.
   *
   * ⚠ الاتجاه بلون: الدين بلون المنصرف (زاد عليك)، والسداد
   * والخصم بلون الوارد (نقص). نفس ترميز شاشة الخزنة بالظبط —
   * العين اتعوّدت عليه ومش هتحتاج تقرا الكلمة.
   */
  function ledRow(m) {
    var kind = m.direction === 'DEBT'
      ? 'دين'
      : (m.isDiscount ? 'خصم' : 'سداد');

    // ⚠ العنوان: اسم الجهاز الأول، والملاحظة احتياطي.
    // الحركات القديمة والدين اليدوي مالهمش جهاز مربوط.
    var title = m.itemName || m.note || kind;

    var bits = [m.occurredAt];
    // ⚠ الفرع بيبان لصاحب المحل بس. مدير الفرع كل حركاته في
    // فرعه أصلاً، فكتابته على كل سطر ضجيج بيغطّي على المهم.
    if (IS_OWNER) bits.push(m.branchName || 'غير موزّع');
    if (m.entryDate && m.entryDate !== m.occurredAt) bits.push('دخل ' + m.entryDate);
    if (m.serialNumber) bits.push(m.serialNumber);
    if (m.treasuryName) bits.push('من ' + m.treasuryName);
    bits.push(m.actorName + ' — ' + roleWord(m.actorRole));

    // ⚠ الملاحظة بتتعرض لوحدها لما تكون **زيادة** على العنوان.
    // لو العنوان هو الملاحظة نفسها، تكرارها بيملا السطر بلا فايدة.
    if (m.note && m.note !== title) bits.push(m.note);

    return '<div class="mv-row">' +
      '<div class="mv-main">' +
        '<span class="mv-title">' + escLed(kind + ' · ' + title) + '</span>' +
        '<span class="mv-sub">' + escLed(bits.join(' · ')) + '</span>' +
      '</div>' +
      '<div class="mv-side">' +
        '<span class="mv-amount" data-dir="' +
          (m.direction === 'DEBT' ? 'OUT' : 'IN') + '">' +
          money(m.amountPiastres) +
        '</span>' +
      '</div>' +
    '</div>';
  }

  /**
   * تحميل الدفتر.
   *
   * ⚠ مرة واحدة لكل مورّد. الحالة متعلّمة على العنصر نفسه
   * (سمة data-loaded) مش في متغيّر جنبه — العنصر بيتمسح مع أي
   * إعادة رسم، والعلامة بتروح معاه فما بيفضلش عندنا ذاكرة
   * بتقول "اتحمّل" وهو مش موجود أصلاً.
   */
  async function loadLedger(id) {
    var box = document.getElementById('sled-' + id);
    if (!box || box.getAttribute('data-loaded') === '1') return;

    try {
      var res = await fetch('/api/suppliers/' + encodeURIComponent(id) + '/movements', {
        credentials: 'same-origin'
      });
      var data = await res.json();

      if (!res.ok || !data.ok) {
        box.innerHTML = '<p class="field-hint">تعذّر فتح الدفتر.</p>';
        return;
      }

      var list = data.movements || [];
      if (!list.length) {
        box.innerHTML = '<p class="field-hint">مفيش حركات على الحساب ده لسه.</p>';
        box.setAttribute('data-loaded', '1');
        return;
      }

      var out = '';
      for (var i = 0; i < list.length; i++) out += ledRow(list[i]);
      box.innerHTML = out;
      box.setAttribute('data-loaded', '1');
    } catch (err) {
      box.innerHTML = '<p class="field-hint">تعذّر الاتصال بالخادم.</p>';
    }
  }

  // فتح/قفل لوحة الحركة
  //
  // ⚠ الدفتر بيتحمّل عند **الفتح** مش مع الصفحة.
  //
  // تحميله لكل مورّد مع الصفحة معناه عشرين رحلة شبكة عشان
  // تبصّ على واحد. والفتح هو اللحظة اللي المستخدم بيقول فيها
  // إنه مهتم بالمورّد ده تحديدًا.
  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sup-open]') : null;
    if (!btn) return;
    var id = btn.getAttribute('data-sup-open');
    var panel = document.getElementById('supp-' + id);
    if (!panel) return;

    panel.hidden = !panel.hidden;
    if (!panel.hidden) loadLedger(id);
  });

  // ══════════ البحث ══════════
  //
  // ⚠ بيفلتر المعروض، ومش بيطلب من الخادم. القايمة كلها موجودة
  // في الصفحة أصلاً، ورحلة شبكة لكل حرف كانت هتبطّئ الكتابة.
  var searchEl = document.getElementById('sup-search');
  if (searchEl) {
    searchEl.addEventListener('input', function () {
      var q = searchEl.value.trim().toLowerCase();
      var all = rows.querySelectorAll('[data-sup-name]');
      for (var i = 0; i < all.length; i++) {
        var name = (all[i].getAttribute('data-sup-name') || '').toLowerCase();
        var hit = !q || name.indexOf(q) !== -1;
        all[i].hidden = !hit;
        // ⚠ اللوحة المفتوحة بتتخفي مع صفّها.
        // من غير ده بتفضل معلّقة تحت صفّ مختفي.
        var panel = document.getElementById('supp-' + all[i].getAttribute('data-sup-id'));
        if (panel && !hit) panel.hidden = true;
      }
    });
  }

  // ══════════ السداد السريع ══════════
  // ══════════ فلترة الخزائن بالفرع ══════════
  //
  // ⚠ الفرع بيتحدّد بالخزنة **في الخادم**، مش بالخانة دي.
  //
  // يعني الخانة دي راحة عين مش حراسة: بتضيّق القايمة عشان
  // العين ما تغلطش. والقفل الحقيقي إن الخادم بيقرا فرع الخزنة
  // وبينزّل منه — فمستحيل يحصل "سداد على فرع من خزنة فرع تاني"
  // مهما اتبعت من الشاشة.
  function paintTreasuries() {
    var field = document.getElementById('pay-branch-field');
    var brEl = document.getElementById('pay-branch');
    var trEl = document.getElementById('pay-treasury');
    if (!trEl) return;

    if (field) field.hidden = !IS_OWNER;
    if (!IS_OWNER) return;

    var want = brEl ? brEl.value : '';
    var keep = trEl.value;
    var out = '';
    var found = false;

    for (var i = 0; i < TREASURIES.length; i++) {
      var t = TREASURIES[i];
      if (want && t.branchId !== want) continue;
      out += '<option value="' + t.treasuryId + '">' + t.name + '</option>';
      if (t.treasuryId === keep) found = true;
    }

    // ⚠ الفرع اللي مالوش خزنة بيبان صراحةً بدل قايمة فاضية.
    // القايمة الفاضية بتخلّي الواحد يفتكر الشاشة معلّقة.
    if (!out) out = '<option value="">— مفيش خزنة في الفرع ده —</option>';

    trEl.innerHTML = out;
    if (found) trEl.value = keep;
  }

  var payBranchEl = document.getElementById('pay-branch');
  if (payBranchEl) payBranchEl.addEventListener('change', paintTreasuries);
  paintTreasuries();

  var payBtn = document.getElementById('pay-go');
  if (payBtn) {
    payBtn.addEventListener('click', async function () {
      var sup = document.getElementById('pay-sup');
      var amt = document.getElementById('pay-amount');
      var tre = document.getElementById('pay-treasury');

      if (!sup || !sup.value) { say('اختر المورّد.', false); return; }
      if (!amt || !amt.value.trim()) { say('اكتب المبلغ.', false); return; }
      if (!tre || !tre.value) { say('اختر الخزنة.', false); return; }

      var result = await send(
        '/api/suppliers/' + encodeURIComponent(sup.value) + '/movement',
        { kind: 'PAYMENT', amount: amt.value, treasuryId: tre.value, note: null },
        payBtn, 'جارٍ السداد…'
      );
      if (result) {
        say('تم السداد — الرصيد الآن ' + money(result.newBalance) + '.', true);
        setTimeout(function () { window.location.reload(); }, 1000);
      }
    });
  }

  // ══════════ الدين القديم والخصم ══════════
  //
  // ⚠ الاتنين بيطلبوا المبلغ في نافذة. والخصم **بيطلب السبب
  // كمان وبيرفض من غيره** — رقم بينقص بلا أثر مادي محتاج سبب
  // مكتوب، وإلا مفيش طريقة تفرّق بين خصم وغلطة بعد شهرين.
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sup-act]') : null;
    if (!btn) return;

    var kind = btn.getAttribute('data-sup-act');
    var id = btn.getAttribute('data-sup-id');
    var isDiscount = kind === 'DISCOUNT';

    var amount = prompt(isDiscount ? 'مبلغ الخصم؟' : 'إجمالي الدين القديم؟');
    if (amount === null) return;
    if (!amount.trim()) { say('اكتب المبلغ.', false); return; }

    var note = prompt(isDiscount ? 'سبب الخصم؟ (إلزامي)' : 'ملاحظة؟ (اختياري)');
    if (note === null) return;
    if (isDiscount && !note.trim()) { say('اكتب سبب الخصم.', false); return; }

    // ⚠ الفرع سؤال لصاحب المحل وحده.
    //
    // الدين والخصم مش وراهم خزنة تحدّد الفرع زي السداد، فلازم
    // نسأل. ومدير الفرع ما بيتسألش لأن فرعه بيتاخد من جلسته
    // في الخادم — والسؤال كان هيبقى خانة بإجابة واحدة.
    var branchId = askBranch(
      isDiscount ? 'الخصم ده على أنهي فرع؟' : 'الدين ده على أنهي فرع؟'
    );
    if (branchId === null) return;

    var result = await send('/api/suppliers/' + encodeURIComponent(id) + '/movement',
      {
        kind: kind,
        amount: amount,
        note: note.trim() || null,
        branchId: branchId || null
      }, btn, '…');
    if (result) {
      say('تم التسجيل — الرصيد الآن ' + money(result.newBalance) + '.', true);
      setTimeout(function () { window.location.reload(); }, 1000);
    }
  });

  // ══════════ تعديل بيانات المورّد ══════════
  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sup-edit]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-sup-edit');
    var row = rows.querySelector('[data-sup-id="' + id + '"]');
    var current = row ? row.getAttribute('data-sup-name') : '';

    var name = prompt('اسم المورّد؟', current || '');
    if (name === null) return;
    if (name.trim().length < 2) { say('اسم المورّد قصير.', false); return; }

    var phone = prompt('رقم التليفون؟ (اختياري)', row ? (row.getAttribute('data-sup-phone') || '') : '');
    if (phone === null) return;

    var result = await send('/api/suppliers/' + encodeURIComponent(id),
      { name: name.trim(), phone: phone.trim() || null }, btn, '…', 'PATCH');
    if (result) {
      say('اتحفظ.', true);
      setTimeout(function () { window.location.reload(); }, 800);
    }
  });

  // ══════════ التصدير ══════════
  //
  // ⚠ الاتنين محليّين بالكامل — مفيش مكتبة ومفيش طلب شبكة.
  //
  // الإكسل ملف CSV. إكسل بيفتحه عادي، وبناء ملف xlsx حقيقي
  // كان محتاج مكتبة تتحمّل من الإنترنت عشان جدول من خمس أعمدة.
  //
  // ⚠ وعلامة الترتيب في أوله مش زينة: من غيرها إكسل بيقرا
  // العربي كرموز مبعثرة على ويندوز العربي.
  function exportCsv(sp) {
    var lines = [
      'المورّد,' + (sp.name || ''),
      'الرصيد,' + (sp.balancePiastres / 100),
      'إجمالي الدين,' + (sp.debtPiastres / 100),
      'إجمالي السداد,' + (sp.paidPiastres / 100),
      ''
    ];
    var csv = '\\uFEFF' + lines.join('\\r\\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'حساب-' + (sp.name || 'مورّد') + '.csv';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ⚠ الـPDF بيتعمل بحوار الطباعة بتاع المتصفح ("طباعة كـPDF").
  // نفس آلية الفاتورة والملصق — مفيش محرّك PDF جديد يتصان.
  function exportPdf(sp) {
    if (typeof window.printHtml !== 'function') {
      say('الطباعة غير متاحة على هذا المتصفح.', false);
      return;
    }
    window.printHtml(
      '<div class="pr-doc">' +
        '<h3>حساب المورّد</h3>' +
        '<p>' + (sp.name || '') + '</p>' +
        '<p>الرصيد: ' + money(sp.balancePiastres) + ' ج.م</p>' +
        '<p>إجمالي الدين: ' + money(sp.debtPiastres) + ' ج.م</p>' +
        '<p>إجمالي السداد: ' + money(sp.paidPiastres) + ' ج.م</p>' +
      '</div>'
    );
  }

  document.addEventListener('click', function (e) {
    var csvBtn = e.target.closest ? e.target.closest('[data-sup-csv]') : null;
    var pdfBtn = e.target.closest ? e.target.closest('[data-sup-pdf]') : null;
    if (!csvBtn && !pdfBtn) return;

    var id = (csvBtn || pdfBtn).getAttribute(csvBtn ? 'data-sup-csv' : 'data-sup-pdf');
    var sp = null;
    for (var i = 0; i < LAST_LIST.length; i++) {
      if (LAST_LIST[i].supplierId === id) { sp = LAST_LIST[i]; break; }
    }
    if (!sp) { say('تعذّر تجهيز الملف.', false); return; }

    if (csvBtn) exportCsv(sp);
    else exportPdf(sp);
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


// ═══════════════════ شاشة حساب المحلات ═══════════════════
//
// ⚠ المرآة المقلوبة لشاشة الموردين:
//     الموردين  →  دين **عليك**
//     المحلات   →  دين **ليك**
//
// نفس الشكل ونفس الأزرار عن قصد. اللي فهم شاشة الموردين
// بيفهم دي من غير شرح، والفرق الوحيد اتجاه الفلوس.

export interface ShopsPageData {
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

export function shopsPage(data: ShopsPageData): Html {
  return shell({
    title: 'حساب المحلات',
    tenantName: data.tenantName,
    script: shopsScript(
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
  <div class="alert-box" id="shopmsg" role="alert" hidden><span id="shopmsg-text"></span></div>

  <!-- ⚠ التحصيل السريع فوق: ده الفعل اليومي. المحل بيجي يدفع،
       تختاره وتكتب المبلغ وخلاص. -->
  <div class="panel">
    <div class="panel-body">
      <label class="field-label" for="sh-pay-shop">تحصيل سريع</label>
      <select class="field-input" id="sh-pay-shop">
        <option value="">— اختر المحل —</option>
      </select>

      <label class="field-label" for="sh-pay-amount">المبلغ</label>
      <input class="field-input" id="sh-pay-amount" type="text" inputmode="decimal"
        dir="ltr" placeholder="1500.00" autocomplete="off">

      <label class="field-label" for="sh-pay-treasury">الخزنة</label>
      <select class="field-input" id="sh-pay-treasury">
        ${data.treasuries.map(
          (t) => html`<option value="${t.treasuryId}">${t.name}</option>`,
        )}
      </select>

      <button class="btn-mini" type="button" id="sh-pay-go">تحصيل</button>
      <p class="field-hint">المبلغ يدخل الخزنة فورًا وينزل من حساب المحل.</p>
    </div>
  </div>

  <details class="panel">
    <summary>إضافة محل</summary>
    <div class="panel-body">
      <label class="field-label" for="sh-name">اسم المحل</label>
      <input class="field-input" id="sh-name" type="text" maxlength="80" autocomplete="off">

      <label class="field-label" for="sh-contact">اسم المسؤول</label>
      <input class="field-input" id="sh-contact" type="text" maxlength="80" autocomplete="off">

      <label class="field-label" for="sh-phone">الهاتف</label>
      <input class="field-input" id="sh-phone" type="text" dir="ltr" maxlength="32"
        autocomplete="off">

      <button class="btn-mini" type="button" id="sh-add">إضافة</button>
    </div>
  </details>

  <details class="panel" open>
    <summary>المحلات <span id="sh-count"></span></summary>
    <div class="panel-body">
      <!-- ⚠ الرصيد الموجب معناه المحل **مديون لك** — عكس شاشة
           الموردين بالظبط. السطر ده موجود عشان محدش يقرا الرقم
           بالمعنى الغلط. -->
      <p class="field-hint">
        الرصيد محسوب من الحركات: ما خرج بالأجل ناقص ما حصّلته.
        الرقم الموجب معناه المحل مدين لك.
      </p>

      <input class="field-input" id="sh-search" type="search"
        placeholder="ابحث باسم المحل" autocomplete="off">

      <div id="sh-rows"><p class="field-hint">جارٍ التحميل…</p></div>
    </div>
  </details>
</main>
`,
  });
}

function shopsScript(
  idleTimeout: number,
  warnAt: number,
  action: 'LOGOUT' | 'LOCK',
  treasuries: Array<{ treasuryId: string; name: string }>,
): string {
  const shared = IDLE_SHARED_JS.replace('__IDLE__', String(idleTimeout))
    .replace('__WARN__', String(warnAt))
    .replace('__ACTION__', action);

  return `
${shared}
${MENU_JS}

(function () {
  var box = document.getElementById('shopmsg');
  var text = document.getElementById('shopmsg-text');
  var rows = document.getElementById('sh-rows');
  var countEl = document.getElementById('sh-count');
  /** آخر قايمة اتحمّلت — بيستخدمها التصدير */
  var LAST = [];

  function say(message, ok) {
    box.hidden = false;
    if (ok) box.setAttribute('data-tone', 'ok');
    else box.removeAttribute('data-tone');
    text.textContent = message;
    box.scrollIntoView({ block: 'nearest' });
  }

  function money(piastres) {
    var neg = piastres < 0;
    var abs = Math.abs(Math.trunc(piastres));
    return (neg ? '-' : '') + Math.floor(abs / 100).toLocaleString('en-US') +
      '.' + String(abs % 100).padStart(2, '0');
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
      if (!res.ok || !data || !data.ok) {
        say((data && data.error && data.error.message) || 'تعذّر التنفيذ.', false);
        return null;
      }
      return data;
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
      return null;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = original; }
    }
  }

  async function load() {
    try {
      var res = await fetch('/api/shops', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return null; });
      if (!res.ok || !data || !data.ok) {
        rows.innerHTML = '<p class="field-hint">تعذّر التحميل.</p>';
        return;
      }

      var list = data.shops || [];
      LAST = list;
      countEl.textContent = '(' + list.length + ')';

      var paySel = document.getElementById('sh-pay-shop');
      if (paySel) {
        var opts = '<option value="">— اختر المحل —</option>';
        for (var pi = 0; pi < list.length; pi++) {
          opts += '<option value="' + list[pi].shopId + '">' +
            list[pi].name + ' — ' + money(list[pi].balancePiastres) + '</option>';
        }
        paySel.innerHTML = opts;
      }

      rows.innerHTML = '';
      if (list.length === 0) {
        rows.innerHTML = '<p class="field-hint">مفيش محلات لسه.</p>';
        return;
      }

      for (var i = 0; i < list.length; i++) {
        var sh = list[i];

        var row = document.createElement('div');
        row.className = 'mv-row';
        row.setAttribute('data-sh-id', sh.shopId);
        row.setAttribute('data-sh-name', sh.name || '');
        row.setAttribute('data-sh-phone', sh.phone || '');

        var main = document.createElement('div');
        main.className = 'mv-main';
        var title = document.createElement('span');
        title.className = 'mv-title';
        title.textContent = sh.name;
        main.appendChild(title);

        var sub = document.createElement('span');
        sub.className = 'mv-sub';
        sub.textContent = (sh.contactName ? sh.contactName + ' · ' : '') +
          (sh.phone || '') + (sh.lastMovement ? ' · آخر حركة ' + sh.lastMovement : '');
        main.appendChild(sub);
        row.appendChild(main);

        // ⚠ الموجب هنا معناه **ليك** — فبنعرضه بلون الوارد،
        // عكس شاشة الموردين بالظبط. اللون هو اللي بيخلّي العين
        // تفرّق من غير ما تقرا.
        var bal = document.createElement('span');
        bal.className = 'mv-amount';
        bal.setAttribute('data-dir', sh.balancePiastres > 0 ? 'IN' : 'OUT');
        bal.textContent = money(sh.balancePiastres);
        row.appendChild(bal);

        var btn = document.createElement('button');
        btn.className = 'btn-mini';
        btn.type = 'button';
        btn.textContent = 'إجراءات';
        btn.setAttribute('data-sh-open', sh.shopId);
        row.appendChild(btn);

        rows.appendChild(row);

        var panel = document.createElement('div');
        panel.className = 'exit-edit';
        panel.id = 'shp-' + sh.shopId;
        panel.hidden = true;
        panel.innerHTML =
          '<div class="tools">' +
            '<button class="btn-mini" type="button" ' +
              'data-sh-edit="' + sh.shopId + '">تعديل البيانات</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sh-csv="' + sh.shopId + '">تصدير إكسل</button>' +
            '<button class="btn-mini" type="button" ' +
              'data-sh-pdf="' + sh.shopId + '">تصدير PDF</button>' +
          '</div>' +
          '<p class="field-hint">' +
            'خروج البضاعة بيتعمل من شاشة البيع، مش من هنا. ' +
            'الرصيد ناتج جمع الحركات مش رقم مخزّن.' +
          '</p>';

        rows.appendChild(panel);
      }
    } catch (err) {
      say('تعذّر الاتصال بالخادم.', false);
    }
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sh-open]') : null;
    if (!btn) return;
    var panel = document.getElementById('shp-' + btn.getAttribute('data-sh-open'));
    if (panel) panel.hidden = !panel.hidden;
  });

  var searchEl = document.getElementById('sh-search');
  if (searchEl) {
    searchEl.addEventListener('input', function () {
      var q = searchEl.value.trim().toLowerCase();
      var all = rows.querySelectorAll('[data-sh-name]');
      for (var i = 0; i < all.length; i++) {
        var name = (all[i].getAttribute('data-sh-name') || '').toLowerCase();
        var hit = !q || name.indexOf(q) !== -1;
        all[i].hidden = !hit;
        var panel = document.getElementById('shp-' + all[i].getAttribute('data-sh-id'));
        if (panel && !hit) panel.hidden = true;
      }
    });
  }

  var payBtn = document.getElementById('sh-pay-go');
  if (payBtn) {
    payBtn.addEventListener('click', async function () {
      var shop = document.getElementById('sh-pay-shop');
      var amt = document.getElementById('sh-pay-amount');
      var tre = document.getElementById('sh-pay-treasury');

      if (!shop || !shop.value) { say('اختر المحل.', false); return; }
      if (!amt || !amt.value.trim()) { say('اكتب المبلغ.', false); return; }
      if (!tre || !tre.value) { say('اختر الخزنة.', false); return; }

      var result = await send(
        '/api/shops/' + encodeURIComponent(shop.value) + '/payment',
        { amount: amt.value, treasuryId: tre.value, note: null },
        payBtn, 'جارٍ التحصيل…'
      );
      if (result) {
        say('تم التحصيل — الرصيد الآن ' + money(result.newBalance) + '.', true);
        setTimeout(function () { window.location.reload(); }, 1000);
      }
    });
  }

  document.addEventListener('click', async function (e) {
    var btn = e.target.closest ? e.target.closest('[data-sh-edit]') : null;
    if (!btn) return;

    var id = btn.getAttribute('data-sh-edit');
    var row = rows.querySelector('[data-sh-id="' + id + '"]');

    var name = prompt('اسم المحل؟', row ? (row.getAttribute('data-sh-name') || '') : '');
    if (name === null) return;
    if (name.trim().length < 2) { say('الاسم قصير.', false); return; }

    var phone = prompt('الهاتف؟', row ? (row.getAttribute('data-sh-phone') || '') : '');
    if (phone === null) return;

    var result = await send('/api/shops/' + encodeURIComponent(id),
      { name: name.trim(), phone: phone.trim() || null }, btn, '…', 'PATCH');
    if (result) {
      say('اتحفظ.', true);
      setTimeout(function () { window.location.reload(); }, 800);
    }
  });

  // ══ التصدير ══
  //
  // ⚠ الاتنين محليّين: الإكسل ملف CSV بعلامة ترتيب (من غيرها
  // العربي بيطلع رموز مبعثرة في إكسل)، والـPDF بحوار الطباعة.
  // مفيش مكتبة ومفيش طلب شبكة.
  document.addEventListener('click', function (e) {
    var csvBtn = e.target.closest ? e.target.closest('[data-sh-csv]') : null;
    var pdfBtn = e.target.closest ? e.target.closest('[data-sh-pdf]') : null;
    if (!csvBtn && !pdfBtn) return;

    var id = (csvBtn || pdfBtn).getAttribute(csvBtn ? 'data-sh-csv' : 'data-sh-pdf');
    var sh = null;
    for (var i = 0; i < LAST.length; i++) {
      if (LAST[i].shopId === id) { sh = LAST[i]; break; }
    }
    if (!sh) { say('تعذّر تجهيز الملف.', false); return; }

    if (csvBtn) {
      var lines = [
        'المحل,' + (sh.name || ''),
        'خرج بالأجل,' + (sh.totalOut / 100),
        'المحصّل,' + (sh.totalPaid / 100),
        'الباقي,' + (sh.balancePiastres / 100),
        ''
      ];
      var blob = new Blob(['\\uFEFF' + lines.join('\\r\\n')],
        { type: 'text/csv;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'حساب-' + (sh.name || 'محل') + '.csv';
      a.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      return;
    }

    if (typeof window.printHtml !== 'function') {
      say('الطباعة غير متاحة على هذا المتصفح.', false);
      return;
    }
    window.printHtml(
      '<div class="pr-doc">' +
        '<h3>حساب محل</h3>' +
        '<p>' + (sh.name || '') + '</p>' +
        '<p>خرج بالأجل: ' + money(sh.totalOut) + ' ج.م</p>' +
        '<p>المحصّل: ' + money(sh.totalPaid) + ' ج.م</p>' +
        '<p>الباقي: ' + money(sh.balancePiastres) + ' ج.م</p>' +
      '</div>'
    );
  });

  document.getElementById('sh-add').addEventListener('click', async function () {
    var name = document.getElementById('sh-name').value;
    if (!name || name.trim().length < 2) { say('اكتب اسم المحل.', false); return; }

    var result = await send('/api/shops', {
      name: name,
      contactName: document.getElementById('sh-contact').value,
      phone: document.getElementById('sh-phone').value
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
        الإرسال يتم من شاشة البضاعة.
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
      row(previewEl, 'حركات خزنة', String(d.movementsCount));

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

    // ── الخزنة ──
    var mvBody = panel('حركات الخزنة (' + (cl.movements || []).length + ')');
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
