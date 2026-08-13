/**
 * أنماط الواجهة
 *
 * عالمين مختلفين عمداً، والفرق بينهم بيحكي القصة الأمنية:
 *
 * 1) شاشة الكاشير: ورقية، ساطعة، أزرار كبيرة تتضغط بإبهام مبلول
 *    وبسرعة قدّام طابور. مستوحاة من ورق الفواتير الحراري.
 *    العنصر المميّز: حافّة تمزيق الفاتورة فوق الكرت.
 *
 * 2) بوّابة المالك: مظلمة، صامتة، **من غير أي هوية بصرية**.
 *    لا شعار، لا اسم نظام، لا رسايل مساعدة. الباب المخفي
 *    ما يصحّش يعلن عن اللي وراه. الغياب هنا قرار، مش كسل.
 *
 * كل ده CSS واحد بيتبعت مع الصفحة — مفيش خطوة بناء ولا ملفات
 * خارجية تتحمّل. أهم حاجة عندك: أقل عدد ممكن من الحاجات اللي تقع.
 */

export const BASE_CSS = `
:root{
  --paper:#fff; --paper-edge:#eceef1; --ink:#0f1b2d; --ink-soft:#5a6b80;
  --field:#f2f5f8; --line:#d9e0e8; --till:#0b6e4f; --till-deep:#085239;
  --alert:#b4322a; --amber:#b8710d;
  --vault:#0a0d10; --vault-panel:#11151a; --vault-line:#1f262e;
  --vault-ink:#c3ccd6; --vault-dim:#6c7784;
  --font-ui:'IBM Plex Sans Arabic',system-ui,-apple-system,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,monospace;
  --radius:4px; --tap:56px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;font-family:var(--font-ui);color:var(--ink);
  background:var(--paper-edge);-webkit-text-size-adjust:100%}
:focus-visible{outline:3px solid var(--till);outline-offset:2px}

.counter{min-height:100dvh;display:grid;place-items:center;padding:24px 16px;
  background:repeating-linear-gradient(180deg,transparent 0 39px,rgba(15,27,45,.035) 39px 40px),var(--paper-edge)}
.counter-card{width:100%;max-width:420px;background:var(--paper);border:1px solid var(--line);
  border-top:none;padding:32px 28px 28px;box-shadow:0 12px 32px -20px rgba(15,27,45,.5)}
.receipt-edge{width:100%;max-width:420px;height:12px;display:block;color:var(--paper)}
.counter-eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.14em;
  color:var(--ink-soft);margin:0 0 6px;direction:ltr;text-align:right}
.counter-title{font-size:26px;font-weight:700;letter-spacing:-.01em;margin:0 0 4px}
.counter-sub{font-size:14px;color:var(--ink-soft);margin:0 0 26px;line-height:1.6}

.field{margin-bottom:16px}
.field-label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
.field-input,.field-area{width:100%;padding:0 14px;font-family:var(--font-ui);font-size:17px;
  color:var(--ink);background:var(--field);border:1px solid var(--line);border-radius:var(--radius);
  transition:border-color .12s,background .12s}
.field-input{height:var(--tap)}
.field-area{padding:14px;min-height:110px;font-size:15px;line-height:1.7;resize:vertical}
.field-input:focus,.field-area:focus{background:var(--paper);border-color:var(--till);outline:none}
.field-hint{font-size:12px;color:var(--ink-soft);margin:6px 0 0;line-height:1.6}
select.field-input{appearance:none}

.btn-primary{width:100%;height:var(--tap);margin-top:8px;font-family:var(--font-ui);
  font-size:17px;font-weight:600;color:#fff;background:var(--till);border:none;
  border-radius:var(--radius);cursor:pointer;transition:background .12s}
.btn-primary:hover:not(:disabled){background:var(--till-deep)}
.btn-primary:disabled{background:var(--ink-soft);cursor:not-allowed}
.btn-ghost{height:44px;padding:0 18px;font-family:var(--font-ui);font-size:15px;
  color:var(--ink);background:transparent;border:1px solid var(--line);
  border-radius:var(--radius);cursor:pointer}

.alert-box{display:flex;gap:10px;padding:12px 14px;margin-bottom:18px;font-size:14px;
  line-height:1.5;color:var(--alert);background:#fdf3f2;border-inline-start:3px solid var(--alert);
  border-radius:0 var(--radius) var(--radius) 0}
.alert-box[data-tone="ok"]{color:var(--till-deep);background:#e9f4ef;border-color:var(--till)}
.alert-box[hidden]{display:none}

.counter-foot{display:flex;justify-content:space-between;margin-top:24px;padding-top:16px;
  border-top:1px dashed var(--line);font-family:var(--font-mono);font-size:11px;
  color:var(--ink-soft);direction:ltr}

.vault{min-height:100dvh;display:grid;place-items:center;padding:24px;
  background:var(--vault);color:var(--vault-ink)}
.vault-card{width:100%;max-width:340px}
.vault-field{margin-bottom:14px}
.vault-input{width:100%;height:50px;padding:0 14px;font-family:var(--font-mono);font-size:15px;
  letter-spacing:.05em;color:var(--vault-ink);background:var(--vault-panel);
  border:1px solid var(--vault-line);border-radius:2px;transition:border-color .15s}
.vault-input::placeholder{color:var(--vault-dim);letter-spacing:.12em}
.vault-input:focus{border-color:var(--vault-ink);outline:none}
.vault-btn{width:100%;height:50px;margin-top:6px;font-family:var(--font-mono);font-size:14px;
  letter-spacing:.1em;color:var(--vault);background:var(--vault-ink);border:none;
  border-radius:2px;cursor:pointer}
.vault-btn:disabled{color:var(--vault-dim);background:var(--vault-line);cursor:not-allowed}
.vault-error{font-family:var(--font-mono);font-size:12px;color:#d8756c;margin:0 0 14px;min-height:16px}

.shell{max-width:720px;margin:0 auto;padding:20px 16px 80px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:6px;
  padding:20px;margin-bottom:16px}
.card h2{margin:0 0 4px;font-size:17px}
.card p.muted{margin:0 0 16px;font-size:13px;color:var(--ink-soft);line-height:1.6}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 16px;background:var(--ink);color:#fff}
.topbar strong{font-size:15px}
.topbar span{font-family:var(--font-mono);font-size:11px;opacity:.7;display:block}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:0;list-style:none}
.chips li{font-family:var(--font-mono);font-size:11px;padding:4px 8px;
  background:var(--field);border:1px solid var(--line);border-radius:2px;direction:ltr}

.gate-backdrop{position:fixed;inset:0;z-index:100;display:grid;place-items:center;padding:20px;
  background:rgba(10,16,26,.72);backdrop-filter:blur(3px)}
.gate-panel{width:100%;max-width:520px;max-height:88dvh;display:flex;flex-direction:column;
  background:var(--paper);border-radius:6px;overflow:hidden}
.gate-head{padding:18px 22px 14px;border-bottom:1px solid var(--line)}
.gate-tag{display:inline-block;padding:3px 9px;margin-bottom:10px;font-family:var(--font-mono);
  font-size:11px;letter-spacing:.1em;border-radius:2px}
.gate-tag[data-severity="INFO"]{color:var(--till-deep);background:#e6f2ed}
.gate-tag[data-severity="WARNING"]{color:var(--amber);background:#fbf1e0}
.gate-tag[data-severity="CRITICAL"]{color:#fff;background:var(--alert)}
.gate-title{font-size:20px;font-weight:700;margin:0}
.gate-body{padding:20px 22px;overflow-y:auto;font-size:15px;line-height:1.75;white-space:pre-wrap}
.gate-foot{padding:16px 22px;border-top:1px solid var(--line);background:var(--field)}
.gate-count{font-family:var(--font-mono);font-size:12px;color:var(--ink-soft);
  margin:0 0 10px;direction:ltr;text-align:right}

.idle-bar{position:fixed;inset-block-end:0;inset-inline:0;z-index:90;display:flex;
  align-items:center;justify-content:center;gap:14px;padding:14px 18px;font-size:15px;
  color:#fff;background:var(--alert)}
.idle-count{font-family:var(--font-mono);font-size:18px;font-weight:500}
.idle-btn{padding:9px 18px;font-family:var(--font-ui);font-size:15px;font-weight:600;
  color:var(--alert);background:#fff;border:none;border-radius:var(--radius);cursor:pointer}

.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
  clip:rect(0,0,0,0);white-space:nowrap;border:0}

/* ═══ قائمة الفريق والفروع ═══
   الصف بيتعامل كسطر في كشف — الاسم بالخط العادي، والمعرّف بخط
   الآلة الكاتبة لأنه معرّف نظام مش اسم بشري.
   الحساب المعطّل بياخد شطب خفيف، زي فاتورة ملغية في دفتر. */
.roster{margin:0;padding:0;list-style:none;border-top:1px solid var(--line)}
.roster-row{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px 0;border-bottom:1px solid var(--line)}
.roster-main{min-width:0}
.roster-name{display:block;font-size:15px;font-weight:600;line-height:1.4}
.roster-id{display:block;margin-top:2px;font-family:var(--font-mono);font-size:12px;
  color:var(--ink-soft);direction:ltr;text-align:right;overflow-wrap:anywhere}
.roster-side{display:flex;align-items:center;gap:8px;flex-shrink:0}
.roster-row[data-inactive="true"] .roster-name{text-decoration:line-through;
  text-decoration-thickness:1px;color:var(--ink-soft)}
.roster-row[data-inactive="true"] .roster-id{opacity:.6}

.tag{display:inline-block;padding:3px 8px;font-family:var(--font-mono);font-size:11px;
  letter-spacing:.06em;border-radius:2px;white-space:nowrap;
  color:var(--ink-soft);background:var(--field);border:1px solid var(--line)}
.tag[data-variant="off"]{color:var(--alert);background:#fdf3f2;border-color:#f0d5d2}

.btn-mini{height:36px;padding:0 12px;font-family:var(--font-ui);font-size:13px;
  font-weight:600;color:var(--ink);background:var(--paper);border:1px solid var(--line);
  border-radius:var(--radius);cursor:pointer;white-space:nowrap;
  transition:border-color .12s,color .12s}
.btn-mini:hover:not(:disabled){border-color:var(--ink-soft)}
.btn-mini[data-danger="true"]:hover:not(:disabled){color:var(--alert);border-color:var(--alert)}
.btn-mini:disabled{opacity:.5;cursor:not-allowed}

@media (prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
`;
