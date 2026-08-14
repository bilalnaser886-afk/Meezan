/**
 * نظام التصميم — "البنكنوت"
 *
 * ══ من فين جت الألوان؟ ══
 * النظام ده بيتعامل مع فلوس مصرية طول اليوم. فبدل ما نخترع لوحة
 * ألوان، أخدناها من الحاجة اللي في إيد الموظّف فعلاً — الجنيه:
 *
 *   البترولي الغامق  ← حبر فئة الـ200
 *   الأخضر           ← فئة الـ20   (دخل / تأكيد)
 *   القرمزي          ← فئة الـ10   (منصرف / خطر)
 *   الذهبي           ← خيط الأمان  (معلّق / محتاج انتباه)
 *   الورقي           ← ورق البنكنوت نفسه
 *
 * ══ العنصر المميّز: الختم ══
 * المحلات في مصر بتختم كل ورقة. فالدور بيتعرض كختم مطاطي مايل
 * شوية بحدّين — أصدق وأقرب للواقع من تاج ملوّن عادي.
 *
 * ══ الخطوط ══
 * Readex Pro      للعناوين والمبالغ — عربي بشخصية، مش الافتراضي
 * IBM Plex Arabic للنص — كثيف ومقروء في الأحجام الصغيرة
 * IBM Plex Mono   للأرقام والمعرّفات — خانات متساوية العرض عشان
 *                 المبالغ تتصفّ تحت بعضها في عمود
 */

export const BASE_CSS = `
:root{
  --ground:#0E2A33; --ground-soft:#173B46;
  --surface:#EDF1EF; --card:#FFFFFF; --line:#D7E0DC; --line-soft:#E8EEEB;
  --ink:#0E2A33; --ink-soft:#5F757C; --ink-faint:#93A5AA;
  --credit:#12805C; --credit-deep:#0C6247; --credit-wash:#E6F2ED;
  --debit:#9E2B3E; --debit-wash:#FAECEE;
  --thread:#B5822A; --thread-wash:#FBF3E2;

  --font-display:'Readex Pro',system-ui,sans-serif;
  --font-ui:'IBM Plex Sans Arabic',system-ui,-apple-system,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,monospace;

  --r:10px; --r-sm:6px; --tap:54px; --pad:16px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;font-family:var(--font-ui);color:var(--ink);
  background:var(--surface);-webkit-text-size-adjust:100%;
  -webkit-tap-highlight-color:transparent}
:focus-visible{outline:2.5px solid var(--credit);outline-offset:2px;border-radius:3px}
button{font:inherit}

/* ═══ الختم — العنصر المميّز ═══
   حدّين (border + inset shadow) وميلة بسيطة = إحساس الختم
   المطاطي المتحطّ بإيد على ورقة. */
.stamp{display:inline-block;padding:3px 9px 4px;border:1.5px solid currentColor;
  border-radius:4px;box-shadow:inset 0 0 0 1px currentColor;
  font-family:var(--font-display);font-size:11px;font-weight:600;
  letter-spacing:.02em;line-height:1.4;transform:rotate(-1.5deg);white-space:nowrap}
.stamp[data-role="SUPER_ADMIN"]{color:var(--thread)}
.stamp[data-role="BRANCH_MANAGER"]{color:var(--credit)}
.stamp[data-role="STAFF"]{color:var(--ink-faint)}

/* ═══ الشريط العلوي ═══ */
.app-bar{position:sticky;top:0;z-index:50;display:flex;align-items:center;
  justify-content:space-between;gap:12px;padding:12px var(--pad);
  background:var(--ground);color:#fff}
.who{display:flex;align-items:center;gap:10px;min-width:0}
.who-name{font-family:var(--font-display);font-size:16px;font-weight:600;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ═══ قائمة النقط الثلاث ═══
   مبنية على <details> — بتشتغل بالكيبورد وبدون أي JavaScript. */
.menu{position:relative}
.menu>summary{list-style:none;width:40px;height:40px;display:grid;place-items:center;
  border-radius:var(--r-sm);cursor:pointer;font-size:20px;line-height:1;color:#fff;
  background:rgba(255,255,255,.08)}
.menu>summary::-webkit-details-marker{display:none}
.menu[open]>summary{background:rgba(255,255,255,.18)}
.menu-sheet{position:absolute;inset-inline-end:0;top:calc(100% + 8px);z-index:60;
  min-width:236px;padding:6px;background:var(--card);color:var(--ink);
  border:1px solid var(--line);border-radius:var(--r);
  box-shadow:0 16px 40px -16px rgba(14,42,51,.5)}
.menu-info{padding:10px 12px 12px;border-bottom:1px solid var(--line-soft);margin-bottom:6px}
.menu-row{display:flex;justify-content:space-between;gap:12px;font-size:13px;
  padding:3px 0;color:var(--ink-soft)}
.menu-row b{color:var(--ink);font-weight:600;font-family:var(--font-mono);
  font-size:12px;direction:ltr}
.menu-item{display:block;width:100%;text-align:start;padding:11px 12px;font-size:15px;
  color:var(--ink);background:none;border:none;border-radius:var(--r-sm);cursor:pointer}
.menu-item:hover{background:var(--surface)}
.menu-item[data-danger]{color:var(--debit)}

/* ═══ شريط الانتباه ═══ بيقول حاجة واحدة: فيه حاجة مستنياك ولا لأ */
.strip{display:flex;align-items:center;gap:13px;padding:14px var(--pad);
  border-radius:var(--r);margin-bottom:14px;background:var(--card);
  border:1px solid var(--line)}
.strip[data-tone="wait"]{background:var(--thread-wash);border-color:#EBD9AE}
.strip-count{font-family:var(--font-display);font-size:26px;font-weight:700;line-height:1;
  color:var(--thread);font-variant-numeric:tabular-nums}
.strip-text{font-size:14px;line-height:1.55;flex:1}
.strip-text b{font-weight:600}
.strip-go{padding:9px 14px;font-size:14px;font-weight:600;color:#fff;
  background:var(--thread);border:none;border-radius:var(--r-sm);
  text-decoration:none;white-space:nowrap}
.strip[data-tone="calm"] .strip-text{color:var(--ink-soft)}

/* ═══ بلاطات الإجراءات ═══ */
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
.tile{display:flex;flex-direction:column;justify-content:space-between;gap:10px;
  min-height:94px;padding:14px;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);text-decoration:none;color:var(--ink)}
.tile:active{background:var(--surface)}
.tile-label{font-family:var(--font-display);font-size:15px;font-weight:600;line-height:1.3}
.tile-note{font-size:12px;color:var(--ink-soft);line-height:1.5}
.tile-num{font-family:var(--font-mono);font-size:19px;font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr}
.tile[data-wide]{grid-column:1/-1;min-height:0;flex-direction:row;align-items:center;
  justify-content:space-between}

/* ═══ الأقسام القابلة للطي ═══ */
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:10px;overflow:hidden}
.panel>summary{list-style:none;display:flex;align-items:center;justify-content:space-between;
  gap:10px;padding:15px var(--pad);cursor:pointer;font-family:var(--font-display);
  font-size:15px;font-weight:600}
.panel>summary::-webkit-details-marker{display:none}
.panel>summary::after{content:'+';font-family:var(--font-mono);font-size:19px;
  color:var(--ink-faint);line-height:1}
.panel[open]>summary::after{content:'−'}
.panel[open]>summary{border-bottom:1px solid var(--line-soft)}
.panel-body{padding:var(--pad)}

/* ═══ الشريط السفلي ═══ إبهامك بيوصله من غير ما تمد إيدك */
.tabbar{position:fixed;inset-inline:0;bottom:0;z-index:40;display:flex;
  background:var(--card);border-top:1px solid var(--line);
  padding-bottom:env(safe-area-inset-bottom)}
.tabbar a{flex:1;padding:11px 4px 13px;text-align:center;text-decoration:none;
  font-size:12px;font-weight:600;color:var(--ink-faint);
  border-top:2.5px solid transparent;margin-top:-1px}
.tabbar a[aria-current="page"]{color:var(--credit);border-top-color:var(--credit)}
.tabbar-icon{display:block;font-family:var(--font-mono);font-size:17px;margin-bottom:2px}
.shell{max-width:640px;margin:0 auto;padding:14px var(--pad) 96px}

/* ═══ الحقول ═══ */
.field{margin-bottom:15px}
.field-label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
.field-input,.field-area{width:100%;padding:0 14px;font-family:var(--font-ui);font-size:16px;
  color:var(--ink);background:var(--card);border:1.5px solid var(--line);
  border-radius:var(--r-sm);transition:border-color .12s}
.field-input{height:var(--tap)}
.field-area{padding:13px 14px;min-height:104px;font-size:15px;line-height:1.7;resize:vertical}
.field-input:focus,.field-area:focus{border-color:var(--credit);outline:none}
select.field-input{appearance:none;
  background-image:linear-gradient(45deg,transparent 50%,var(--ink-faint) 50%),
    linear-gradient(135deg,var(--ink-faint) 50%,transparent 50%);
  background-position:16px calc(50% + 1px),21px calc(50% + 1px);
  background-size:5px 5px,5px 5px;background-repeat:no-repeat}
.field-hint{font-size:12px;color:var(--ink-soft);margin:6px 0 0;line-height:1.6}

.btn-primary{width:100%;height:var(--tap);font-family:var(--font-display);font-size:16px;
  font-weight:600;color:#fff;background:var(--credit);border:none;border-radius:var(--r-sm);
  cursor:pointer;transition:background .12s}
.btn-primary:hover:not(:disabled){background:var(--credit-deep)}
.btn-primary:disabled{background:var(--ink-faint);cursor:not-allowed}
.btn-mini{height:36px;padding:0 13px;font-size:13px;font-weight:600;color:var(--ink);
  background:var(--card);border:1.5px solid var(--line);border-radius:var(--r-sm);
  cursor:pointer;white-space:nowrap;transition:border-color .12s,color .12s}
.btn-mini:hover:not(:disabled){border-color:var(--ink-soft)}
.btn-mini[data-danger="true"]:hover:not(:disabled){color:var(--debit);border-color:var(--debit)}
.btn-mini:disabled{opacity:.5;cursor:not-allowed}

.alert-box{display:flex;gap:10px;padding:12px 14px;margin-bottom:16px;font-size:14px;
  line-height:1.6;color:var(--debit);background:var(--debit-wash);
  border-inline-start:3px solid var(--debit);border-radius:0 var(--r-sm) var(--r-sm) 0}
.alert-box[data-tone="ok"]{color:var(--credit-deep);background:var(--credit-wash);
  border-color:var(--credit)}
.alert-box[hidden]{display:none}

/* ═══ القوائم ═══ */
.roster{margin:0;padding:0;list-style:none}
.roster-row{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:13px 0;border-bottom:1px solid var(--line-soft)}
.roster-row:last-child{border-bottom:none}
.roster-main{min-width:0}
.roster-name{display:block;font-size:15px;font-weight:600;line-height:1.4}
.roster-id{display:block;margin-top:2px;font-family:var(--font-mono);font-size:12px;
  color:var(--ink-soft);direction:ltr;text-align:right;overflow-wrap:anywhere}
.roster-side{display:flex;align-items:center;gap:8px;flex-shrink:0}
.roster-row[data-inactive="true"] .roster-name{text-decoration:line-through;color:var(--ink-faint)}
.roster-row[data-inactive="true"] .roster-id{opacity:.55}

.tag{display:inline-block;padding:3px 8px;font-family:var(--font-mono);font-size:11px;
  border-radius:3px;white-space:nowrap;color:var(--ink-soft);background:var(--surface);
  border:1px solid var(--line)}
.tag[data-variant="off"]{color:var(--debit);background:var(--debit-wash);border-color:#F0D2D7}
.tag[data-variant="wait"]{color:var(--thread);background:var(--thread-wash);border-color:#EBD9AE}

/* ═══ الأرصدة ═══
   المبلغ بخط العرض بحجم كبير وخيط ذهبي فوقه، زي رقم الفئة على
   البنكنوت. ده المكان الوحيد اللي بنصرف فيه جرأة بصرية. */
.balances{display:grid;gap:10px}
.bal-card{padding:15px var(--pad);background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);border-top:2px solid var(--thread)}
.bal-name{font-size:14px;font-weight:600}
.bal-meta{display:block;font-family:var(--font-mono);font-size:11px;color:var(--ink-faint);
  margin-top:2px;direction:ltr;text-align:right}
.bal-amount{display:block;margin-top:10px;font-family:var(--font-display);font-size:30px;
  font-weight:600;line-height:1;font-variant-numeric:tabular-nums;direction:ltr;
  text-align:right;color:var(--credit-deep)}
.bal-amount[data-negative="true"]{color:var(--debit)}
.bal-cur{font-family:var(--font-ui);font-size:14px;font-weight:500;color:var(--ink-faint);
  margin-inline-start:6px}
.bal-total{border-top-color:var(--ground);background:var(--ground);color:#fff}
.bal-total .bal-name{color:rgba(255,255,255,.72)}
.bal-total .bal-amount{color:#fff}
.bal-total .bal-cur{color:rgba(255,255,255,.5)}

/* ═══ الحركات ═══ */
.mv-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;
  padding:13px 0;border-bottom:1px solid var(--line-soft)}
.mv-row:last-child{border-bottom:none}
.mv-main{min-width:0;flex:1}
.mv-title{font-size:14px;font-weight:600;line-height:1.5}
.mv-sub{display:block;font-size:12px;color:var(--ink-soft);margin-top:3px;line-height:1.6}
.mv-side{display:flex;flex-direction:column;align-items:flex-end;gap:7px;flex-shrink:0}
.mv-amount{font-family:var(--font-mono);font-size:15px;font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr;white-space:nowrap}
.mv-amount[data-dir="IN"]{color:var(--credit)}
.mv-amount[data-dir="OUT"]{color:var(--debit)}
.mv-row[data-status="PENDING"]{background:var(--thread-wash);
  margin-inline:calc(var(--pad) * -1);padding-inline:var(--pad)}
.mv-row[data-status="REJECTED"] .mv-title{text-decoration:line-through;color:var(--ink-faint)}
.mv-actions{display:flex;gap:6px}

.empty{padding:26px 16px;text-align:center}
.empty-title{font-family:var(--font-display);font-size:15px;font-weight:600;margin:0 0 6px}
.empty-note{font-size:13px;color:var(--ink-soft);line-height:1.65;margin:0}
.muted{font-size:13px;color:var(--ink-soft);line-height:1.65;margin:0 0 14px}

/* ═══ نافذة الإعلان الإلزامي ═══ */
.gate-backdrop{position:fixed;inset:0;z-index:100;display:grid;place-items:center;
  padding:18px;background:rgba(14,42,51,.76);backdrop-filter:blur(3px)}
.gate-panel{width:100%;max-width:520px;max-height:88dvh;display:flex;flex-direction:column;
  background:var(--card);border-radius:var(--r);overflow:hidden}
.gate-head{padding:18px var(--pad) 14px;border-bottom:1px solid var(--line)}
.gate-tag{display:inline-block;padding:3px 9px;margin-bottom:10px;font-family:var(--font-mono);
  font-size:11px;border-radius:3px}
.gate-tag[data-severity="INFO"]{color:var(--credit-deep);background:var(--credit-wash)}
.gate-tag[data-severity="WARNING"]{color:var(--thread);background:var(--thread-wash)}
.gate-tag[data-severity="CRITICAL"]{color:#fff;background:var(--debit)}
.gate-title{font-family:var(--font-display);font-size:20px;font-weight:700;margin:0}
.gate-body{padding:18px var(--pad);overflow-y:auto;font-size:15px;line-height:1.8;
  white-space:pre-wrap}
.gate-foot{padding:15px var(--pad);border-top:1px solid var(--line);background:var(--surface)}
.gate-count{font-family:var(--font-mono);font-size:12px;color:var(--ink-soft);margin:0 0 10px;
  direction:ltr;text-align:right}

/* ═══ شريط تحذير الخمول ═══ */
.idle-bar{position:fixed;inset-block-end:0;inset-inline:0;z-index:90;display:flex;
  align-items:center;justify-content:center;gap:12px;padding:14px 16px;
  padding-bottom:calc(14px + env(safe-area-inset-bottom));font-size:15px;color:#fff;
  background:var(--debit)}
.idle-count{font-family:var(--font-mono);font-size:18px;font-weight:500}
.idle-btn{padding:9px 17px;font-size:15px;font-weight:600;color:var(--debit);background:#fff;
  border:none;border-radius:var(--r-sm);cursor:pointer}

/* ═══ قفل الشاشة ═══ */
.lock-screen{position:fixed;inset:0;z-index:200;display:grid;place-items:center;
  padding:24px;background:var(--ground);color:#fff}
.lock-card{width:100%;max-width:320px;text-align:center}
.lock-eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.16em;
  color:rgba(255,255,255,.45);margin:0 0 12px}
.lock-title{font-family:var(--font-display);font-size:22px;font-weight:600;margin:0 0 6px}
.lock-who{font-size:14px;color:rgba(255,255,255,.62);margin:0 0 24px;line-height:1.6}
.lock-input{width:100%;height:var(--tap);padding:0 14px;font-family:var(--font-ui);
  font-size:17px;color:#fff;background:rgba(255,255,255,.08);
  border:1.5px solid rgba(255,255,255,.2);border-radius:var(--r-sm);text-align:center}
.lock-input:focus{outline:none;border-color:#fff;background:rgba(255,255,255,.14)}
.lock-btn{width:100%;height:var(--tap);margin-top:10px;font-family:var(--font-display);
  font-size:16px;font-weight:600;color:var(--ground);background:#fff;border:none;
  border-radius:var(--r-sm);cursor:pointer}
.lock-btn:disabled{opacity:.5;cursor:not-allowed}
.lock-error{font-size:14px;color:#F2A9AF;margin:14px 0 0;min-height:20px}
.lock-exit{margin-top:20px;font-size:13px;color:rgba(255,255,255,.5);background:none;
  border:none;text-decoration:underline;cursor:pointer;font-family:var(--font-ui)}

/* ═══ الدخول ═══ */
.counter{min-height:100dvh;display:grid;place-items:center;padding:24px 16px;
  background:var(--surface)}
.counter-card{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);
  border-top:none;padding:30px 26px 26px;border-radius:0 0 var(--r) var(--r);
  box-shadow:0 20px 50px -30px rgba(14,42,51,.55)}
.receipt-edge{width:100%;max-width:400px;height:11px;display:block;color:var(--card)}
.counter-eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.14em;
  color:var(--ink-faint);margin:0 0 6px;direction:ltr;text-align:right}
.counter-title{font-family:var(--font-display);font-size:26px;font-weight:700;
  letter-spacing:-.01em;margin:0 0 4px}
.counter-sub{font-size:14px;color:var(--ink-soft);margin:0 0 24px;line-height:1.6}
.counter-foot{display:flex;justify-content:space-between;margin-top:22px;padding-top:15px;
  border-top:1px dashed var(--line);font-family:var(--font-mono);font-size:11px;
  color:var(--ink-faint);direction:ltr}

.vault{min-height:100dvh;display:grid;place-items:center;padding:24px;background:#080B0D;
  color:#B9C4C7}
.vault-card{width:100%;max-width:330px}
.vault-field{margin-bottom:13px}
.vault-input{width:100%;height:50px;padding:0 14px;font-family:var(--font-mono);font-size:15px;
  letter-spacing:.05em;color:#B9C4C7;background:#0F1417;border:1px solid #1C2529;
  border-radius:3px;transition:border-color .15s}
.vault-input::placeholder{color:#4C5A5F;letter-spacing:.12em}
.vault-input:focus{border-color:#B9C4C7;outline:none}
.vault-btn{width:100%;height:50px;margin-top:6px;font-family:var(--font-mono);font-size:14px;
  letter-spacing:.1em;color:#080B0D;background:#B9C4C7;border:none;border-radius:3px;
  cursor:pointer}
.vault-btn:disabled{color:#4C5A5F;background:#1C2529;cursor:not-allowed}
.vault-error{font-family:var(--font-mono);font-size:12px;color:#C97B7B;margin:0 0 13px;
  min-height:16px}

.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
  clip:rect(0,0,0,0);white-space:nowrap;border:0}

/* ═══ السلة — قلب شاشة الكاشير ═══
   فوق الصفحة عن قصد: الموظّف بيبصّ عليها بين كل ضغطة وضغطة،
   والزبون بيسأل "بقى كام؟" وهو واقف قدامه. */
.cart{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:14px;overflow:hidden}
.cart-head{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:12px var(--pad);border-bottom:1px solid var(--line-soft)}
.cart-title{font-family:var(--font-display);font-size:15px;font-weight:600}
.cart-empty{margin:0;padding:22px var(--pad);text-align:center;font-size:13px;
  color:var(--ink-faint)}
.cart-empty[hidden]{display:none}

.cart-line{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:11px var(--pad);border-bottom:1px solid var(--line-soft)}
.cart-line-main{min-width:0;flex:1}
.cart-line-name{display:block;font-size:14px;font-weight:600;line-height:1.45;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cart-line-sub{display:block;font-family:var(--font-mono);font-size:11px;
  color:var(--ink-soft);margin-top:3px;direction:ltr;text-align:start}
.cart-line-side{display:flex;flex-direction:column;align-items:flex-end;gap:7px;flex-shrink:0}
.cart-line-amount{font-family:var(--font-mono);font-size:14px;font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr}

/* أزرار الكمية 40 بكسل: بتتضغط بالإبهام وقدّام طابور */
.qty-steps{display:flex;align-items:center;gap:2px;border:1px solid var(--line);
  border-radius:var(--r-sm);overflow:hidden}
.qty-btn{width:40px;height:36px;font-family:var(--font-mono);font-size:17px;line-height:1;
  color:var(--ink);background:var(--card);border:none;cursor:pointer}
.qty-btn:active:not(:disabled){background:var(--surface)}
.qty-btn:disabled{color:var(--ink-faint);cursor:not-allowed}
.qty-num{min-width:34px;text-align:center;font-family:var(--font-mono);font-size:14px;
  font-weight:500;font-variant-numeric:tabular-nums}

.cart-total{display:flex;align-items:baseline;justify-content:space-between;gap:12px;
  padding:14px var(--pad);background:var(--ground);color:#fff}
.cart-total-label{font-size:14px;color:rgba(255,255,255,.72)}
.cart-total-num{font-family:var(--font-display);font-size:28px;font-weight:700;
  line-height:1;font-variant-numeric:tabular-nums;direction:ltr}
.cart-total-num .bal-cur{color:rgba(255,255,255,.5)}

/* ═══ مربّعات المنتجات ═══
   مربّعات كبيرة مش قايمة: الضغط بالإبهام على شاشة لمس. */
.prod-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.prod-btn{display:flex;flex-direction:column;align-items:flex-start;gap:5px;
  min-height:86px;padding:12px;text-align:start;cursor:pointer;
  background:var(--card);border:1px solid var(--line);border-radius:var(--r);color:var(--ink)}
.prod-btn:active{background:var(--credit-wash);border-color:var(--credit)}
.prod-btn[hidden]{display:none}
.prod-btn-name{font-size:14px;font-weight:600;line-height:1.35;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.prod-btn-price{margin-top:auto;font-family:var(--font-mono);font-size:15px;
  font-weight:500;color:var(--credit);direction:ltr}
.prod-btn-qty{font-family:var(--font-mono);font-size:11px;color:var(--ink-faint);direction:rtl}

/* ═══ صفوف شاشة المنتجات ═══
   flex-wrap مش حساب عرض يدوي: لوحة التعديل بتنزل سطر كامل تحت
   لوحدها، والسطر بيتظبط مهما طال الاسم. */
.prod-row{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;
  gap:12px;padding:12px 0;border-bottom:1px solid var(--line-soft)}
.prod-row:last-child{border-bottom:none}
.prod-row-main{flex:1;min-width:0}
.prod-row-name{display:block;font-size:14px;font-weight:600;line-height:1.45}
.prod-row-name[data-off="true"]{color:var(--ink-faint);text-decoration:line-through}
.prod-row-sub{display:block;font-family:var(--font-mono);font-size:11px;
  color:var(--ink-soft);margin-top:3px;direction:ltr;text-align:start}
.prod-row-side{display:flex;align-items:center;gap:9px;flex-shrink:0}
.prod-row-qty{font-family:var(--font-mono);font-size:17px;font-weight:500;
  font-variant-numeric:tabular-nums;color:var(--ink)}
/* الصفر بالأحمر: أهم معلومة في السطر لو المنتج خلص */
.prod-row-qty[data-zero="true"]{color:var(--debit)}

.prod-edit{flex-basis:100%;margin-top:2px;padding:13px;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--r-sm)}
.prod-edit[hidden]{display:none}
.prod-edit-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.prod-edit-grid .field{margin-bottom:0}
.prod-edit-grid .field:only-child{grid-column:1/-1}
.prod-edit-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}

@media (max-width:360px){
  .prod-grid{grid-template-columns:1fr}
  .prod-edit-grid{grid-template-columns:1fr}
}

@media (max-width:360px){.tiles{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
`;
