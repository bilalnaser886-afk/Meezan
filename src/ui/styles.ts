/**
 * نظام التصميم — "الميزان النحاسي"
 *
 * ══ من فين جت الألوان؟ ══
 * النظام ده بيتعامل مع فلوس مصرية طول اليوم، والاسم نفسه "ميزان".
 * فاللوحة مأخوذة من أدوات الوزن والمحاسبة نفسها:
 *
 *   النحاسي   ← معدن الميزان والختم. **لون الهوية وحده**
 *   الأخضر-الأسود ← حبر الدفتر الثقيل. الهيدر والشريط السفلي
 *   الأخضر الوظيفي ← فئة الـ20. **الأزرار الإجرائية بس**
 *   القرمزي    ← فئة الـ10. منصرف أو خطر
 *   الكريمي    ← ورق الدفتر، بلمحة خضراء خفيفة
 *
 * ══ قاعدة حاكمة: الهوية غير الوظيفة ══
 * النحاسي **ما بيتحطّش أبدًا على زرار إجراء**، والأخضر الوظيفي
 * **ما بيتحطّش أبدًا على شعار أو شارة**.
 *
 * ليه؟ عشان لما الموظّف يشوف أخضر يبقى عارف إن ده حاجة بيدوس
 * عليها. لو استخدمنا نفس اللون للهوية، الأخضر يفقد معناه ويبقى
 * مجرد لون في الصفحة.
 *
 * ═══════════════════════════════════════════════════════════
 *  الخطوط — النسخة الجديدة
 * ═══════════════════════════════════════════════════════════
 *
 * كان: Readex Pro + IBM Plex Arabic. الاتنين ممتازين تقنيًا،
 * لكن الاتنين **حياديين عن قصد** — اتصمّموا عشان يختفوا. النظام
 * كان بيقرا زي لوحة تحكم شركة برمجيات، مش زي محل ليه اسم.
 *
 * بقى:
 *
 *   Reem Kufi      الشعار وحده. الختم المحفور. (زي ما هو)
 *
 *   El Messiri     العناوين والأزرار والمبالغ الكبيرة.
 *                  ⤷ ده مصدر "الروح": خط فيه أثر القلم — سماكة
 *                    بتزيد وتقل جوّه الحرف الواحد زي الخط اليدوي،
 *                    ونهايات مايلة شوية. بيدّي إحساس لافتة محل
 *                    اتكتبت بإيد خطاط، مش شاشة مطبوعة.
 *                  ⚠ بيتحطّ على العناوين بس — لأن الخط اللي فيه
 *                    شخصية قوية بيتعب العين لو النص كله بيه.
 *
 *   Alexandria     كل النص العادي. هندسي ونضيف وواضح في الأحجام
 *                  الصغيرة، وبيسيب المسرح للعناوين.
 *                  ⤷ التباين بين الاتنين مقصود: العنوان بيتكلم،
 *                    والنص بيشتغل.
 *
 *   JetBrains Mono الأرقام والسريالات وكلمات المرور.
 *                  ⤷ اتختار عشان **الصفر فيه نقطة جوّاه**، والواحد
 *                    له قاعدة. في شاشة بتسلّم كلمات مرور وبتعرض
 *                    آيمي، الفرق بين 0 و O مش تفصيلة شكلية.
 *
 * ══ ⚠ الحجم بقى مقبض واحد ══
 * كل أحجام الخطوط بقت مشتقّة من `--fs` في :root. عايز الخط أكبر
 * في المحل كله؟ غيّر رقم واحد لـ 1.06. أصغر؟ 0.94. مفيش سطر
 * تاني بيتلمس.
 *
 * ⚠ واستثناء واحد إلزامي: خانات الإدخال ما تنزلش عن 16px مهما
 * صغّرت المقبض — الأيفون بيزوّم الصفحة تلقائيًا لو نزلت، والزووم
 * ده بيحسّ إن الشاشة بتتخبّط. عشان كده فيه `--fs-input` بـ max().
 */

export const BASE_CSS = `
:root{
  --ground:#16211D; --ground-soft:#22302A;
  --surface:#F1F1E6; --card:#FDFDF7; --line:#DCDCCB; --line-soft:#EAEAE0;
  --ink:#16211D; --ink-soft:#5B6A62; --ink-faint:#94A099;

  /* الهوية — الشعار والشارات والخطوط الرفيعة. مش للأزرار. */
  --brand:#B08D3D; --brand-soft:#C9A557; --brand-wash:#F6F0E1; --brand-line:#E4D4AC;

  /* الوظيفة — الأزرار الإجرائية والتأكيد. مش للهوية. */
  --credit:#12805C; --credit-deep:#0C6247; --credit-wash:#E6F2ED;
  --debit:#9E2B3E; --debit-wash:#FAECEE;

  /* مرادفات: الذهبي القديم بقى هو النحاسي */
  --thread:var(--brand); --thread-wash:var(--brand-wash);

  /* ═══ الخطوط ═══
     ⚠ كل عيلة ورا اسمها بدائل. لو جوجل فونتس اتأخرت أو اتقفلت،
     الصفحة بتتكتب بخط الجهاز فورًا بدل ما تفضل بيضا مستنية. */
  --font-brand:'Reem Kufi','El Messiri',system-ui,sans-serif;
  --font-display:'El Messiri','Alexandria',system-ui,sans-serif;
  --font-ui:'Alexandria',system-ui,-apple-system,'Segoe UI',sans-serif;
  --font-mono:'JetBrains Mono','Alexandria',ui-monospace,monospace;

  /* ═══ مقياس الخط ═══
     ⚠ المقبض ده هو المكان الوحيد اللي بتغيّر منه حجم الخط
     في النظام كله:
        1     الحالي
        1.06  أكبر شوية
        0.94  أصغر شوية
     كل الأرقام تحت بتتضرب فيه تلقائيًا. */
  --fs:1;

  --fs-0:calc(10.5px * var(--fs));   /* وسوم دقيقة جدًا */
  --fs-1:calc(11.5px * var(--fs));   /* سريال · بيانات جانبية */
  --fs-2:calc(12.5px * var(--fs));   /* تلميحات وملاحظات */
  --fs-3:calc(13.5px * var(--fs));   /* نص ثانوي */
  --fs-4:calc(15px   * var(--fs));   /* نص الصفوف — الأكتر استخدامًا */
  --fs-5:calc(16px   * var(--fs));   /* عناوين الأقسام والأزرار */
  --fs-6:calc(17.5px * var(--fs));   /* أرقام متوسطة */
  --fs-7:calc(20px   * var(--fs));   /* عناوين ثانوية */
  --fs-8:calc(23.5px * var(--fs));   /* عناوين الشاشات */
  --fs-9:calc(28px   * var(--fs));   /* المبالغ */
  --fs-10:calc(32px  * var(--fs));   /* الرصيد الكبير */
  --fs-brand:calc(34px * var(--fs)); /* الشعار */

  /* ⚠ لا تنزل عن 16px. سفاري على الأيفون بيزوّم الصفحة لو
     خانة الإدخال أصغر من كده، والزووم بياخد وقت وبيلخبط التخطيط. */
  --fs-input:max(16px, calc(16px * var(--fs)));

  --r:10px; --r-sm:6px; --tap:54px; --pad:16px;

  /* ═══ الحركة ═══
     ⚠ اقرا قسم "الاستجابة للّمس" في آخر الملف قبل ما تغيّر
     الأرقام دي. القاعدة: **الضغطة فورية، والرجوع بيهدى**. */
  --ease:cubic-bezier(.2,.7,.3,1);
  --t-fast:90ms; --t:140ms;

  /* عمق الظل — بيتغيّر في الوضع الليلي لأن الظل الأسود
     على خلفية غامقة مش بيبان */
  --shadow:0 1px 2px rgba(22,33,29,.06), 0 2px 8px rgba(22,33,29,.05);
  --shadow-lift:0 2px 4px rgba(22,33,29,.08), 0 8px 20px rgba(22,33,29,.09);

  /* ⚠ المسافة تحت آخر زرار.
     الشريط السفلي ~70px، وكانت 96 — يعني 26px بس تحت آخر
     زرار، فبيتحسّ لازق. 128 بتدّي راحة حقيقية، والقيمة هنا
     عشان تتغيّر في مكان واحد لكل الصفحات. */
  --shell-bottom:128px;
}

/* ═══════════════════════════════════════════════════════════
   الوضع الليلي

   ⚠ إعادة تعريف **التوكنات وبس** — ولا قاعدة تنسيق واحدة
   اتكررت. ده اللي بيخلّي الوضع الليلي سطور معدودة بدل نسخة
   تانية من الملف كله.

   ══ والألوان مش مقلوبة، هي **متعادة** ══
   قلب الفاتح للغامق بيطلّع رمادي ميّت. الخلفية هنا مشتقّة من
   الأخضر-الأسود بتاع الهوية (#16211D) — يعني الوضع الليلي
   بيحس إنه نفس المنتج في إضاءة تانية، مش تطبيق تاني.

   ══ ⚠ والنحاسي اتفتح شوية ══
   #B08D3D على خلفية غامقة تباينه ضعيف. #C9A557 بيحافظ على
   نفس الشخصية ويعدّي عتبة القراءة.

   ══ والأخضر الوظيفي زي ما هو تقريبًا ══
   لأنه لون الأزرار، ولو اتغيّر الموظّف هيبطّل يعرف إيه اللي
   بيتضغط — وهي القاعدة الحاكمة في هويتك.
   ═══════════════════════════════════════════════════════════ */
[data-theme="dark"]{
  --ground:#0E1613; --ground-soft:#1A2622;
  --surface:#121C18; --card:#18241F; --line:#2C3A34; --line-soft:#222E29;
  --ink:#E8EDE9; --ink-soft:#9FB0A7; --ink-faint:#6E8078;

  --brand:#C9A557; --brand-soft:#DBBC77; --brand-wash:#241F14; --brand-line:#4A3F26;

  --credit:#17936B; --credit-deep:#0F7052; --credit-wash:#12261F;
  --debit:#C4485C; --debit-wash:#2A171B;

  --shadow:0 1px 2px rgba(0,0,0,.4), 0 2px 8px rgba(0,0,0,.3);
  --shadow-lift:0 2px 4px rgba(0,0,0,.5), 0 8px 20px rgba(0,0,0,.4);

  color-scheme:dark;
}
*{box-sizing:border-box}

/* ⚠ touch-action:manipulation هنا هو أهم سطر واحد في الملف
   من ناحية السرعة المحسوسة.

   من غيره، المتصفح بيستنى بعد كل لمسة يشوف هتلمس تاني (زووم
   بضغطتين) ولا لأ — وبعدين ينفّذ. الانتظار ده بيوصل ٣٠٠ جزء من
   الثانية، وبيخلّي كل زرار في النظام يتحسّ متأخر.

   القيمة دي بتقول للمتصفح: مفيش زووم بضغطتين هنا، نفّذ فورًا.
   والتكبير بإصبعين لسه شغّال عادي. */
html,body{margin:0;padding:0;font-family:var(--font-ui);color:var(--ink);
  background:var(--surface);font-size:var(--fs-4);line-height:1.6;
  -webkit-text-size-adjust:100%;
  -webkit-tap-highlight-color:transparent;touch-action:manipulation}
:focus-visible{outline:2.5px solid var(--credit);outline-offset:2px;border-radius:3px}
button{font:inherit}

/* ═══ كتل التجهيز — الفروع والحسابات ═══ */
.setup-block{margin:18px 0;padding:13px;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--r-sm)}
.setup-head{display:flex;align-items:center;justify-content:space-between;
  gap:12px;margin-bottom:12px}
.setup-title{font-family:var(--font-display);font-size:var(--fs-4);font-weight:600}
.setup-row{padding:12px;margin-bottom:10px;background:var(--card);
  border:1px solid var(--line);border-radius:var(--r-sm)}
.setup-row .field{margin-bottom:10px}
.setup-row .field:last-of-type{margin-bottom:0}

/* ═══ ملخّص التسليم ═══
   إطار نحاسي تخين: دي الشاشة الوحيدة في النظام اللي بتعرض كلمات
   مرور نصّ صريح، ومحتواها ما بيترجّعش. لازم تبان إنها مختلفة. */
.handover{margin-bottom:18px;padding:15px;background:var(--brand-wash);
  border:2px solid var(--brand);border-radius:var(--r)}
.handover[hidden]{display:none}
.handover-title{margin:0 0 6px;font-family:var(--font-display);font-size:var(--fs-5);
  font-weight:700;color:var(--brand)}
.handover-note{margin:0 0 13px;font-size:var(--fs-2);line-height:1.7;color:var(--ink-soft)}
.handover-row{display:flex;align-items:baseline;justify-content:space-between;
  gap:12px;padding:9px 0;border-bottom:1px solid var(--brand-line)}
.handover-label{font-size:var(--fs-2);color:var(--ink-soft)}
.handover-value{font-family:var(--font-mono);font-size:var(--fs-5);direction:ltr}
.handover-card{padding:10px 0;border-bottom:1px solid var(--brand-line)}
.handover-who{font-size:var(--fs-3);font-weight:600;margin-bottom:5px}
/* الاسم وكلمة المرور بخط أحادي المسافة وقابلين للتحديد بسهولة —
   دي بتتنسخ بالإصبع على شاشة موبايل */
.handover-creds{font-family:var(--font-mono);font-size:var(--fs-4);direction:ltr;
  text-align:start;user-select:all;-webkit-user-select:all;
  background:var(--card);padding:8px 10px;border-radius:var(--r-sm)}
.handover .btn-mini{margin-top:13px}

/* قسم قابل للفتح في صفحة الدخول — هادي عشان ما يسحبش الانتباه
   من الحقول اللي كل الناس بتملاها */
.advanced{margin-bottom:18px}
.advanced summary{font-size:var(--fs-2);color:var(--ink-faint);cursor:pointer;
  padding:6px 0;list-style:none}
.advanced summary::-webkit-details-marker{display:none}
.advanced summary::before{content:"+ ";font-family:var(--font-mono)}
.advanced[open] summary::before{content:"− "}
.advanced[open] summary{margin-bottom:10px}

/* ═══ الشعار — العنصر المميّز ═══
   ميزان بخط رفيع نحاسي. الكفة بتتزن مرة واحدة عند فتح صفحة
   الدخول، وبعدها تسكن. حركة واحدة في النظام كله. */
.brandmark{display:inline-flex;align-items:center;gap:10px;color:var(--brand)}
.brandmark-word{font-family:var(--font-brand);font-weight:600;letter-spacing:.02em;
  line-height:1;color:var(--brand)}
.brandmark[data-size="lg"] .brandmark-word{font-size:var(--fs-brand)}
.brandmark[data-size="sm"] .brandmark-word{font-size:var(--fs-6)}
.mark{display:block;flex-shrink:0}
.mark-beam{transform-box:view-box;transform-origin:20px 12.5px}

@media (prefers-reduced-motion:no-preference){
  .brandmark[data-animate="true"] .mark-beam{
    animation:meezan-settle 1.15s cubic-bezier(.33,.78,.38,1) 1 both}
}
@keyframes meezan-settle{
  0%{transform:rotate(-9deg)}
  45%{transform:rotate(4.5deg)}
  74%{transform:rotate(-1.8deg)}
  100%{transform:rotate(0deg)}
}

/* ═══ الشارة — كلمة محفورة مش صندوق ═══
   بلا إطار، مستقيمة، تخينة، بتباعد حروف واسع.
   الإطار كان بيعمل صندوق صغير جنب الاسم فبياخد انتباه أكتر من
   الاسم نفسه. الحرف التخين النحاسي بيقول نفس المعلومة بهدوء. */
.stamp{display:inline-block;padding:0;border:none;background:none;
  color:var(--brand);font-family:var(--font-display);font-size:var(--fs-1);
  font-weight:700;letter-spacing:.09em;line-height:1.5;
  transform:none;white-space:nowrap}

/* ═══ الشريط العلوي ═══
   الخط النحاسي تحته هو خيط الأمان في ورقة البنكنوت — أرفع تفصيلة
   في الشاشة وأكترها تكرارًا. */
/* ⚠ وسم viewport فيه viewport-fit=cover، يعني الصفحة بتتمد تحت
   شريط حالة الموبايل (الساعة والبطارية) بدل ما تقف تحته.
   من غير الحشوة دي، اسم المستخدم بيتخبّي ورا النوتش في الأيفون.
   env() بترجّع صفر على أي جهاز مالوش نوتش — فويندوز وأندرويد
   القديم ما بيتأثروش. */
.app-bar{position:sticky;top:0;z-index:50;display:flex;align-items:center;
  justify-content:space-between;gap:12px;
  padding:11px calc(var(--pad) + env(safe-area-inset-right))
          11px calc(var(--pad) + env(safe-area-inset-left));
  padding-top:calc(11px + env(safe-area-inset-top));
  background:var(--ground);color:#fff;border-bottom:1.5px solid var(--brand)}
.who{display:flex;align-items:center;gap:9px;min-width:0}
.who .brandmark{color:var(--brand-soft)}
.who-name{font-family:var(--font-display);font-size:var(--fs-5);font-weight:600;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.app-bar .stamp{color:var(--brand-soft)}

/* ⚠ الطبقتين دول **مالهمش أي أثر على الموبايل**.
   «.who-shop» مخفي، فالعمود بيبقى فيه سطر واحد — يعني نفس
   الشكل القديم بالحرف. وجودهم هنا عشان الكمبيوتر يقلبهم
   بسطرين، من غير ما نبني شريط علوي تاني. */
.who-stack{display:flex;flex-direction:column;gap:2px;min-width:0}
.who-line{display:flex;align-items:center;gap:9px;min-width:0}
.who-shop{display:none;font-family:var(--font-display);font-size:var(--fs-5);
  font-weight:600;line-height:1.25;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ═══ ختم الصانع ═══
   «ميزان» بخط الشعار نحاسي، و«by Meazan» بخط أحادي بتباعد حروف
   واسع في الطرف التاني.

   ⚠ الفرق في **الخط** هو اللي بيعمل الهرم، مش فرق الأحجام.
   الاسم بالخط الكوفي والتوقيع بالأحادي — العين بتفرّق بينهم من
   غير ما واحد فيهم يكبر على التاني.

   ⚠ وساكن بلا حركة. القاعدة في الملف ده إن الكفة بتتزن مرة
   واحدة في صفحة الدخول وبس؛ جوّه النظام هي متزنة خلاص. */
.stamp-by{display:flex;align-items:center;gap:8px;
  padding-top:11px;border-top:1px solid var(--line-soft)}
.stamp-by .mark{color:var(--brand);flex:none}
.stamp-by-word{font-family:var(--font-brand);font-size:var(--fs-3);
  font-weight:600;color:var(--brand);line-height:1}
.stamp-by-note{margin-inline-start:auto;font-family:var(--font-mono);
  font-size:var(--fs-0);letter-spacing:.14em;color:var(--ink-faint);
  direction:ltr;line-height:1}

/* على الموبايل مكانه قدم قائمة النقط الثلاث */
.menu-stamp{padding:2px 12px 4px}
/* وعلى الكمبيوتر بينتقل لقدم الكعب — فمخفي هنا */
.rail-stamp{display:none}

/* ═══ قائمة النقط الثلاث ═══
   مبنية على <details> — بتشتغل بالكيبورد وبدون أي JavaScript. */
.menu{position:relative}
.menu>summary{list-style:none;width:40px;height:40px;display:grid;place-items:center;
  border-radius:var(--r-sm);cursor:pointer;font-size:var(--fs-7);line-height:1;color:#fff;
  background:rgba(255,255,255,.08)}
.menu>summary::-webkit-details-marker{display:none}
.menu[open]>summary{background:rgba(255,255,255,.18)}
.menu-sheet{position:absolute;inset-inline-end:0;top:calc(100% + 8px);z-index:60;
  min-width:240px;padding:6px;background:var(--card);color:var(--ink);
  border:1px solid var(--line);border-radius:var(--r);
  box-shadow:0 16px 40px -16px rgba(14,42,51,.5)}
.menu-info{padding:10px 12px 12px;border-bottom:1px solid var(--line-soft);margin-bottom:6px}
.menu-row{display:flex;justify-content:space-between;gap:12px;font-size:var(--fs-3);
  padding:3px 0;color:var(--ink-soft)}
.menu-row b{color:var(--ink);font-weight:600;font-family:var(--font-mono);
  font-size:var(--fs-2);direction:ltr}
.menu-item{display:block;width:100%;text-align:start;padding:11px 12px;font-size:var(--fs-5);
  color:var(--ink);background:none;border:none;border-radius:var(--r-sm);cursor:pointer}
/* ═══ شرائط الأدراج ═══
   ⚠ شرايط أفقية بتلفّ، مش قايمة رأسية. سبع أدراج في قايمة
   بتاخد نص الشاشة قبل ما المخزون يبدأ؛ نفس السبعة في شرايط
   بياخدوا سطرين.

   ⚠ والمختار بيتعلّم **بالخلفية والحدّ** مش باللون وحده —
   نفس قاعدة النظام: الفرق اللي بيتشاف بلون واحد بيضيع على
   شاشة مغسولة بالشمس قدّام كاونتر. */
/* ⚠ سطر واحد بيتزحلق، مش لفّ على سطور.

   بقى عندنا **خمس صفوف** فلترة. لو كل واحد لفّ، الصفوف كانت
   هتاخد نص الشاشة على الموبايل والمخزون يختفي تحت.

   السطر الواحد بيدّي ارتفاع ثابت متوقّع، و"الكل" بيفضل أول
   شريط دايمًا — فالرجوع نقرة واحدة من غير زحلقة. */
.drawers{display:flex;flex-wrap:nowrap;gap:6px;margin-bottom:14px;
  overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch}
.drawers::-webkit-scrollbar{display:none}
.drawer{flex:none}
/* ⚠ العنوان جنب الشرايط مش فوقها: خمس صفوف، والعين لازم تعرف
   أي صفّ بتبصّ عليه من غير ما تعدّ. */
.drawers-row{display:flex;align-items:baseline;gap:10px;margin-bottom:8px}
.drawers-row .drawers{margin-bottom:0;flex:1;min-width:0}
.drawers-label{flex:none;width:3.6em;font-size:var(--fs-2);
  color:var(--ink-faint);padding-top:8px;text-align:start}
/* النقطة الملوّنة — الشكل أسرع من الاسم في القراءة */
.dot{width:10px;height:10px;border-radius:50%;flex:none;
  border:1px solid rgba(0,0,0,.18)}
.drawer{display:inline-flex;align-items:center;gap:6px;
  min-height:36px;padding:0 12px;
  border:1px solid var(--line);border-radius:999px;
  background:transparent;color:var(--ink-soft);
  font-family:inherit;font-size:var(--fs-3);cursor:pointer}
.drawer:hover{border-color:var(--brand-soft)}
.drawer[data-on]{background:var(--brand);border-color:var(--brand);
  color:#fff;font-weight:600}
/* العدّ بخط أحادي عشان الأرقام تتحاذى ومتخبطش عرض الشريط */
.drawer-n{font-family:var(--font-mono);font-size:var(--fs-1);
  opacity:.75}
.drawer[data-add-drawer]{font-size:var(--fs-5);line-height:1;
  padding:0 14px;color:var(--brand)}

.menu-item[data-danger]{color:var(--debit)}
/* ⚠ العنصر المعطّل بيفضل **مقروء**، بس بلا مؤشّر ضغط.
   إخفاؤه كان هيخلّي المستخدم يدوّر على إعداد مش لاقيه؛ والحالة
   جنبه («غير مدعومة» · «مرفوضة من المتصفح») هي الرد على سؤاله. */
.menu-item:disabled{cursor:default;opacity:.55}

/* ⚠ اللافتة بتقول الوضع الحالي، فبتتكتب بالنحاسي — لون
   الهوية والحالة، مش لون الإجراء. الأخضر الوظيفي محجوز
   لأزرار الفعل وحدها، وده قانون هويتك. */
.menu-note{float:inline-end;font-size:var(--fs-3);color:var(--brand);font-weight:600}

/* ═══ شريط الانتباه ═══ بيقول حاجة واحدة: فيه حاجة مستنياك ولا لأ */
/* ⚠ قاعدة عامة إلزامية — اقراها قبل ما تضيف أي عنصر بـ hidden
   خاصية hidden في HTML بتشتغل عن طريق قاعدة [hidden]{display:none}
   في المتصفح نفسه. وأي كلاس عندنا بيحدّد display (زي display:flex)
   **بيغلبها**، لأن أنماط الصفحة دايمًا أقوى من أنماط المتصفح.
   النتيجة: عنصر مكتوب عليه hidden وظاهر على الشاشة.

   حصلت فعلاً مع شريط التنبيهات: ظهر فاضي وهو المفروض مخفي.
   القاعدة دي بتقفل الباب للأبد بدل ما نفتكر نكتب سطر لكل كلاس. */
[hidden]{display:none !important}

/* ═══ الطباعة ═══
   حاوية مخفية في كل صفحة. وقت الطباعة بتظهر لوحدها والباقي
   بيختفي — من غير نافذة جديدة، لأن window.open بيتمنع في سفاري
   على الأيفون وفي وضع التطبيق المثبّت. */
#print-root{display:none}

/* ═══ شبكة رسم النمط ═══
   ٩ نقط، بتتوصّل بالسحب أو الضغط. القيمة بتتخزّن كتسلسل
   أرقام "1-2-3-6-9" — مش صورة، عشان تتقرا وتتعدّل بالكتابة
   لو المستخدم عايز.

   ⚠ touch-action:none هنا **إلزامي** وبيغلب القاعدة العامة
   فوق: السحب بالإصبع لازم يرسم النمط مش يمرّر الصفحة. */
.pat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;
  width:200px;margin:8px auto;padding:14px;background:var(--card);
  border:1px solid var(--line);border-radius:var(--r);touch-action:none}
.pat-dot{aspect-ratio:1;border-radius:50%;background:var(--line);
  border:2px solid transparent;display:grid;place-items:center;
  font-family:var(--font-mono);font-size:var(--fs-2);color:transparent;cursor:pointer}
.pat-dot[data-on="true"]{background:var(--brand);border-color:var(--ground);
  color:var(--ground)}
.pat-out{text-align:center;font-family:var(--font-mono);font-size:var(--fs-4);
  letter-spacing:2px;direction:ltr;margin-top:4px}

/* ═══ عرض بيانات الفتح ═══
   النمط بيتعاد رسمه متحرّك بدل ما يتعرض كأرقام. الرقم
   "1-2-3-6-9" لازم تترجمه في دماغك لشكل؛ الرسم بيوريه على طول. */
.unlock-wrap{position:fixed;inset:0;z-index:250;display:grid;place-items:center;
  background:rgba(0,0,0,.85);
  padding:env(safe-area-inset-top) env(safe-area-inset-right)
          env(safe-area-inset-bottom) env(safe-area-inset-left)}
.unlock-panel{background:var(--card);border-radius:var(--r);padding:20px;
  width:min(92vw,340px);text-align:center}
.unlock-title{font-family:var(--font-display);font-size:var(--fs-5);margin-bottom:14px}
.unlock-pass{font-family:var(--font-mono);font-size:var(--fs-8);letter-spacing:3px;
  direction:ltr;padding:14px;background:var(--ground);color:#fff;
  border-radius:var(--r);word-break:break-all}

/* مسرح رسم النمط: النقط والخط فوق بعض */
.pat-play{position:relative;width:220px;height:220px;margin:0 auto}
.pat-play svg{position:absolute;inset:0;width:100%;height:100%}
.pat-play-dot{position:absolute;width:22px;height:22px;border-radius:50%;
  background:var(--line);transform:translate(-50%,-50%);
  transition:background var(--t-fast) var(--ease)}
.pat-play-dot[data-on="true"]{background:var(--brand);
  box-shadow:0 0 0 5px rgba(176,141,61,.25)}
.pat-play-seq{font-family:var(--font-mono);font-size:var(--fs-4);letter-spacing:3px;
  direction:ltr;margin-top:12px}

/* ═══ الماسح بالكاميرا ═══ */
.scan-wrap{position:fixed;inset:0;z-index:300;display:grid;place-items:center;
  background:rgba(0,0,0,.88);
  padding:env(safe-area-inset-top) env(safe-area-inset-right)
          env(safe-area-inset-bottom) env(safe-area-inset-left)}
.scan-box{width:min(94vw,460px);text-align:center}
.scan-video{width:100%;max-height:62vh;border-radius:var(--r);background:#000;
  object-fit:cover}
.scan-hint{color:#fff;font-size:var(--fs-4);margin:12px 0}

@media print{
  body > *{display:none !important}
  #print-root{display:block !important;color:#000;background:#fff}
  @page{margin:8mm}
}

/* ⚠ الطباعة بأحجام ثابتة مش بالمقياس: الورقة مقاسها فيزيائي،
   ومقبض حجم الشاشة مالوش دعوة بيها.
   وكان مكتوب هنا var(--font-body) وهو متغيّر **مش موجود** أصلًا
   في :root — كان شغّال بالصدفة عن طريق الوراثة. اتصلّح. */
.pr-doc{font-family:var(--font-ui);color:#000;font-size:13px;line-height:1.7}
.pr-head{display:flex;justify-content:space-between;align-items:baseline;
  border-bottom:2px solid #000;padding-bottom:6px;margin-bottom:10px}
.pr-shop{font-family:var(--font-display);font-size:18px;font-weight:600}
.pr-row{display:flex;justify-content:space-between;padding:3px 0}
.pr-total{border-top:1.5px solid #000;margin-top:8px;padding-top:8px;
  font-size:16px;font-weight:600}
.pr-note{margin-top:12px;font-size:11px;color:#444}
/* الملصق: مقاس صغير مستقل عن الفاتورة */
.pr-label{width:58mm;text-align:center;padding:3mm 1mm}
.pr-label-shop{font-family:var(--font-display);font-size:12px;font-weight:600;
  border-bottom:1px solid #000;padding-bottom:2px;margin-bottom:4px}
.pr-label-name{font-size:13px;font-weight:600;margin-bottom:3px}
.pr-label-code{font-family:var(--font-mono);font-size:11px;letter-spacing:1px;
  margin-top:2px;direction:ltr}
/* سطر المواصفات: بيلف لو طال بدل ما يتقص */
.pr-label-spec{font-size:10px;margin-top:4px;line-height:1.6;
  display:flex;flex-wrap:wrap;justify-content:center;gap:3px 8px}
.pr-label-foot{display:flex;justify-content:space-between;margin-top:5px;
  padding-top:3px;border-top:1px solid #000;font-size:10px;
  font-family:var(--font-mono)}

.strip{display:flex;align-items:center;gap:13px;padding:14px var(--pad);
  border-radius:var(--r);margin-bottom:14px;background:var(--card);
  border:1px solid var(--line)}
.strip[data-tone="wait"]{background:var(--thread-wash);border-color:#EBD9AE}
.strip-count{font-family:var(--font-display);font-size:var(--fs-9);font-weight:700;
  line-height:1;color:var(--thread);font-variant-numeric:tabular-nums}
.strip-text{font-size:var(--fs-4);line-height:1.55;flex:1}
.strip-text b{font-weight:600}
.strip-go{padding:9px 14px;font-size:var(--fs-4);font-weight:600;color:#fff;
  background:var(--thread);border:none;border-radius:var(--r-sm);
  text-decoration:none;white-space:nowrap}
.strip[data-tone="calm"] .strip-text{color:var(--ink-soft)}

/* ═══ بلاطات الإجراءات ═══ */
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
.tile{display:flex;flex-direction:column;justify-content:space-between;gap:10px;
  min-height:94px;padding:14px;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);text-decoration:none;color:var(--ink)}
.tile:active{background:var(--surface)}
.tile-label{font-family:var(--font-display);font-size:var(--fs-5);font-weight:600;
  line-height:1.35}
.tile-note{font-size:var(--fs-2);color:var(--ink-soft);line-height:1.5}
.tile-num{font-family:var(--font-mono);font-size:var(--fs-7);font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr}
.tile[data-wide]{grid-column:1/-1;min-height:0;flex-direction:row;align-items:center;
  justify-content:space-between}

/* ═══ الأقسام القابلة للطي ═══ */
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
  margin-bottom:10px;overflow:hidden}
.panel>summary{list-style:none;display:flex;align-items:center;justify-content:space-between;
  gap:10px;padding:15px var(--pad);cursor:pointer;font-family:var(--font-display);
  font-size:var(--fs-5);font-weight:600}
.panel>summary::-webkit-details-marker{display:none}
.panel>summary::after{content:'+';font-family:var(--font-mono);font-size:var(--fs-7);
  color:var(--ink-faint);line-height:1}
.panel[open]>summary::after{content:'−'}
.panel[open]>summary{border-bottom:1px solid var(--line-soft)}
.panel-body{padding:var(--pad)}

/* ═══ الشريط السفلي ═══ إبهامك بيوصله من غير ما تمد إيدك */
.tabbar{position:fixed;inset-inline:0;bottom:0;z-index:40;display:flex;
  padding-inline:env(safe-area-inset-left) env(safe-area-inset-right);
  background:var(--card);border-top:1px solid var(--line);
  padding-bottom:env(safe-area-inset-bottom)}
.tabbar a{flex:1;padding:11px 4px 13px;text-align:center;text-decoration:none;
  font-size:var(--fs-2);font-weight:600;color:var(--ink-faint);
  border-top:2.5px solid transparent;margin-top:-1px}
/* التبويب النشط نحاسي مش أخضر: التنقّل تحديد مكان، مش إجراء.
   الأخضر محجوز لحاجة بتحصل لما تدوس عليها. */
.tabbar a[aria-current="page"]{color:var(--brand);border-top-color:var(--brand)}
.tabbar a:active{background:var(--surface)}
.tabbar-icon{display:block;font-family:var(--font-mono);font-size:var(--fs-6);
  margin-bottom:2px}
/* الجوانب مهمة في الوضع الأفقي: النوتش بياكل من الشمال أو اليمين */
/* ⚠ المسافة السفلية من متغيّر — بتتغيّر لكل الصفحات مرة واحدة */
.shell{max-width:640px;margin:0 auto;
  padding:14px calc(var(--pad) + env(safe-area-inset-right))
          calc(var(--shell-bottom) + env(safe-area-inset-bottom))
          calc(var(--pad) + env(safe-area-inset-left))}

/* ═══ الحقول ═══ */
.field{margin-bottom:15px}
.field-label{display:block;font-size:var(--fs-3);font-weight:600;margin-bottom:6px}
/* ⚠ حجم الخانة من --fs-input مش من المقياس العام. السبب مكتوب
   جنب المتغيّر في :root: أقل من 16px بيخلّي الأيفون يزوّم. */
.field-input,.field-area{width:100%;padding:0 14px;font-family:var(--font-ui);
  font-size:var(--fs-input);color:var(--ink);background:var(--card);
  border:1.5px solid var(--line);border-radius:var(--r-sm)}
.field-input{height:var(--tap)}
.field-area{padding:13px 14px;min-height:104px;line-height:1.7;resize:vertical}
.field-input:focus,.field-area:focus{border-color:var(--credit);outline:none}
select.field-input{appearance:none;
  background-image:linear-gradient(45deg,transparent 50%,var(--ink-faint) 50%),
    linear-gradient(135deg,var(--ink-faint) 50%,transparent 50%);
  background-position:16px calc(50% + 1px),21px calc(50% + 1px);
  background-size:5px 5px,5px 5px;background-repeat:no-repeat}
.field-hint{font-size:var(--fs-2);color:var(--ink-soft);margin:6px 0 0;line-height:1.6}

.btn-primary{width:100%;height:var(--tap);font-family:var(--font-display);
  font-size:var(--fs-5);font-weight:600;color:#fff;background:var(--credit);
  border:none;border-radius:var(--r-sm);cursor:pointer}
.btn-primary:disabled{background:var(--ink-faint);cursor:not-allowed}
.btn-mini{height:36px;padding:0 13px;font-size:var(--fs-3);font-weight:600;color:var(--ink);
  background:var(--card);border:1.5px solid var(--line);border-radius:var(--r-sm);
  cursor:pointer;white-space:nowrap}
.btn-mini:disabled{opacity:.5;cursor:not-allowed}

.alert-box{display:flex;gap:10px;padding:12px 14px;margin-bottom:16px;
  font-size:var(--fs-4);line-height:1.6;color:var(--debit);background:var(--debit-wash);
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
.roster-name{display:block;font-size:var(--fs-5);font-weight:600;line-height:1.4}
.roster-id{display:block;margin-top:2px;font-family:var(--font-mono);font-size:var(--fs-2);
  color:var(--ink-soft);direction:ltr;text-align:right;overflow-wrap:anywhere}
.roster-side{display:flex;align-items:center;gap:8px;flex-shrink:0}
.roster-row[data-inactive="true"] .roster-name{text-decoration:line-through;color:var(--ink-faint)}
.roster-row[data-inactive="true"] .roster-id{opacity:.55}

.tag{display:inline-block;padding:3px 8px;font-family:var(--font-mono);
  font-size:var(--fs-1);border-radius:3px;white-space:nowrap;color:var(--ink-soft);
  background:var(--surface);border:1px solid var(--line)}
.tag[data-variant="off"]{color:var(--debit);background:var(--debit-wash);border-color:#F0D2D7}
.tag[data-variant="wait"]{color:var(--thread);background:var(--thread-wash);border-color:#EBD9AE}

/* ═══ الأرصدة ═══
   المبلغ بخط العرض بحجم كبير وخيط ذهبي فوقه، زي رقم الفئة على
   البنكنوت. ده المكان الوحيد اللي بنصرف فيه جرأة بصرية. */
.balances{display:grid;gap:10px}
.bal-card{padding:15px var(--pad);background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);border-top:2px solid var(--thread)}
.bal-name{font-size:var(--fs-4);font-weight:600}
.bal-meta{display:block;font-family:var(--font-mono);font-size:var(--fs-1);
  color:var(--ink-faint);margin-top:2px;direction:ltr;text-align:right}
.bal-amount{display:block;margin-top:10px;font-family:var(--font-display);
  font-size:var(--fs-10);font-weight:700;line-height:1;font-variant-numeric:tabular-nums;
  direction:ltr;text-align:right;color:var(--credit-deep)}
.bal-amount[data-negative="true"]{color:var(--debit)}
.bal-cur{font-family:var(--font-ui);font-size:var(--fs-3);font-weight:500;
  color:var(--ink-faint);margin-inline-start:6px}
.bal-total{border-top-color:var(--ground);background:var(--ground);color:#fff}
.bal-total .bal-name{color:rgba(255,255,255,.72)}
.bal-total .bal-amount{color:#fff}
.bal-total .bal-cur{color:rgba(255,255,255,.5)}

/* ═══ الحركات ═══ */
.mv-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;
  padding:13px 0;border-bottom:1px solid var(--line-soft)}
.mv-row:last-child{border-bottom:none}
.mv-main{min-width:0;flex:1}
.mv-title{font-size:var(--fs-4);font-weight:600;line-height:1.5}
.mv-sub{display:block;font-size:var(--fs-2);color:var(--ink-soft);margin-top:3px;
  line-height:1.6}
.mv-side{display:flex;flex-direction:column;align-items:flex-end;gap:7px;flex-shrink:0}
.mv-amount{font-family:var(--font-mono);font-size:var(--fs-4);font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr;white-space:nowrap}
.mv-amount[data-dir="IN"]{color:var(--credit)}
.mv-amount[data-dir="OUT"]{color:var(--debit)}
.mv-row[data-status="PENDING"]{background:var(--thread-wash);
  margin-inline:calc(var(--pad) * -1);padding-inline:var(--pad)}
.mv-row[data-status="REJECTED"] .mv-title{text-decoration:line-through;color:var(--ink-faint)}
.mv-actions{display:flex;gap:6px}

.empty{padding:26px 16px;text-align:center}
.empty-title{font-family:var(--font-display);font-size:var(--fs-5);font-weight:600;
  margin:0 0 6px}
.empty-note{font-size:var(--fs-3);color:var(--ink-soft);line-height:1.65;margin:0}
.muted{font-size:var(--fs-3);color:var(--ink-soft);line-height:1.65;margin:0 0 14px}

/* ═══ نافذة الإعلان الإلزامي ═══
   ⚠ اتشال من هنا backdrop-filter:blur — التمويه بيتحسب على كل
   إطار وبيتهته على موبايل متوسط، والنافذة بتتفتح بتقل. خلفية
   أغمق شوية بتعمل نفس الفصل البصري بصفر تكلفة. */
.gate-backdrop{position:fixed;inset:0;z-index:100;display:grid;place-items:center;
  padding:18px;background:rgba(14,42,51,.84)}
.gate-panel{width:100%;max-width:520px;max-height:88dvh;display:flex;flex-direction:column;
  background:var(--card);border-radius:var(--r);overflow:hidden}
.gate-head{padding:18px var(--pad) 14px;border-bottom:1px solid var(--line)}
.gate-tag{display:inline-block;padding:3px 9px;margin-bottom:10px;font-family:var(--font-mono);
  font-size:var(--fs-1);border-radius:3px}
.gate-tag[data-severity="INFO"]{color:var(--credit-deep);background:var(--credit-wash)}
.gate-tag[data-severity="WARNING"]{color:var(--thread);background:var(--thread-wash)}
.gate-tag[data-severity="CRITICAL"]{color:#fff;background:var(--debit)}
.gate-title{font-family:var(--font-display);font-size:var(--fs-7);font-weight:700;margin:0}
.gate-body{padding:18px var(--pad);overflow-y:auto;font-size:var(--fs-5);line-height:1.8;
  white-space:pre-wrap}
.gate-foot{padding:15px var(--pad);border-top:1px solid var(--line);background:var(--surface)}
.gate-count{font-family:var(--font-mono);font-size:var(--fs-2);color:var(--ink-soft);
  margin:0 0 10px;direction:ltr;text-align:right}

/* ═══ شريط تحذير الخمول ═══ */
.idle-bar{position:fixed;inset-block-end:0;inset-inline:0;z-index:90;display:flex;
  align-items:center;justify-content:center;gap:12px;padding:14px 16px;
  padding-bottom:calc(14px + env(safe-area-inset-bottom));font-size:var(--fs-5);color:#fff;
  background:var(--debit)}
.idle-count{font-family:var(--font-mono);font-size:var(--fs-6);font-weight:500}
.idle-btn{padding:9px 17px;font-size:var(--fs-5);font-weight:600;color:var(--debit);
  background:#fff;border:none;border-radius:var(--r-sm);cursor:pointer}

/* ═══ قفل الشاشة ═══ */
.lock-screen{position:fixed;inset:0;z-index:200;display:grid;place-items:center;
  padding:24px;background:var(--ground);color:#fff}
.lock-card{width:100%;max-width:320px;text-align:center}
.lock-eyebrow{font-family:var(--font-mono);font-size:var(--fs-1);letter-spacing:.16em;
  color:rgba(255,255,255,.45);margin:0 0 12px}
.lock-title{font-family:var(--font-display);font-size:var(--fs-8);font-weight:600;margin:0 0 6px}
.lock-who{font-size:var(--fs-4);color:rgba(255,255,255,.62);margin:0 0 24px;line-height:1.6}
.lock-input{width:100%;height:var(--tap);padding:0 14px;font-family:var(--font-ui);
  font-size:var(--fs-input);color:#fff;background:rgba(255,255,255,.08);
  border:1.5px solid rgba(255,255,255,.2);border-radius:var(--r-sm);text-align:center}
.lock-input:focus{outline:none;border-color:#fff;background:rgba(255,255,255,.14)}
.lock-btn{width:100%;height:var(--tap);margin-top:10px;font-family:var(--font-display);
  font-size:var(--fs-5);font-weight:600;color:var(--ground);background:#fff;border:none;
  border-radius:var(--r-sm);cursor:pointer}
.lock-btn:disabled{opacity:.5;cursor:not-allowed}
.lock-error{font-size:var(--fs-4);color:#F2A9AF;margin:14px 0 0;min-height:20px}
.lock-exit{margin-top:20px;font-size:var(--fs-3);color:rgba(255,255,255,.5);background:none;
  border:none;text-decoration:underline;cursor:pointer;font-family:var(--font-ui)}

/* ═══ الدخول ═══ */
.counter{min-height:100dvh;display:grid;place-items:center;padding:24px 16px;
  background:var(--surface)}
.counter-brand{display:flex;justify-content:center;margin-bottom:18px}
.counter-card{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);
  border-top:none;padding:30px 26px 26px;border-radius:0 0 var(--r) var(--r);
  box-shadow:0 20px 50px -30px rgba(14,42,51,.55)}
.receipt-edge{width:100%;max-width:400px;height:11px;display:block;color:var(--card)}
.counter-eyebrow{font-family:var(--font-mono);font-size:var(--fs-1);letter-spacing:.14em;
  color:var(--ink-faint);margin:0 0 6px;direction:ltr;text-align:right}
.counter-title{font-family:var(--font-display);font-size:var(--fs-9);font-weight:700;
  letter-spacing:-.005em;margin:0 0 4px}
.counter-sub{font-size:var(--fs-4);color:var(--ink-soft);margin:0 0 24px;line-height:1.6}
.counter-foot{display:flex;justify-content:space-between;margin-top:22px;padding-top:15px;
  border-top:1px dashed var(--line);font-family:var(--font-mono);font-size:var(--fs-1);
  color:var(--ink-faint);direction:ltr}

.vault{min-height:100dvh;display:grid;place-items:center;padding:24px;background:#080B0D;
  color:#B9C4C7}
.vault-card{width:100%;max-width:330px}
.vault-field{margin-bottom:13px}
.vault-input{width:100%;height:50px;padding:0 14px;font-family:var(--font-mono);
  font-size:var(--fs-input);letter-spacing:.05em;color:#B9C4C7;background:#0F1417;
  border:1px solid #1C2529;border-radius:3px}
.vault-input::placeholder{color:#4C5A5F;letter-spacing:.12em}
.vault-input:focus{border-color:#B9C4C7;outline:none}
.vault-btn{width:100%;height:50px;margin-top:6px;font-family:var(--font-mono);
  font-size:var(--fs-3);letter-spacing:.1em;color:#080B0D;background:#B9C4C7;border:none;
  border-radius:3px;cursor:pointer}
.vault-btn:disabled{color:#4C5A5F;background:#1C2529;cursor:not-allowed}
.vault-error{font-family:var(--font-mono);font-size:var(--fs-2);color:#C97B7B;margin:0 0 13px;
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
.cart-title{font-family:var(--font-display);font-size:var(--fs-5);font-weight:600}
.cart-empty{margin:0;padding:22px var(--pad);text-align:center;font-size:var(--fs-3);
  color:var(--ink-faint)}
.cart-empty[hidden]{display:none}

.cart-line{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:11px var(--pad);border-bottom:1px solid var(--line-soft)}
.cart-line-main{min-width:0;flex:1}
.cart-line-name{display:block;font-size:var(--fs-4);font-weight:600;line-height:1.45;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cart-line-sub{display:block;font-family:var(--font-mono);font-size:var(--fs-1);
  color:var(--ink-soft);margin-top:3px;direction:ltr;text-align:start}
.cart-line-side{display:flex;flex-direction:column;align-items:flex-end;gap:7px;flex-shrink:0}
.cart-line-amount{font-family:var(--font-mono);font-size:var(--fs-4);font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr}

/* أزرار الكمية 40 بكسل: بتتضغط بالإبهام وقدّام طابور */
.qty-steps{display:flex;align-items:center;gap:2px;border:1px solid var(--line);
  border-radius:var(--r-sm);overflow:hidden}
.qty-btn{width:40px;height:36px;font-family:var(--font-mono);font-size:var(--fs-6);
  line-height:1;color:var(--ink);background:var(--card);border:none;cursor:pointer}
.qty-btn:active:not(:disabled){background:var(--surface)}
.qty-btn:disabled{color:var(--ink-faint);cursor:not-allowed}
.qty-num{min-width:34px;text-align:center;font-family:var(--font-mono);font-size:var(--fs-4);
  font-weight:500;font-variant-numeric:tabular-nums}

.cart-total{display:flex;align-items:baseline;justify-content:space-between;gap:12px;
  padding:14px var(--pad);background:var(--ground);color:#fff}
.cart-total-label{font-size:var(--fs-4);color:rgba(255,255,255,.72)}
.cart-total-num{font-family:var(--font-display);font-size:var(--fs-9);font-weight:700;
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
.prod-btn-name{font-size:var(--fs-4);font-weight:600;line-height:1.35;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.prod-btn-price{margin-top:auto;font-family:var(--font-mono);font-size:var(--fs-4);
  font-weight:500;color:var(--credit);direction:ltr}
.prod-btn-qty{font-family:var(--font-mono);font-size:var(--fs-1);color:var(--ink-faint);
  direction:rtl}

/* ═══ صفوف شاشة المنتجات ═══
   flex-wrap مش حساب عرض يدوي: لوحة التعديل بتنزل سطر كامل تحت
   لوحدها، والسطر بيتظبط مهما طال الاسم. */
.prod-row{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;
  gap:12px;padding:12px 0;border-bottom:1px solid var(--line-soft)}
.prod-row:last-child{border-bottom:none}
.prod-row-main{flex:1;min-width:0}
.prod-row-name{display:block;font-size:var(--fs-4);font-weight:600;line-height:1.45}
.prod-row-name[data-off="true"]{color:var(--ink-faint);text-decoration:line-through}
.prod-row-sub{display:block;font-family:var(--font-mono);font-size:var(--fs-1);
  color:var(--ink-soft);margin-top:3px;direction:ltr;text-align:start}
.prod-row-side{display:flex;align-items:center;gap:9px;flex-shrink:0}
.prod-row-qty{font-family:var(--font-mono);font-size:var(--fs-6);font-weight:500;
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

/* ═══ نوع المنتج ═══
   الجهاز والإكسسوار قاعدتين مختلفتين، فبيتفرّقوا بالعين قبل
   ما تقرا. الجهاز نحاسي (له سريال وقطعة واحدة)، الإكسسوار رمادي
   هادي (صنف بكمية). */
.type-tag{display:inline-block;padding:1px 7px 2px;border-radius:3px;
  font-family:var(--font-mono);font-size:var(--fs-0);font-weight:500;
  letter-spacing:.04em;line-height:1.6;white-space:nowrap}
.type-tag[data-type="device"]{color:var(--brand);background:var(--brand-wash)}
.type-tag[data-type="accessory"]{color:var(--ink-soft);background:var(--surface)}

/* السريال بخط أحادي المسافة: الأرقام والحروف بتتصفّ فبتقارن أسرع */
.serial{font-family:var(--font-mono);font-size:var(--fs-1);color:var(--ink-soft);
  direction:ltr;unicode-bidi:embed}

/* ═══ السعر الحالي في لوحة التعديل ═══
   نص مش خانة إدخال، عشان يستحيل تدهسه وإنت بتكتب. */
.price-now{display:flex;align-items:baseline;justify-content:space-between;
  gap:12px;padding:10px 12px;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r-sm);margin-bottom:10px}
.price-now-label{font-size:var(--fs-2);color:var(--ink-soft)}
.price-now-value{font-family:var(--font-mono);font-size:var(--fs-5);font-weight:500;
  font-variant-numeric:tabular-nums;direction:ltr}
.price-now-value[data-empty="true"]{color:var(--ink-faint);font-size:var(--fs-3)}

/* ═══ سجل الأسعار ═══ */
.price-log{margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}
.price-log-title{font-size:var(--fs-2);font-weight:600;color:var(--ink-soft);margin:0 0 7px}
.price-log-row{display:flex;align-items:baseline;justify-content:space-between;
  gap:10px;padding:4px 0;font-size:var(--fs-2)}
.price-log-move{font-family:var(--font-mono);direction:ltr;font-variant-numeric:tabular-nums}
.price-log-who{color:var(--ink-faint);font-size:var(--fs-1)}

/* ═══ السعر اليدوي في السلة ═══
   بيظهر بس للمنتجات اللي مالهاش سعر مسجّل. */
.cart-price{display:flex;align-items:center;gap:6px;margin-top:6px}
.cart-price-input{width:104px;height:38px;padding:0 9px;font-family:var(--font-mono);
  font-size:var(--fs-input);direction:ltr;text-align:center;color:var(--ink);
  background:var(--card);border:1.5px solid var(--brand);border-radius:var(--r-sm)}
.cart-price-input:focus{outline:none;border-color:var(--credit)}
.cart-price-note{font-size:var(--fs-1);color:var(--brand)}

/* عدّاد الأجهزة — الرقم اللي القائمة مترتّبة بيه، فبيبقى أوضح
   حاجة في السطر. الصفر بيبهت عشان الترتيب يقرا نفسه من فوق لتحت. */
.dev-count{display:flex;flex-direction:column;align-items:center;
  min-width:44px;line-height:1.15}
.dev-count b{font-family:var(--font-mono);font-size:var(--fs-6);font-weight:600;
  font-variant-numeric:tabular-nums;color:var(--brand)}
.dev-count span{font-size:var(--fs-0);color:var(--ink-faint)}
.dev-count[data-zero="true"] b{color:var(--ink-faint)}

/* ملاحظات العميل: بتلتف على أكتر من سطر مش بتتقص */
.cust-notes{display:block;font-size:var(--fs-2);color:var(--ink-soft);
  line-height:1.6;margin-top:4px;white-space:pre-wrap}

/* لوحة تعديل تاريخ الخروج جوّه صف الفاتورة */
.exit-edit{flex-basis:100%;display:flex;flex-wrap:wrap;align-items:center;gap:8px;
  margin-top:10px;padding:11px;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--r-sm)}
.exit-edit[hidden]{display:none}
.exit-edit .field-input{width:auto;flex:1;min-width:150px}
.exit-edit .field-hint{flex-basis:100%;margin:0}

textarea.field-input{height:auto;padding:10px 12px;line-height:1.7;resize:vertical}

@media (max-width:360px){
  .prod-grid{grid-template-columns:1fr}
  .prod-edit-grid{grid-template-columns:1fr}
  .tiles{grid-template-columns:1fr}
}

/* ═══════════════════════════════════════════════════════════
   الاستجابة للّمس — أهم قسم في الملف

   ══ ⚠ القاعدة الحاكمة: الضغطة فورية، والرجوع بيهدى ══

   كان الزرار بيغيّر لونه على مدى 110 جزء من الثانية وقت الضغط.
   والنتيجة إن الموظّف بيدوس وما بيحصلش حاجة **لحظيًا** — فيدوس
   تاني، ويلاقي العملية اتنفّذت مرتين أو الشاشة "معلّقة".

   دلوقتي:
      الضغط  → transition-duration:0s  → اللون بيتغيّر في نفس اللحظة
      الرفع  → 90ms                    → بيرجع بهدوء

   ودي هي بالظبط طريقة التطبيقات الأصلية. الفرق بين شاشة بتحس
   إنها بتردّ وشاشة بتحس إنها بتتكسّل.

   ══ والحركة على transform وopacity بس ══
   دول الاتنين اللي المتصفح بيحرّكهم على كارت الشاشة. أي حاجة
   تانية (عرض، ارتفاع، **ظل**) بتجبره يعيد الحساب كل إطار.
   ⚠ عشان كده box-shadow اتشال من قائمة الانتقالات خالص.

   ══ ⚠ و:hover اتحبس على أجهزة الماوس بس ══
   على اللمس، :hover بيلزق بعد الضغط: بتسيب الزرار ويفضل مضوّي
   لحد ما تدوس في حتة تانية. ده بيخلّي الشاشة تبان لخبطة.
   القاعدة (hover:hover) بتقول: طبّقها بس لو فيه ماوس حقيقي.
   ═══════════════════════════════════════════════════════════ */

.btn-primary,.btn-mini,.tile,.panel>summary,.tabbar a,.menu-item,
.qty-btn,.prod-btn,.strip-go,.idle-btn,.lock-btn,.vault-btn{
  touch-action:manipulation;
  transition:background var(--t-fast) var(--ease),
             border-color var(--t-fast) var(--ease),
             color var(--t-fast) var(--ease),
             transform var(--t-fast) var(--ease)}

/* ⚠ السطر ده هو الفرق كله: صفر تأخير لحظة الضغط */
.btn-primary:active,.btn-mini:active,.tile:active,.panel>summary:active,
.tabbar a:active,.menu-item:active,.qty-btn:active,.prod-btn:active,
.strip-go:active,.idle-btn:active,.lock-btn:active,.vault-btn:active{
  transition-duration:0s}

.btn-primary:active:not(:disabled){transform:scale(.985)}
.btn-mini:active:not(:disabled){transform:scale(.97)}
.tile:active{transform:scale(.985)}
.prod-btn:active{transform:scale(.985)}
.strip-go:active{transform:scale(.97)}
.menu-item:active{background:var(--surface)}
.panel>summary:active{background:var(--surface)}

/* أجهزة الماوس وحدها */
@media (hover:hover) and (pointer:fine){
  .btn-primary:hover:not(:disabled){background:var(--credit-deep)}
  .btn-mini:hover:not(:disabled){border-color:var(--ink-soft)}
  .btn-mini[data-danger="true"]:hover:not(:disabled){color:var(--debit);border-color:var(--debit)}
  .menu-item:hover{background:var(--surface)}
  .tile:hover{border-color:var(--ink-faint)}
}

/* ⚠ الحقل بيتوسّع بحلقة بدل ما يقفز.
   التغيير في box-shadow مش في border-width — عرض الحد لو
   اتغيّر، العنصر بيكبر والصفحة كلها تتزحلق تحته.

   والحلقة بتظهر **فورًا** بلا انتقال: علامة "أنا واقف هنا"
   المفروض تسبق الكيبورد مش تلحقه. */
.field-input,.field-area,.cart-price-input,.lock-input,.vault-input{
  transition:border-color var(--t-fast) var(--ease)}
.field-input:focus,.field-area:focus{
  box-shadow:0 0 0 3px var(--credit-wash)}

/* الكروت بتاخد عمق خفيف — بيفصلها عن الخلفية في الوضعين.
   ⚠ ثابت، مش متحرّك. */
.tile,.panel,.bal-card{box-shadow:var(--shadow)}
.panel[open]{box-shadow:var(--shadow-lift)}

/* ═══ ⚠ ظهور المحتوى — اتشال بالكامل ═══

   كان فيه هنا: .shell>* { animation: rise ... }
   يعني **كل** عنصر في الصفحة بيبدأ مخفي وبيطلع من تحت لفوق.

   المشكلة إن ده مش زينة — ده تأخير حقيقي قبل ما تشوف حاجة، وبيتكرر
   مع كل فتح شاشة. الموظّف اللي بيفتح الكاشير خمسين مرة في اليوم
   بيدفع الانتظار ده خمسين مرة.

   تشبيه: بدل ما تدخل الجيم تلاقي الناس واقفة مستنياك، كل واحد
   بيدخل من الباب قدامك واحد واحد.

   ⚠ التطبيقات السريعة بتعرض المحتوى **فورًا**. المحتوى الفوري
   هو الحركة. لو حبيت ترجّعها يومًا ما، ارجع لسجل جيت هب — بس
   اعرف إن ده تأخير مقصود بتدفعه من سرعة الشاشة. */

/* ═══════════════════════════════════════════════════════════
   توزيعة الكمبيوتر — "الدفتر المفتوح"

   ══ الفكرة ══
   على الموبايل إنت ماسك الدفتر **مقفول**، بتقلب صفحة صفحة.
   الشريط السفلي تحت إبهامك، والعمود ضيّق عشان العين تقرا من
   غير ما الرقبة تلف. ده تصميم صح ومش محتاج يتغيّر.

   على الكمبيوتر إنت بتفرد الدفتر على المكتب. والدفتر العربي
   كعبه على اليمين — فالشريط السفلي بيقوم من تحت ويقف **كعب
   على اليمين**، والصفحة بتتفرد على شماله.

   ══ ⚠ والموبايل ما اتلمسش ولا حرف ══
   كل اللي تحت جوّه «@media» واحدة. لو شيلتها، النظام بيرجع
   لشكله القديم بالظبط على كل الأجهزة.

   ══ ⚠ ليه 1024 ══
   تحتها التابلت الأفقي، والكعب بعرض 236 كان هياكل ربع الشاشة
   ويسيب المحتوى مخنوق. فوقها فيه فضل مساحة حقيقي.

   ══ ⚠ والمقابض هي اللي بتتغيّر مش القواعد ══
   كل اللي تحت بيعيد ضبط متغيّرات موجودة في «:root» أصلاً. ده
   اللي خلّى التعديل ده رخيص: التصميم كان مبني على مقابض من
   الأول، مش على أرقام متناثرة.
   ═══════════════════════════════════════════════════════════ */
@media (min-width:1024px){
  :root{
    /* 54 مقاس **إصبع**. الماوس بيوصل لنص المسافة دي بدقة،
       والزراير الطويلة على شاشة كبيرة بتبان فجّة. */
    --tap:44px;
    --pad:24px;
    /* مفيش شريط سفلي نفضّيله مكان — الحشوة بترجع مسافة راحة بس */
    --shell-bottom:56px;
    --rail:236px;
  }

  /* ⚠ الزحزحة على «body» مش على كل عنصر لوحده.
     كده الشريط العلوي اللاصق والمحتوى بيتزحزحوا مع بعض، ومفيش
     حاجة بتعدّي تحت الكعب لو صفحة جديدة اتضافت بكرة. */
  body{padding-inline-start:var(--rail)}

  /* ─── الكعب ───
     ⚠ الخيط النحاسي مش عنصر جديد. هو **هو نفسه** اللي كان تحت
     الشريط العلوي، بس واقف بدل ما هو نايم — نفس التفصيلة بعد
     ربع لفة. */
  .tabbar{
    inset-inline:0 auto;top:0;bottom:0;width:var(--rail);
    flex-direction:column;align-items:stretch;gap:2px;
    padding:18px 0 var(--pad);
    background:var(--surface);
    border-top:none;
    border-inline-end:1.5px solid var(--brand);
  }
  .tabbar a{
    flex:0 0 auto;display:flex;align-items:center;gap:12px;
    height:var(--tap);padding:0 var(--pad);
    text-align:start;font-size:var(--fs-4);
    border-top:none;margin-top:0;
    /* العلامة على الحافة **البرّانية**. الجوّانية عليها الخيط
       النحاسي خلاص، ولو حطّيناها هناك الاتنين هيتخانقوا. */
    border-inline-start:2.5px solid transparent;
  }
  .tabbar a[aria-current="page"]{
    background:var(--card);border-inline-start-color:var(--brand)}
  .tabbar-icon{display:inline;margin:0;width:1.2em;text-align:center;
    font-size:var(--fs-5)}

  /* ختم الصانع في قدم الكعب. «margin-top:auto» بتدفعه لتحت
     مهما كان عدد الوجهات فوقه. */
  .rail-stamp{display:block;margin-top:auto;padding:0 var(--pad)}
  .menu-stamp{display:none}

  /* ─── الشريط العلوي: لهوية المحل وحدها ───

     ⚠ الميزان الصغير بيختفي من هنا وبينزل للكعب. ميزانين في
     شاشة واحدة بيلغوا بعض.

     والنتيجة إن الشريط بقى **لاسم المحل**، والكعب لهوية النظام.
     صاحب المحل بيبص فوق يلاقي محله، وبيبص على الكعب يلاقي مين
     بنى اللي هو ماسكه. */
  .app-bar{padding-block:9px}
  .app-bar .brandmark{display:none}
  .who-shop{display:block}
  /* ⚠ مربوطة بـ«[data-shop]» عن قصد: الصفحات اللي مالهاش محل
     (شاشة المنصّة) اسم الموظّف فيها هو السطر الوحيد، فما يصحّش
     يتصغّر ويبهت وهو لوحده. */
  .who[data-shop] .who-name{font-size:var(--fs-3);font-weight:500;
    color:rgba(255,255,255,.72)}

  /* ─── الصفحة ───
     ⚠ مفيش «margin:0 auto» هنا — الصفحة بتتزنق ناحية الكعب مش
     بتتوسّط الشاشة. الدفتر المفرود جنبه كعب من ناحية واحدة، مش
     طاير في النص. */
  .shell{max-width:1120px;margin-inline:0;padding-top:var(--pad)}

  .tiles{grid-template-columns:repeat(3,1fr);gap:14px}
  /* ⚠ العريضة بتاخد **عمودين** مش الصف كله، وبترجع عمود بدل
     ما تتفرد على الطرفين: على عرض 1120 الاسم كان هيقف يمين
     والوصف شمال، وبينهم صحرا فاضية. */
  .tile[data-wide]{grid-column:span 2;flex-direction:column;
    align-items:flex-start;justify-content:center;gap:6px}

  /* الماوس بيمرّ من غير ما يدوس، فالكعب بيرد على المرور */
  .tabbar a:hover{background:var(--card);color:var(--ink)}
}

@media (prefers-reduced-motion:reduce){
  *{animation-duration:.01ms !important;transition-duration:.01ms !important}
}
`;
