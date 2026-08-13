/**
 * نقطة الدخول — Cloudflare Pages Functions
 *
 * ══ إزاي Pages بتشتغل؟ ══
 * كلاودفلير بتبصّ على مجلد `functions` وبتحوّل كل ملف فيه لمسار.
 * الاسم `[[path]]` بالقوسين المزدوجين معناه: **امسك كل حاجة**.
 *
 * تشبيه: بدل ما تحطّ حارس على كل باب في المبنى، بتحطّ حارس واحد
 * على البوّابة الرئيسية وهو اللي بيوزّع الناس جوّه.
 *
 * ══ الفرق عن Worker ══
 * الـ Worker بيصدّر { fetch, scheduled }.
 * الـ Pages بتصدّر onRequest من ملف جوّه functions.
 * الاتنين بيشغّلوا نفس الكود بالظبط — الباب بس هو اللي مختلف.
 */

import { handle } from 'hono/cloudflare-pages';
import app from '../src/app';

export const onRequest = handle(app);
