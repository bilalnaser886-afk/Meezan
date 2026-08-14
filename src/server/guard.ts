/**
 * حارس الصلاحيات (RBAC Guard)
 *
 * تشبيه: موظّف الاستقبال. مش عارف حاجة عن التمارين، وظيفته الوحيدة:
 * افحص البطاقة ← افحص إن حزامك يسمح بدخول القاعة دي ← افتح أو امنع.
 *
 * ══ ليه الحراسة هنا مش في الواجهة؟ ══
 * إخفاء زرار من الشاشة مش بيحمي حاجة — أي حد يقدر ينادي الـ API
 * على طول من المتصفح. تشبيه: بتخبّي الميدالية تحت ترابيزة من إزاز.
 * **الحراسة الحقيقية دايماً عند البيانات، مش عند الشاشة.**
 */

import type { Context, MiddlewareHandler } from 'hono';
import { getCookie } from 'hono/cookie';
import { COOKIES, type Env } from '../domain/config';
import { AppError, Errors } from '../domain/errors';
import type { PermissionKey } from '../domain/permissions';
import type { AuthenticatedUser } from '../application/ports';
import { verifyAccessToken } from '../infrastructure/crypto';
import { checkSession } from '../application/use-cases/auth';
import { buildContainer } from './runtime';

export interface AppBindings {
  Bindings: Env;
  Variables: {
    user: AuthenticatedUser;
    sessionId: string;
  };
}

export interface GuardOptions {
  /** كل الصلاحيات دي مطلوبة */
  requireAll?: PermissionKey[];
  /** واحدة على الأقل من دول تكفي */
  requireAny?: PermissionKey[];
  /**
   * هل نحدّث ختم النشاط؟ الافتراضي true.
   * خلّيها false في المسارات اللي بتتنادى تلقائياً في الخلفية،
   * وإلا هيفضل الموظف "نشط" وهو سايب الكاشير ورايح.
   */
  touchActivity?: boolean;
  /** إعادة توجيه لصفحة الدخول بدل رد JSON (للصفحات مش الـ API) */
  redirectOnFail?: boolean;
}

export function requireAuth(options: GuardOptions = {}): MiddlewareHandler<AppBindings> {
  return async (c, next) => {
    try {
      // 1) معاك بطاقة أصلاً؟
      const token = getCookie(c, COOKIES.ACCESS);
      if (!token) throw Errors.unauthenticated();

      // 2) الختم سليم ومش منتهي؟ (فحص سريع من غير قاعدة بيانات)
      const payload = await verifyAccessToken(token, c.env.JWT_SECRET);

      // 3) الجلسة نفسها لسه حيّة في الخادم؟
      //    البطاقة ممكن تكون سليمة والجلسة ملغية (موظف اتفصل،
      //    أو عدّى 10 دقايق خمول). عشان كده مش بنكتفي بفحص الـ JWT.
      const container = buildContainer(c.env);
      const user = await checkSession(
        container.auth,
        payload.sid,
        payload.sub,
        options.touchActivity ?? true,
      );

      // 4) حزامك يسمح؟
      assertPermissions(user, options);

      c.set('user', user);
      c.set('sessionId', payload.sid);

      await next();
    } catch (error) {
      if (options.redirectOnFail) {
        // القفل غير الانتهاء: الجلسة لسه حيّة، فبنوجّه لشاشة فك
        // القفل مش لصفحة الدخول — وبنسيب الكوكيز زي ما هي.
        if (error instanceof AppError && error.code === 'SESSION_LOCKED') {
          return c.redirect('/locked');
        }
        return c.redirect('/login?expired=1');
      }
      throw error; // بيمسكه app.onError ويحوّله لرد JSON موحّد
    }
  };
}

function assertPermissions(user: AuthenticatedUser, options: GuardOptions): void {
  const owned = new Set<string>(user.permissions);

  if (options.requireAll?.length) {
    const missing = options.requireAll.find((p) => !owned.has(p));
    if (missing) throw Errors.forbidden(missing);
  }

  if (options.requireAny?.length) {
    if (!options.requireAny.some((p) => owned.has(p))) {
      throw Errors.forbidden(options.requireAny.join(' | '));
    }
  }
}

/**
 * حارس نطاق الفرع.
 * المالك بيشوف كل الفروع. غيره محبوس في فرعه.
 *
 * استعملها في كل استعلام بيخصّ بيانات فرع. نسيانها مرة واحدة
 * معناها إن مدير فرع الرياض بيقرأ مبيعات فرع جدة.
 */
export function assertBranchScope(user: AuthenticatedUser, targetBranchId: string | null): void {
  if (user.roleKey === 'SUPER_ADMIN') return;
  if (!targetBranchId || targetBranchId !== user.branchId) throw Errors.forbidden('branch scope');
}

/** فلتر جاهز يتضاف لأي استعلام عشان يحصر النتائج في فرع المستخدم */
export function branchFilter(user: AuthenticatedUser): string | null {
  return user.roleKey === 'SUPER_ADMIN' ? null : (user.branchId ?? '__none__');
}

/** قراءة المستخدم الحالي داخل أي معالج محمي */
export function currentUser(c: Context<AppBindings>): AuthenticatedUser {
  return c.get('user');
}
