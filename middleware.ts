import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

/**
 * التقاط النطاق الفرعي وتوجيه الطلب.
 *
 * shop.mobishop.app/pos   →  /s/shop/pos      (مساحة عمل المحل)
 * mobishop.app/pricing    →  /(marketing)/pricing
 * pos.metro-mobile.com    →  /s/metro-mobile  (نطاق مخصص)
 *
 * قرار مقصود: لا يوجد أي استعلام لقاعدة البيانات هنا.
 * الـ Middleware يعمل على الحافة قبل كل طلب — استعلام واحد فيه يعني
 * إضافة 40-80ms إلى *كل* صورة وصفحة. التحقق من وجود المحل فعلاً
 * يحدث مرة واحدة في app/s/[tenant]/layout.tsx مع تخزين مؤقت.
 * هنا نتحقق من الشكل فقط، والتوجيه إلى محل غير موجود ينتهي بـ 404.
 */

const ROOT_DOMAIN = process.env.NEXT_PUBLIC_ROOT_DOMAIN ?? 'localhost:3000'

/** نطاقات فرعية مملوكة للمنصّة — لا يجوز أن تكون محلاً */
const RESERVED = new Set([
  'www', 'app', 'api', 'admin', 'auth', 'login', 'signup', 'billing',
  'status', 'docs', 'help', 'blog', 'cdn', 'static', 'assets', 'mail',
  'support', 'dashboard', 'account', 'portal', 'system', 'demo',
])

/** مسارات مساحة العمل المتاحة بدون تسجيل دخول */
const PUBLIC_TENANT_PATHS = ['/login', '/reset-password', '/accept-invite', '/suspended']

const SLUG_RE = /^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$/

type Tenant =
  | { kind: 'subdomain'; slug: string }
  | { kind: 'custom'; host: string }
  | null

function getHost(req: NextRequest): string {
  const raw =
    req.headers.get('x-forwarded-host') ??
    req.headers.get('host') ??
    ''
  return raw.toLowerCase().split(':')[0]
}

function resolveTenant(host: string): Tenant {
  const root = ROOT_DOMAIN.split(':')[0]

  // معاينات Vercel ونطاق المنصّة نفسه → الموقع التسويقي
  if (host === root || host === `www.${root}` || host.endsWith('.vercel.app')) {
    return null
  }

  // النطاق الفرعي: shop.mobishop.app — وفي التطوير shop.localhost
  if (host.endsWith(`.${root}`)) {
    const slug = host.slice(0, -(root.length + 1))
    // نتجاهل النطاقات المتداخلة مثل a.b.mobishop.app
    if (slug.includes('.')) return null
    if (RESERVED.has(slug) || !SLUG_RE.test(slug)) return null
    return { kind: 'subdomain', slug }
  }

  // أي شيء آخر: نطاق مخصص اشتراه صاحب المحل
  return { kind: 'custom', host }
}

export async function middleware(req: NextRequest) {
  const host = getHost(req)
  const tenant = resolveTenant(host)
  const { pathname, search } = req.nextUrl

  // مسارات مساحة العمل الداخلية لا تُفتح مباشرة من النطاق الرئيسي
  if (!tenant && pathname.startsWith('/s/')) {
    return NextResponse.rewrite(new URL('/404', req.url))
  }

  // ── تحديث جلسة Supabase ───────────────────────────────────────────────
  // نجمع الكوكيز أولاً ثم نضعها على الاستجابة النهائية أياً كانت
  // (تمرير أو إعادة كتابة أو تحويل) — وإلا ضاع تجديد التوكن.
  const cookiesToSet: { name: string; value: string; options: any }[] = []

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => req.cookies.getAll(),
        setAll: (all) => {
          all.forEach((c) => {
            req.cookies.set(c.name, c.value)
            cookiesToSet.push(c)
          })
        },
      },
    },
  )

  const {
    data: { user },
  } = await supabase.auth.getUser()

  // ── الموقع التسويقي ───────────────────────────────────────────────────
  if (!tenant) {
    return finalize(NextResponse.next({ request: req }), cookiesToSet)
  }

  // ── مساحة عمل المحل ───────────────────────────────────────────────────
  const key = tenant.kind === 'subdomain' ? tenant.slug : tenant.host
  const isPublicPath = PUBLIC_TENANT_PATHS.some((p) => pathname.startsWith(p))

  if (!user && !isPublicPath) {
    const login = req.nextUrl.clone()
    login.pathname = '/login'
    login.search = `?next=${encodeURIComponent(pathname + search)}`
    return finalize(NextResponse.redirect(login), cookiesToSet)
  }

  if (user && pathname === '/login') {
    const home = req.nextUrl.clone()
    home.pathname = '/'
    home.search = ''
    return finalize(NextResponse.redirect(home), cookiesToSet)
  }

  const url = req.nextUrl.clone()
  url.pathname = `/s/${key}${pathname === '/' ? '' : pathname}`

  const headers = new Headers(req.headers)
  headers.set('x-tenant-key', key)
  headers.set('x-tenant-kind', tenant.kind)
  headers.set('x-tenant-host', host)
  // ننظّف أي محاولة من العميل لحقن هوية محل يدوياً
  headers.delete('x-tenant-id')

  return finalize(
    NextResponse.rewrite(url, { request: { headers } }),
    cookiesToSet,
  )
}

function finalize(
  res: NextResponse,
  cookies: { name: string; value: string; options: any }[],
) {
  cookies.forEach((c) => res.cookies.set(c.name, c.value, c.options))
  return res
}

export const config = {
  matcher: [
    /**
     * كل شيء ما عدا الملفات الثابتة.
     * الاستثناءات هنا هي أكبر مكسب أداء في المشروع كله —
     * كل مسار غير مستثنى يمر بـ getUser() ويكلّف رحلة شبكة.
     */
    '/((?!_next/static|_next/image|favicon.ico|manifest.webmanifest|sw.js|.*\\.(?:svg|png|jpg|jpeg|gif|webp|avif|ico|woff|woff2|ttf)$).*)',
  ],
}
