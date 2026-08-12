import 'server-only'
import { cache } from 'react'
import { headers } from 'next/headers'
import { unstable_cache } from 'next/cache'
import { notFound, redirect } from 'next/navigation'
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export type Tenant = {
  id: string
  slug: string
  name: string
  logo_url: string | null
  status: 'trialing' | 'active' | 'suspended' | 'canceled'
  locale: string
}

/**
 * تحويل النطاق إلى محل.
 *
 * طبقتا تخزين مؤقت:
 *   unstable_cache → مشترك بين كل الطلبات والمستخدمين، عمره ساعة (بيانات المحل نادرة التغيّر)
 *   cache()        → داخل الطلب الواحد، حتى لا يتكرر البحث بين layout وpage وأي مكوّن
 *
 * النتيجة: صفحة فيها 12 مكوّناً تحتاج tenant.id تُنفّذ استعلاماً واحداً كل ساعة، لا 12 لكل طلب.
 */
const lookup = unstable_cache(
  async (key: string): Promise<Tenant | null> => {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      { cookies: { getAll: () => [], setAll: () => {} } },
    )
    const { data } = await supabase.rpc('resolve_tenant', { p_host: key }).maybeSingle()
    return (data as Tenant) ?? null
  },
  ['tenant-by-host'],
  { revalidate: 3600, tags: ['tenants'] },
)

export const getTenant = cache(async (): Promise<Tenant> => {
  const key = (await headers()).get('x-tenant-key')
  if (!key) notFound()

  const tenant = await lookup(key)
  if (!tenant) notFound()
  if (tenant.status === 'suspended') redirect('/suspended')

  return tenant
})

/**
 * عميل Supabase مربوط بالمحل الحالي.
 *
 * ترويسة x-tenant-id هي نصف مفتاح العزل: تخبر RLS أي محل نقصد.
 * النصف الآخر — هل يملك هذا المستخدم هذا المحل — يقرره الـ JWT وحده،
 * لذا لا ضرر إن تسرّبت هذه الترويسة أو حاول أحد تغييرها.
 */
export async function getScopedClient() {
  const [tenant, cookieStore] = await Promise.all([getTenant(), cookies()])

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      global: { headers: { 'x-tenant-id': tenant.id } },
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (all) => {
          try {
            all.forEach((c) => cookieStore.set(c.name, c.value, c.options))
          } catch {
            // الاستدعاء من Server Component — التجديد يتكفّل به الـ middleware
          }
        },
      },
    },
  )
}

/** الدور والصلاحيات داخل المحل الحالي */
export const getMembership = cache(async () => {
  const supabase = await getScopedClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) redirect('/login')

  const { data } = await supabase
    .from('memberships')
    .select('role, branch_id, permissions')
    .eq('user_id', user.id)
    .single()

  if (!data) notFound()
  return { user, ...data }
})

/** حالة الاشتراك — يستهلكها شريط التنبيه أعلى لوحة التحكم */
export const getSubscription = cache(async () => {
  const supabase = await getScopedClient()
  const { data } = await supabase.rpc('subscription_state').maybeSingle()
  return data as {
    status: string
    plan_code: string
    days_left: number
    can_write: boolean
    trial_ends_at: string
  } | null
})

/** بناء رابط لمحل معيّن — يستعمله مبدّل المحلات */
export function tenantUrl(slug: string, path = '/') {
  const root = process.env.NEXT_PUBLIC_ROOT_DOMAIN ?? 'localhost:3000'
  const proto = root.startsWith('localhost') ? 'http' : 'https'
  return `${proto}://${slug}.${root}${path}`
}
