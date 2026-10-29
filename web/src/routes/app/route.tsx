import { createFileRoute, Link, Outlet, redirect, useRouter } from '@tanstack/react-router'
import { ThemeToggle } from '@/components/chrome'
import { Logo } from '@/components/ui'
import { getViewer } from '@/lib/api'
import { authClient } from '@/lib/auth-client'

export const Route = createFileRoute('/app')({
  beforeLoad: async () => {
    const viewer = await getViewer()
    if (!viewer) throw redirect({ to: '/login' })
    return { viewer }
  },
  head: () => ({ meta: [{ title: 'Dashboard — Sentris' }, { name: 'robots', content: 'noindex' }] }),
  component: AppShell,
})

function AppShell() {
  const { viewer } = Route.useRouteContext()
  const router = useRouter()
  const signOut = async () => {
    await authClient.signOut()
    await router.navigate({ to: '/' })
  }

  return (
    <div className="min-h-dvh">
      <header className="border-b border-line">
        <div className="container-page flex h-14 items-center gap-6">
          <Link to="/app" aria-label="Dashboard">
            <Logo />
          </Link>
          <span className="hidden rounded-full bg-sunken px-2 py-0.5 font-mono text-[11px] text-faint ring-1 ring-line sm:inline">beta</span>
          <div className="ml-auto flex items-center gap-2 text-sm">
            <ThemeToggle />
            {viewer.image && <img src={viewer.image} alt="" className="size-7 rounded-full ring-1 ring-line" />}
            <button onClick={signOut} className="px-2 text-muted hover:text-fg">Sign out</button>
          </div>
        </div>
      </header>
      <Outlet />
    </div>
  )
}
