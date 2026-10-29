import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import { useState } from 'react'
import { z } from 'zod'
import { Button, Logo } from '@/components/ui'
import { authClient } from '@/lib/auth-client'
import { getViewer } from '@/lib/api'

export const Route = createFileRoute('/login')({
  validateSearch: z.object({ seats: z.number().int().min(1).max(500).optional() }),
  beforeLoad: async ({ search }) => {
    if (await getViewer()) throw redirect({ to: '/app', search })
  },
  head: () => ({ meta: [{ title: 'Sign in — Sentris' }] }),
  component: Login,
})

function Login() {
  const { seats } = Route.useSearch()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const signIn = async () => {
    setPending(true)
    setError(null)
    const { error } = await authClient.signIn.social({
      provider: 'github',
      callbackURL: seats ? `/app?seats=${seats}` : '/app',
    })
    if (error) {
      setError(error.message ?? 'Sign-in failed. Try again.')
      setPending(false)
    }
  }

  return (
    <main className="grid min-h-dvh place-items-center px-5">
      <div className="hairline-grid pointer-events-none fixed inset-0" aria-hidden />
      <div className="relative w-full max-w-sm rounded-2xl bg-raised p-8 ring-1 ring-line shadow-[0_40px_80px_-40px_rgb(0_0_0/0.45)]">
        <Link to="/" aria-label="Sentris home">
          <Logo />
        </Link>
        <h1 className="mt-8 text-2xl font-semibold tracking-tight">Sign in to Sentris Cloud</h1>
        <p className="mt-2 text-sm text-muted">
          {seats ? `Next: start your 14-day trial for ${seats} developer${seats > 1 ? 's' : ''}.` : 'Your team dashboard and CLI keys live here.'}
        </p>
        <Button onClick={signIn} disabled={pending} className="mt-8 w-full">
          <svg viewBox="0 0 16 16" className="size-4" fill="currentColor" aria-hidden>
            <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.06-.49.06-.49.8.06 1.23.83 1.23.83.72 1.22 1.88.87 2.34.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8" />
          </svg>
          {pending ? 'Redirecting…' : 'Continue with GitHub'}
        </Button>
        {error && <p role="alert" className="mt-4 text-sm text-crit">{error}</p>}
        <p className="mt-8 text-xs text-faint">We only read your name and email. Sentris Cloud never receives source code or secrets.</p>
      </div>
    </main>
  )
}
