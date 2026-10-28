import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { Footer, Nav } from '@/components/chrome'
import { buttonClass, CopyCommand, Eyebrow, cx } from '@/components/ui'
import { site } from '@/lib/site'

export const Route = createFileRoute('/pricing')({
  head: () => ({ meta: [{ title: 'Pricing — Sentris' }] }),
  component: Pricing,
})

const tick = (s: string) => (
  <li key={s} className="flex gap-3">
    <svg viewBox="0 0 16 16" className="mt-1 size-3.5 shrink-0 text-ember" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path d="m3 8.5 3 3 7-7" />
    </svg>
    {s}
  </li>
)

function Pricing() {
  const [seats, setSeats] = useState(5)
  const per = site.priceMonthly
  return (
    <>
      <Nav />
      <main className="container-page py-20 md:py-28">
        <div className="max-w-2xl">
          <Eyebrow>Pricing</Eyebrow>
          <h1 className="mt-4 text-title font-semibold">Detection is free. Pay when Sentris does the fixing.</h1>
          <p className="mt-5 text-muted">No sales call, no seat minimums. Prices in USD; Dodo Payments handles tax, cards and UPI worldwide.</p>
        </div>

        <div className="mt-14 grid gap-4 lg:grid-cols-3">
          <Plan name="CLI" price="$0" unit="forever, MIT">
            <CopyCommand command={site.install} className="w-full" />
            <ul className="mt-6 space-y-2.5 text-sm text-muted">
              {['57+ detectors, ~18 ms scans', 'Pre-commit & pre-push hooks', 'LSP + MCP servers', 'SARIF, JSON, TUI', 'Local remediation to .env'].map(tick)}
            </ul>
          </Plan>

          <Plan name="Pro" price={`$${per}`} unit="per developer / month" featured>
            <Link to="/login" search={{ seats }} className={buttonClass('ember', 'w-full')}>Start 14-day trial</Link>
            <label className="mt-5 flex items-center justify-between gap-3 text-sm">
              <span className="text-muted">Developers</span>
              <input
                type="number"
                min={1}
                max={500}
                value={seats}
                onChange={(e) => setSeats(Math.min(500, Math.max(1, Number(e.target.value) || 1)))}
                className="h-9 w-20 rounded-lg bg-sunken px-3 text-right font-mono tabular-nums ring-1 ring-line outline-none focus:ring-ember"
              />
            </label>
            <p className="mt-2 text-right font-mono text-sm text-muted tabular-nums">${seats * per}/mo</p>
            <ul className="mt-5 space-y-2.5 text-sm text-muted">
              {['Everything in CLI', 'Vault, AWS, Doppler, 1Password, Infisical backends', 'Provider-API key rotation with dual-key grace', 'Zero-knowledge cloud dashboard', 'Cross-repo blast radius'].map(tick)}
            </ul>
          </Plan>

          <Plan name="Self-hosted" price={`$${site.enterpriseYear.toLocaleString()}`} unit="per year, up to 50 devs">
            <a href={site.contact} className="inline-flex h-10 w-full items-center justify-center rounded-full text-sm font-medium ring-1 ring-line-strong ring-inset hover:bg-sunken">
              Talk to the founder
            </a>
            <ul className="mt-6 space-y-2.5 text-sm text-muted">
              {['Everything in Pro', 'Air-gapped Docker / Kubernetes', 'SAML SSO', 'Vanta SOC 2 evidence export'].map(tick)}
            </ul>
          </Plan>
        </div>
      </main>
      <Footer />
    </>
  )
}

function Plan({ name, price, unit, featured, children }: { name: string; price: string; unit: string; featured?: boolean; children: React.ReactNode }) {
  return (
    <section className={cx('flex flex-col rounded-2xl p-7 ring-1', featured ? 'bg-raised ring-line-strong shadow-[0_30px_60px_-30px_rgb(0_0_0/0.35)]' : 'ring-line')}>
      <h2 className="flex items-center gap-2 font-medium">
        {name}
        {featured && <span className="rounded-full bg-ember/10 px-2 py-0.5 text-[11px] text-ember">Beta pricing</span>}
      </h2>
      <p className="mt-6 flex items-baseline gap-2">
        <span className="text-5xl font-semibold tracking-tight">{price}</span>
        <span className="text-sm text-faint">{unit}</span>
      </p>
      <div className="mt-7">{children}</div>
    </section>
  )
}
