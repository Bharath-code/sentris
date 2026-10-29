import { createFileRoute, Link, useRouter } from '@tanstack/react-router'
import { useState, type FormEvent, type ReactNode } from 'react'
import { z } from 'zod'
import { Button, CopyCommand, Severity, cx } from '@/components/ui'
import { Panel, Table } from '@/components/panel'
import { createKey, getOverview, openPortal, revokeKey, startCheckout } from '@/lib/api'
import { loginCommand, site } from '@/lib/site'

export const Route = createFileRoute('/app/')({
  validateSearch: z.object({ seats: z.number().int().min(1).max(500).optional(), checkout: z.string().optional() }),
  loader: () => getOverview(),
  component: Dashboard,
})

type Data = Awaited<ReturnType<typeof getOverview>>
const ago = (d: Date | string) => {
  const s = (Date.now() - new Date(d).getTime()) / 1000
  return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`
}

function Dashboard() {
  const d = Route.useLoaderData()
  const { checkout } = Route.useSearch()
  const empty = d.scans.length === 0

  return (
    <main className="container-page space-y-10 py-10">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{d.org.name}</h1>
          <p className="mt-1 text-sm text-muted">Last 30 days · zero-knowledge fingerprints only</p>
        </div>
        <PlanBadge org={d.org} />
      </div>

      {checkout && d.org.plan !== 'pro' && (
        <p className="rounded-xl bg-sunken px-4 py-3 text-sm text-muted ring-1 ring-line">Payment received. Your plan updates as soon as Dodo confirms it, usually within a few seconds. Refresh to check.</p>
      )}

      {d.org.plan !== 'pro' && <Upgrade />}

      {empty ? <Onboarding d={d} /> : <Stats d={d} />}

      {d.radius.length > 0 && (
        <Panel title="Blast radius" hint="Same credential fingerprint found in more than one repository">
          <Table head={['Fingerprint', 'Rule', 'Severity', 'Repositories']}>
            {d.radius.map((r) => (
              <tr key={r.zk_fingerprint}>
                <td className="font-mono text-xs text-muted">{r.zk_fingerprint.slice(0, 18)}…</td>
                <td>{r.rule_id}</td>
                <td><Severity level={r.severity} /></td>
                <td className="text-muted">{r.affected_repos.join(', ')}</td>
              </tr>
            ))}
          </Table>
        </Panel>
      )}

      {!empty && (
        <Panel title="Recent scans">
          <Table head={['Repository', 'Branch', 'Files', 'Duration', 'Findings', '']}>
            {d.scans.map((s) => (
              <tr key={s.id} className="group">
                <td className="font-medium">
                  <Link to="/app/scans/$id" params={{ id: s.id }} className="after:absolute after:inset-0">{s.repo}</Link>
                </td>
                <td className="font-mono text-xs text-muted">{s.branch}</td>
                <td className="tabular-nums text-muted">{s.filesScanned.toLocaleString()}</td>
                <td className="tabular-nums text-muted">{s.durationMs} ms</td>
                <td className={cx('tabular-nums', s.findingsCount ? 'text-crit' : 'text-ok')}>{s.findingsCount || 'clean'}</td>
                <td className="text-right text-xs text-faint">{ago(s.createdAt)}</td>
              </tr>
            ))}
          </Table>
        </Panel>
      )}

      <Keys d={d} />
    </main>
  )
}

function PlanBadge({ org }: { org: Data['org'] }) {
  const [busy, setBusy] = useState(false)
  const manage = async () => {
    setBusy(true)
    try {
      window.location.href = (await openPortal()).url
    } catch {
      setBusy(false)
    }
  }
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className={cx('rounded-full px-2.5 py-1 font-mono text-xs ring-1', org.plan === 'pro' ? 'bg-ember/10 text-ember ring-ember/25' : 'bg-sunken text-muted ring-line')}>
        {org.plan === 'pro' ? `Pro · ${org.seats} seat${org.seats > 1 ? 's' : ''}` : 'Free'}
      </span>
      {org.hasBilling && (
        <button onClick={manage} disabled={busy} className="text-muted hover:text-fg disabled:opacity-50">Manage billing</button>
      )}
    </div>
  )
}

function Upgrade() {
  const { seats: initial } = Route.useSearch()
  const [seats, setSeats] = useState(initial ?? 1)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const go = async () => {
    setBusy(true)
    setError(null)
    try {
      window.location.href = (await startCheckout({ data: { seats } })).url
    } catch {
      setError('Could not open checkout. Try again in a moment.')
      setBusy(false)
    }
  }
  return (
    <section className="flex flex-col gap-5 rounded-2xl bg-raised p-6 ring-1 ring-line md:flex-row md:items-center">
      <div className="flex-1">
        <h2 className="font-semibold">Let Sentris fix leaks, not just find them</h2>
        <p className="mt-1 text-sm text-muted">Pro unlocks vault backends, API key rotation and cross-repo blast radius. 14 days free, then ${site.priceMonthly}/developer.</p>
        {error && <p role="alert" className="mt-2 text-sm text-crit">{error}</p>}
      </div>
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-muted">
          Seats
          <input type="number" min={1} max={500} value={seats} onChange={(e) => setSeats(Math.min(500, Math.max(1, Number(e.target.value) || 1)))}
            className="h-10 w-16 rounded-lg bg-sunken px-2 text-right font-mono tabular-nums text-fg ring-1 ring-line outline-none focus:ring-ember" />
        </label>
        <Button variant="ember" onClick={go} disabled={busy}>{busy ? 'Opening…' : 'Start trial'}</Button>
      </div>
    </section>
  )
}

function Stats({ d }: { d: Data }) {
  const crit = d.bySeverity.find((s) => s.severity.toLowerCase() === 'critical')?.n ?? 0
  const items = [
    ['Scans', d.totals.scans],
    ['Files scanned', d.totals.files],
    ['Findings', d.totals.findings],
    ['Critical', crit],
  ] as const
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-line ring-1 ring-line md:grid-cols-4">
      {items.map(([k, v]) => (
        <div key={k} className="bg-bg p-5">
          <dt className="text-xs text-faint">{k}</dt>
          <dd className={cx('mt-2 text-3xl font-semibold tracking-tight tabular-nums', k === 'Critical' && v > 0 && 'text-crit')}>{Number(v).toLocaleString()}</dd>
        </div>
      ))}
    </dl>
  )
}

function Onboarding({ d }: { d: Data }) {
  const hasKey = d.keys.length > 0
  return (
    <Panel title="Connect your first repository" hint="Three steps, about a minute.">
      <ol className="divide-y divide-line">
        <Step n={1} done title="Install the CLI"><CopyCommand command={site.install} /></Step>
        <Step n={2} done={hasKey} title="Create an API key"><p className="text-sm text-muted">{hasKey ? 'Done. Keys are listed below.' : 'Use the form at the bottom of this page. The key is shown once.'}</p></Step>
        <Step n={3} title="Log in and sync">
          <div className="space-y-2">
            <CopyCommand command={loginCommand(d.serverUrl)} />
            <CopyCommand command="sentris sync ." />
            <p className="text-xs text-faint">Login prints a team secret. Share it privately; teammates add <span className="font-mono">--team-secret &lt;secret&gt;</span>.</p>
          </div>
        </Step>
      </ol>
    </Panel>
  )
}

function Step({ n, title, done, children }: { n: number; title: string; done?: boolean; children: ReactNode }) {
  return (
    <li className="grid gap-3 py-5 first:pt-0 last:pb-0 sm:grid-cols-[14rem_1fr] sm:items-center">
      <p className="flex items-center gap-3 text-sm font-medium">
        <span className={cx('grid size-6 place-items-center rounded-full font-mono text-[11px] ring-1', done ? 'bg-ok/10 text-ok ring-ok/30' : 'text-muted ring-line-strong')}>{done ? '✓' : n}</span>
        {title}
      </p>
      <div className="min-w-0">{children}</div>
    </li>
  )
}

function Keys({ d }: { d: Data }) {
  const router = useRouter()
  const [name, setName] = useState('')
  const [fresh, setFresh] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const create = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const { key } = await createKey({ data: { name: name || 'My laptop' } })
      setFresh(key)
      setName('')
      await router.invalidate()
    } finally {
      setBusy(false)
    }
  }
  const revoke = async (id: string) => {
    if (!confirm('Revoke this key? Any CLI using it stops syncing immediately.')) return
    await revokeKey({ data: { id } })
    await router.invalidate()
  }

  return (
    <Panel title="CLI API keys" hint="Your first login prints a team secret. Teammates join with --team-secret so fingerprints match across machines. Sentris never sees it.">
      {fresh && (
        <div className="mb-5 space-y-2 rounded-xl bg-ok/5 p-4 ring-1 ring-ok/20">
          <p className="text-sm font-medium">Copy this now. It won't be shown again.</p>
          <CopyCommand command={loginCommand(d.serverUrl, fresh)} />
        </div>
      )}
      {d.keys.length > 0 && (
        <Table head={['Name', 'Key', 'Last used', '']}>
          {d.keys.map((k) => (
            <tr key={k.id}>
              <td className="font-medium">{k.name}</td>
              <td className="font-mono text-xs text-muted">{k.preview}</td>
              <td className="text-muted">{k.lastUsedAt ? ago(k.lastUsedAt) : 'never'}</td>
              <td className="text-right"><button onClick={() => revoke(k.id)} className="text-sm text-muted hover:text-crit">Revoke</button></td>
            </tr>
          ))}
        </Table>
      )}
      <form onSubmit={create} className="mt-5 flex gap-2">
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Key name, e.g. CI or Priya's laptop" aria-label="Key name"
          className="h-10 min-w-0 flex-1 rounded-full bg-sunken px-4 text-sm ring-1 ring-line outline-none placeholder:text-faint focus:ring-ember" />
        <Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create key'}</Button>
      </form>
    </Panel>
  )
}
