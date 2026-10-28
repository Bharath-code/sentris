import { createFileRoute } from '@tanstack/react-router'
import { useRef } from 'react'
import { Footer, Nav } from '@/components/chrome'
import { Terminal } from '@/components/Terminal'
import { ButtonLink, CopyCommand, Eyebrow } from '@/components/ui'
import { gsap, motionOK, SplitText, useGSAP } from '@/lib/motion'
import { site } from '@/lib/site'

export const Route = createFileRoute('/')({ component: Home })

function Home() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Benchmark />
        <Zones />
        <Surfaces />
        <Cloud />
        <Closer />
      </main>
      <Footer />
    </>
  )
}

function Hero() {
  const root = useRef<HTMLElement>(null)
  useGSAP(
    () => {
      if (!motionOK()) return
      const split = SplitText.create('[data-headline]', { type: 'words', mask: 'words' })
      gsap
        .timeline({ defaults: { ease: 'expo.out', duration: 1.1 } })
        .from(split.words, { yPercent: 110, stagger: 0.05 })
        .from('[data-rise]', { y: 16, autoAlpha: 0, stagger: 0.08, duration: 0.9 }, '-=0.8')
        .from('[data-term]', { y: 40, autoAlpha: 0, scale: 0.98, duration: 1.3 }, '-=0.7')
    },
    { scope: root },
  )

  return (
    <section ref={root} className="relative overflow-hidden">
      <div className="hairline-grid pointer-events-none absolute inset-0 -top-16" aria-hidden />
      <div className="container-page relative grid grid-cols-1 gap-14 pt-16 [&>*]:min-w-0 pb-24 sm:pt-24 lg:grid-cols-[1.1fr_1fr] lg:items-center lg:gap-12 lg:pt-28">
        <div>
          <p data-rise className="mb-6 inline-flex items-center gap-2 rounded-full bg-raised px-3 py-1 text-xs text-muted ring-1 ring-line">
            <span className="size-1.5 rounded-full bg-ember" /> Public beta · open-source CLI
          </p>
          <h1 data-headline className="text-display font-semibold">
            Leaked a key? It's fixed before you push.
          </h1>
          <p data-rise className="mt-6 max-w-[34rem] text-lg text-pretty text-muted">
            Other scanners stop at an alert. Sentris finds hardcoded secrets in milliseconds, moves them into your
            secret store and patches the code&nbsp;— in one command, with a byte-exact rollback if you change your mind.
          </p>
          <div data-rise className="mt-9 flex flex-col gap-3 sm:flex-row sm:items-center">
            <ButtonLink to="/login" variant="ember">Start 14-day Pro trial</ButtonLink>
            <CopyCommand command={site.install} className="sm:max-w-[22rem]" />
          </div>
        </div>
        <div data-term>
          <Terminal />
        </div>
      </div>
    </section>
  )
}

function Benchmark() {
  const root = useRef<HTMLElement>(null)
  const max = Math.max(...site.benchmark.map((b) => b.ms))
  useGSAP(
    () => {
      if (!motionOK()) return
      gsap.from('[data-bar]', {
        scaleX: 0,
        transformOrigin: 'left',
        duration: 1.2,
        ease: 'expo.out',
        stagger: 0.12,
        scrollTrigger: { trigger: root.current, start: 'top 75%' },
      })
    },
    { scope: root },
  )

  return (
    <section ref={root} className="border-y border-line bg-raised/40">
      <div className="container-page grid gap-12 py-20 md:grid-cols-[0.8fr_1.2fr] md:py-28">
        <div>
          <Eyebrow>5,000-file polyglot monorepo</Eyebrow>
          <h2 className="mt-4 text-title font-semibold">Fast enough that nobody types <span className="font-mono text-[0.8em]">--no-verify</span>.</h2>
          <p className="mt-5 text-muted">
            A pre-commit hook only works if it's invisible. Sentris scans staged hunks faster than a 60 Hz frame, using
            a work-stealing walker and a single-pass RegexSet DFA. One static 4 MB binary.
          </p>
        </div>
        <dl className="space-y-5 self-center">
          {site.benchmark.map((b, i) => (
            <div key={b.name} className="grid grid-cols-[6.5rem_1fr_4.5rem] items-center gap-4 text-sm">
              <dt className={i === 0 ? 'font-medium' : 'text-muted'}>{b.name}</dt>
              <div className="h-2.5 overflow-hidden rounded-full bg-sunken">
                <div data-bar className={`h-full rounded-full ${i === 0 ? 'bg-ember' : 'bg-line-strong'}`} style={{ width: `${Math.max(2, (b.ms / max) * 100)}%` }} />
              </div>
              <dd className={`text-right font-mono tabular-nums ${i === 0 ? '' : 'text-muted'}`}>{b.ms} ms</dd>
            </div>
          ))}
          <p className="pt-2 font-mono text-xs text-faint">Wall-clock, warm cache. Peak RAM: Sentris 14 MB vs TruffleHog 210 MB.</p>
        </dl>
      </div>
    </section>
  )
}

const zones = [
  {
    k: '01',
    title: 'Not committed yet',
    body: 'Rewrites the literal to process.env / os.environ / std::env across 7+ languages, writes the value to .env or your vault, hardens .gitignore and syncs .env.example.',
    code: 'sentris fix --all --backend vault',
  },
  {
    k: '02',
    title: 'Committed, not pushed',
    body: 'Produces a surgical fixup commit so the credential never reaches the remote. Your history stays clean and reviewable.',
    code: 'sentris scan --since origin/main..HEAD',
  },
  {
    k: '03',
    title: 'Already pushed',
    body: 'Never rewrites shared history behind your back. Opens a quarantine branch and hands you a purge playbook. Revoke the old key at your provider: automatic rotation is on the roadmap.',
    code: 'sentris quarantine <finding>',
  },
]

function Zones() {
  const root = useRef<HTMLElement>(null)
  useGSAP(
    () => {
      if (!motionOK()) return
      gsap.utils.toArray<HTMLElement>('[data-zone]').forEach((el) =>
        gsap.from(el, { y: 32, autoAlpha: 0, duration: 1, ease: 'expo.out', scrollTrigger: { trigger: el, start: 'top 85%' } }),
      )
    },
    { scope: root },
  )

  return (
    <section ref={root} id="how" className="container-page scroll-mt-20 py-24 md:py-32">
      <div className="max-w-2xl">
        <Eyebrow>How remediation works</Eyebrow>
        <h2 className="mt-4 text-title font-semibold">Finding the secret is 20% of the job. Sentris does the other 80%.</h2>
        <p className="mt-5 text-muted">The right fix depends on how far the secret has travelled, so Sentris picks a different strategy for each stage.</p>
      </div>
      <ol className="mt-16 grid gap-px overflow-hidden rounded-2xl bg-line ring-1 ring-line md:grid-cols-3">
        {zones.map((z) => (
          <li data-zone key={z.k} className="flex flex-col bg-bg p-7 sm:p-8">
            <span className="font-mono text-xs text-ember">{z.k}</span>
            <h3 className="mt-6 text-xl font-semibold tracking-tight">{z.title}</h3>
            <p className="mt-3 flex-1 text-[15px] leading-relaxed text-muted">{z.body}</p>
            <code className="mt-8 block truncate rounded-lg bg-sunken px-3 py-2 font-mono text-[12.5px] text-muted ring-1 ring-line">{z.code}</code>
          </li>
        ))}
      </ol>
      <p className="mt-6 text-sm text-faint">Backends: {site.backends.join(' · ')}. Every session is reversible with <span className="font-mono">sentris rollback</span>.</p>
    </section>
  )
}

const surfaces = [
  ['Pre-commit & pre-push', 'sentris install', 'Hooks that scan only staged hunks, plus a pre-push safety net.'],
  ['Your editor', 'sentris lsp', 'LSP 3.17 diagnostics and a one-click "extract to env" quick fix in VS Code, Cursor, Zed and Neovim.'],
  ['Your AI agent', 'sentris mcp', 'A local MCP server so Claude Code, Cursor and Windsurf fix leaked keys before finishing their turn.'],
  ['CI', 'sentris scan --format sarif', 'SARIF 2.1.0 output for GitHub code scanning and any CI runner.'],
] as const

function Surfaces() {
  return (
    <section className="border-t border-line">
      <div className="container-page py-24 md:py-32">
        <Eyebrow>Works where the leak happens</Eyebrow>
        <h2 className="mt-4 max-w-2xl text-title font-semibold">From keystroke to CI, one binary.</h2>
        <div className="mt-14 grid gap-x-10 gap-y-12 sm:grid-cols-2">
          {surfaces.map(([t, cmd, d]) => (
            <div key={t} className="border-t border-line pt-6">
              <div className="flex items-baseline justify-between gap-4">
                <h3 className="text-lg font-semibold tracking-tight">{t}</h3>
                <code className="font-mono text-xs text-faint">{cmd}</code>
              </div>
              <p className="mt-2 text-muted">{d}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function Cloud() {
  return (
    <section id="cloud" className="scroll-mt-20 bg-term text-zinc-100">
      <div className="container-page grid gap-14 py-24 md:grid-cols-2 md:items-center md:py-32">
        <div>
          <p className="font-mono text-xs tracking-[0.14em] text-zinc-500 uppercase">Sentris Pro Cloud</p>
          <h2 className="mt-4 text-title font-semibold">See one leaked key across fifty repos. Without seeing the key.</h2>
          <p className="mt-5 text-zinc-400">
            The CLI fingerprints every finding with a team secret that lives only on your developers' machines. The
            cloud receives keyed fingerprints it can match but never reverse or test guesses against, so it can tell you the same Stripe key lives in <span className="text-zinc-200">billing-svc</span> and{' '}
            <span className="text-zinc-200">checkout-web</span>. It never stores a single byte of source or secret.
          </p>
        </div>
        <div className="space-y-3 font-mono text-[12.5px]" aria-label="Data flow: raw secret stays local, only a salted fingerprint is sent">
          <FlowRow label="On your laptop" value='"sk_live_51AbcDef…"' tone="text-crit" />
          <p className="pl-4 text-zinc-600">↓ HMAC-SHA256(team secret)</p>
          <FlowRow label="Sent to cloud" value="zk_9f3c1a…e04b" tone="text-ok" />
          <p className="pl-4 text-zinc-600">↓ correlate</p>
          <FlowRow label="You see" value="2 repos · same credential" tone="text-ember" />
        </div>
      </div>
    </section>
  )
}

function FlowRow({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-xl bg-white/[0.03] px-4 py-3.5 ring-1 ring-white/[0.06]">
      <span className="text-zinc-500">{label}</span>
      <span className={tone}>{value}</span>
    </div>
  )
}

function Closer() {
  return (
    <section className="container-page py-28 text-center md:py-36">
      <h2 className="mx-auto max-w-3xl text-title font-semibold">The CLI is free forever. The fix-it-for-me part is ${site.priceMonthly} a developer.</h2>
      <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
        <ButtonLink to="/login" variant="ember">Start 14-day Pro trial</ButtonLink>
        <ButtonLink to="/pricing" variant="ghost">Compare plans</ButtonLink>
      </div>
    </section>
  )
}
