import { useRef } from 'react'
import { gsap, motionOK, useGSAP } from '@/lib/motion'

// Condensed from the real `sentris remediate` output in README.md
const command = 'sentris remediate src/billing.ts --yes'
const steps: [string, string, 'ok' | 'warn' | 'muted'][] = [
  ['Verifying key with Stripe', 'LIVE · read_write', 'warn'],
  ['Atomic backup branch', 'sentris/backup-1793196000', 'muted'],
  ['Secured into .env backend', 'STRIPE_SECRET_KEY=***', 'ok'],
  ['Patched source', '1 file · 1 line', 'ok'],
  ['Old key: 24h grace deprecation', 'zero downtime', 'ok'],
  ['Rollback ledger', 'rm_27c44354', 'muted'],
]
const tone = { ok: 'text-ok', warn: 'text-warn', muted: 'text-zinc-500' }

export function Terminal() {
  const root = useRef<HTMLDivElement>(null)

  useGSAP(
    () => {
      if (!motionOK()) return
      const q = gsap.utils.selector(root)
      const cmd = q('[data-cmd]')[0] as HTMLElement
      const tl = gsap.timeline({ repeat: -1, repeatDelay: 3.5, defaults: { ease: 'power2.out' } })
      tl.set(q('[data-line]'), { autoAlpha: 0, y: 6 })
        .set(cmd, { textContent: '' })
        .to({}, { duration: 0.5 })
        .to({ n: 0 }, {
          n: command.length,
          duration: command.length * 0.035,
          ease: 'none',
          onUpdate() {
            cmd.textContent = command.slice(0, Math.round(this.targets()[0].n))
          },
        })
        .to(q('[data-line]'), { autoAlpha: 1, y: 0, duration: 0.35, stagger: 0.32 }, '+=0.35')
        .fromTo(q('[data-old]'), { opacity: 1 }, { opacity: 0.35, duration: 0.4 }, '<+=1.1')
    },
    { scope: root },
  )

  return (
    <div
      ref={root}
      className="relative overflow-hidden rounded-2xl bg-term font-mono text-[12.5px] leading-6 text-zinc-300 shadow-[0_0_0_1px_rgb(255_255_255/0.06),0_40px_80px_-24px_rgb(0_0_0/0.5)] sm:text-[13px]"
      role="img"
      aria-label="Terminal: sentris remediate moves a live Stripe key into .env and patches the source in one command"
    >
      <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
        <span className="size-2.5 rounded-full bg-white/10" />
        <span className="size-2.5 rounded-full bg-white/10" />
        <span className="size-2.5 rounded-full bg-white/10" />
        <span className="ml-3 text-[11px] text-zinc-500">~/acme/billing-svc</span>
      </div>
      <div className="space-y-0.5 p-5 sm:p-6" aria-hidden>
        <p>
          <span className="text-ember">❯</span> <span data-cmd className="text-zinc-100">{command}</span>
          <span className="ml-0.5 inline-block h-4 w-[7px] translate-y-[3px] animate-pulse bg-zinc-400" />
        </p>
        <p data-line className="pt-2 text-zinc-500">
          <span className="text-crit">●</span> stripe-secret-key <span className="text-zinc-400">src/billing.ts:6</span> critical
        </p>
        {steps.map(([label, value, t], i) => (
          <p data-line key={label} className="flex gap-3">
            <span className="text-zinc-600">[{i + 1}/{steps.length}]</span>
            <span className="truncate">{label}</span>
            <span className={`ml-auto shrink-0 ${tone[t]}`}>{value}</span>
          </p>
        ))}
        <div data-line className="my-2 rounded-lg bg-white/[0.03] px-3 py-2 ring-1 ring-white/[0.05]">
          <p data-old className="truncate text-crit/90">- const key = "sk_live_51AbcDefGhIjKl…"</p>
          <p className="truncate text-ok">+ const key = process.env.STRIPE_SECRET_KEY</p>
        </div>
        <p data-line className="text-ok">
          ✓ Fixed in 0.8s <span className="text-zinc-500">· app keeps running</span>
        </p>
      </div>
    </div>
  )
}
