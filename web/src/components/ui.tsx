import { useState, type ComponentProps, type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'

const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ')

const buttonStyles = {
  base: 'inline-flex h-10 items-center justify-center gap-2 rounded-full px-5 text-sm font-medium tracking-tight transition-[background,color,transform,box-shadow] duration-200 ease-out-expo active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50',
  primary: 'bg-fg text-bg hover:bg-fg/85',
  ember: 'bg-ember text-ember-fg shadow-[0_0_0_1px_rgb(0_0_0/0.04),0_8px_24px_-8px_var(--ember)] hover:brightness-110',
  ghost: 'text-fg ring-1 ring-line-strong ring-inset hover:bg-sunken',
} as const

type Variant = Exclude<keyof typeof buttonStyles, 'base'>

export function Button({ variant = 'primary', className, ...p }: ComponentProps<'button'> & { variant?: Variant }) {
  return <button className={cx(buttonStyles.base, buttonStyles[variant], className)} {...p} />
}

export const buttonClass = (variant: Variant = 'primary', className?: string) => cx(buttonStyles.base, buttonStyles[variant], className)

export function ButtonLink({ variant = 'primary', className, ...p }: ComponentProps<typeof Link> & { variant?: Variant; className?: string }) {
  return <Link className={cx(buttonStyles.base, buttonStyles[variant], className)} {...p} />
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="font-mono text-xs tracking-[0.14em] text-faint uppercase">{children}</p>
}

export function CopyCommand({ command, className }: { command: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard.writeText(command).then(() => (setCopied(true), setTimeout(() => setCopied(false), 1400)))}
      className={cx(
        'group flex h-10 max-w-full items-center gap-3 rounded-full bg-sunken pr-2 pl-4 font-mono text-[13px] ring-1 ring-line ring-inset transition-colors hover:ring-line-strong',
        className,
      )}
      aria-label={`Copy command: ${command}`}
    >
      <span className="text-ember select-none">$</span>
      <span className="truncate text-muted group-hover:text-fg">{command}</span>
      <span className="ml-auto rounded-full bg-raised px-2.5 py-1 text-[11px] text-faint ring-1 ring-line" aria-live="polite">
        {copied ? 'Copied' : 'Copy'}
      </span>
    </button>
  )
}

const sev: Record<string, string> = {
  critical: 'text-crit bg-crit/10 ring-crit/25',
  high: 'text-ember bg-ember/10 ring-ember/25',
  medium: 'text-warn bg-warn/10 ring-warn/25',
}

export function Severity({ level }: { level: string }) {
  const k = level.toLowerCase()
  return (
    <span className={cx('inline-flex rounded-full px-2 py-0.5 font-mono text-[11px] uppercase ring-1 ring-inset', sev[k] ?? 'bg-sunken text-muted ring-line')}>
      {k}
    </span>
  )
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cx('inline-flex items-center gap-2 font-semibold tracking-tight', className)}>
      <svg viewBox="0 0 24 24" className="size-5" aria-hidden>
        <rect x="2" y="2" width="20" height="20" rx="6" className="fill-fg" />
        <path d="M8 15.5c1 .9 2.3 1.4 4 1.4 2 0 3.3-.9 3.3-2.3 0-3.2-7-1.6-7-5.2 0-1.4 1.3-2.4 3.4-2.4 1.4 0 2.6.4 3.5 1.1" className="fill-none stroke-bg" strokeWidth="1.9" strokeLinecap="round" />
        <circle cx="17.5" cy="6.5" r="1.6" className="fill-ember" />
      </svg>
      Sentris
    </span>
  )
}

export { cx }
