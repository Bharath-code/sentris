import { Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { site } from '@/lib/site'
import { ButtonLink, Logo, cx } from './ui'

export function Nav() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8)
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [])

  return (
    <header
      className={cx(
        'sticky top-0 z-50 transition-[background,box-shadow] duration-300',
        scrolled && 'bg-bg/75 shadow-[0_1px_0_var(--line)] backdrop-blur-xl backdrop-saturate-150',
      )}
    >
      <nav className="container-page flex h-16 items-center gap-8">
        <Link to="/" aria-label="Sentris home">
          <Logo />
        </Link>
        <div className="hidden items-center gap-6 text-sm text-muted md:flex">
          <a href="/#how" className="hover:text-fg">How it works</a>
          <a href="/#cloud" className="hover:text-fg">Cloud</a>
          <Link to="/pricing" className="hover:text-fg" activeProps={{ className: 'text-fg' }}>Pricing</Link>
          <a href={site.github} className="hover:text-fg">GitHub</a>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <ThemeToggle />
          <Link to="/login" className="hidden px-3 text-sm text-muted hover:text-fg sm:block">Sign in</Link>
          <ButtonLink to="/login" variant="primary" className="h-9 px-4">Start free trial</ButtonLink>
        </div>
      </nav>
    </header>
  )
}

export function ThemeToggle() {
  const toggle = () => {
    const dark = document.documentElement.classList.toggle('dark')
    try {
      localStorage.setItem('theme', dark ? 'dark' : 'light')
    } catch {}
  }
  return (
    <button onClick={toggle} className="grid size-9 place-items-center rounded-full text-muted hover:bg-sunken hover:text-fg" aria-label="Toggle colour theme">
      <svg viewBox="0 0 24 24" className="size-[18px]" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 3.5a8.5 8.5 0 0 0 0 17z" fill="currentColor" />
      </svg>
    </button>
  )
}

export function Footer() {
  return (
    <footer className="border-t border-line">
      <div className="container-page flex flex-col gap-6 py-12 text-sm text-muted sm:flex-row sm:items-center">
        <Logo className="text-fg" />
        <p>Open-source CLI under MIT. Payments by Dodo Payments (Merchant of Record).</p>
        <div className="flex gap-5 sm:ml-auto">
          <Link to="/pricing" className="hover:text-fg">Pricing</Link>
          <a href={site.github} className="hover:text-fg">GitHub</a>
          <a href="/llms.txt" className="hover:text-fg">llms.txt</a>
        </div>
      </div>
    </footer>
  )
}
