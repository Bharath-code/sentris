import { HeadContent, Scripts, createRootRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import appCss from '../styles.css?url'

// Runs before paint so there is no light/dark flash. Dark is the default brand surface.
const THEME_INIT = `try{var t=localStorage.getItem('theme');if(t!=='light')document.documentElement.classList.add('dark')}catch(e){document.documentElement.classList.add('dark')}`

const title = 'Sentris — fix leaked secrets before you push'
const description =
  'A 4 MB Rust CLI that finds hardcoded credentials, moves them into your secret store, patches the code and rotates the key with zero downtime. Free and open source; Pro from $8/dev.'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title },
      { name: 'description', content: description },
      { name: 'theme-color', content: '#08080a' },
      { property: 'og:title', content: title },
      { property: 'og:description', content: description },
      { property: 'og:image', content: '/og-sentris-2026.png' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
    links: [
      { rel: 'stylesheet', href: appCss },
      { rel: 'icon', href: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="6" fill="%23111"/><circle cx="17.5" cy="6.5" r="2" fill="%23ff6a33"/></svg>' },
    ],
  }),
  shellComponent: RootDocument,
  notFoundComponent: () => (
    <main className="container-page grid min-h-[70vh] place-items-center text-center">
      <div>
        <p className="font-mono text-sm text-faint">404</p>
        <h1 className="mt-2 text-title font-semibold">Nothing leaked here.</h1>
        <a href="/" className="mt-6 inline-block text-sm text-muted underline underline-offset-4 hover:text-fg">Back home</a>
      </div>
    </main>
  ),
})

function RootDocument({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  )
}
