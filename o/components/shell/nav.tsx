'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ShieldCheck, Menu, X } from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { useIngest } from './ingest-context'

const LINKS = [
  { href: '/monitoring', label: 'Gateway' },
  { href: '/', label: 'Intelligence' },
  { href: '/investigation', label: 'Investigations' },
  { href: '/cases', label: 'Cases' },
  { href: '/campaigns', label: 'Campaigns' },
]

export function Nav() {
  const pathname = usePathname()
  const { openIngest } = useIngest()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-between px-5 md:px-10">
        <Link href="/" className="flex items-center gap-3">
          <ShieldCheck className="size-5 text-foreground" strokeWidth={1.75} aria-hidden />
          <div className="flex flex-col leading-none">
            <span className="text-[15px] font-semibold tracking-[0.12em]">TRACEGUARD</span>
            <span className="eyebrow mt-1 hidden text-[9px] sm:block">Autonomous Email Defense</span>
          </div>
        </Link>

        <nav aria-label="Primary" className="hidden items-center gap-1 md:flex">
          {LINKS.map((l) => {
            const active = pathname === l.href || (l.href !== '/' && pathname.startsWith(l.href))
            return (
              <Link
                key={l.href}
                href={l.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'rounded-full px-4 py-1.5 text-sm transition-colors',
                  active ? 'bg-surface-2 text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {l.label}
              </Link>
            )
          })}
        </nav>

        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 lg:flex">
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full rounded-full bg-safe opacity-60 tg-pulse" />
              <span className="relative inline-flex size-2 rounded-full bg-safe" />
            </span>
            <span className="eyebrow text-foreground/80">System Active</span>
          </div>
          <button
            type="button"
            onClick={openIngest}
            className="rounded-full bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Ingest Evidence
          </button>
          <button
            type="button"
            className="rounded-full p-2 text-muted-foreground md:hidden"
            aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen((v) => !v)}
          >
            {mobileOpen ? <X className="size-5" /> : <Menu className="size-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <nav aria-label="Mobile" className="border-t border-border bg-background px-5 py-3 md:hidden">
          <ul className="flex flex-col">
            {LINKS.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  onClick={() => setMobileOpen(false)}
                  className={cn(
                    'block py-3 text-base',
                    pathname === l.href ? 'text-foreground' : 'text-muted-foreground',
                  )}
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
      )}
    </header>
  )
}
