'use client'

import { AnimatePresence, motion } from 'framer-motion'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis } from 'recharts'
import { CountUp, Reveal, Section } from '@/components/ui/motion'
import { useGatewayStream } from '@/hooks/use-gateway-stream'
import { scoreColor, verdictColor, type FeedAction, type FeedItem } from '@/lib/traceguard'
import { cn } from '@/lib/utils'

const THROUGHPUT = Array.from({ length: 24 }, (_, h) => ({
  hour: `${String(h).padStart(2, '0')}:00`,
  inbound: Math.round(280 + Math.sin(h / 3.2) * 160 + (h > 8 && h < 18 ? 220 : 0)),
  blocked: Math.round(4 + Math.abs(Math.cos(h / 2.1)) * 9 + (h === 14 ? 12 : 0)),
}))

const ACTION_BG: Record<FeedAction, string> = {
  QUARANTINED: 'bg-critical',
  FLAGGED: 'bg-suspicious',
  DELIVERED: 'bg-safe',
}

export function GatewayView() {
  const { items, metrics, connected } = useGatewayStream()

  return (
    <>
      <Section className="pb-16 pt-16 md:pt-24">
        <div className="flex flex-col gap-10 lg:flex-row lg:items-end lg:justify-between">
          <Reveal className="max-w-3xl">
            <p className="eyebrow">Live Threat Gateway</p>
            <h1 className="display mt-5 text-[clamp(3.25rem,8vw,7.5rem)]">
              The inbox,
              <br />
              under watch.
            </h1>
            <p className="mt-8 max-w-xl text-lg leading-relaxed text-muted-foreground">
              TRACEGUARD watches incoming email and acts before threats reach users.
            </p>
          </Reveal>
          <Reveal delay={0.1} className="flex items-center gap-3 lg:pb-3">
            <span className="relative flex size-2.5">
              <span className={cn('absolute inline-flex size-full rounded-full opacity-60 tg-pulse', connected ? 'bg-safe' : 'bg-warning')} />
              <span className={cn('relative inline-flex size-2.5 rounded-full', connected ? 'bg-safe' : 'bg-warning')} />
            </span>
            <span className="eyebrow text-foreground">{connected ? 'Autonomous gateway active' : 'Reconnecting'}</span>
          </Reveal>
        </div>

        <ul className="mt-20 grid grid-cols-2 gap-px overflow-hidden rounded-3xl border border-border bg-border lg:grid-cols-4">
          {[
            ['Inbound', metrics.inbound, 'text-foreground'],
            ['Quarantined', metrics.quarantined, 'text-critical'],
            ['Flagged', metrics.flagged, 'text-suspicious'],
            ['Delivered', metrics.delivered, 'text-safe'],
          ].map(([label, value, tone], i) => (
            <Reveal key={label as string} as="li" delay={i * 0.06} className="bg-surface p-7 sm:p-10">
              <p className="eyebrow">{label}</p>
              <p className={cn('mt-4 font-mono text-4xl tabular-nums sm:text-6xl', tone as string)}>
                <CountUp value={value as number} />
              </p>
            </Reveal>
          ))}
        </ul>
      </Section>

      <Section className="grid gap-4 pb-24 lg:grid-cols-[1.35fr_1fr] lg:pb-36">
        <div>
          <div className="mb-6 flex items-center justify-between">
            <h2 className="display text-3xl">Intelligence feed</h2>
            <span className="eyebrow">Streaming</span>
          </div>
          <ul className="flex flex-col gap-3">
            <AnimatePresence initial={false}>
              {items.map((item) => (
                <FeedCard key={item.id} item={item} />
              ))}
            </AnimatePresence>
          </ul>
        </div>

        <div className="flex flex-col gap-4">
          <Reveal className="rounded-3xl border border-border bg-surface p-7">
            <p className="eyebrow">24h throughput</p>
            <p className="mt-2 text-sm text-muted-foreground">Inbound volume against autonomous blocks.</p>
            <div className="mt-6 h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={THROUGHPUT} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
                  <defs>
                    <linearGradient id="inb" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--infra)" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="var(--infra)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="hour" hide />
                  <Tooltip
                    cursor={{ stroke: 'rgba(255,255,255,0.15)' }}
                    contentStyle={{
                      background: 'var(--surface-2)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      borderRadius: 12,
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                    }}
                    labelStyle={{ color: 'var(--muted-foreground)' }}
                  />
                  <Area type="monotone" dataKey="inbound" stroke="var(--infra)" strokeWidth={1.5} fill="url(#inb)" />
                  <Area type="monotone" dataKey="blocked" stroke="var(--critical)" strokeWidth={1.5} fill="transparent" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Reveal>

          <Reveal delay={0.05} className="rounded-3xl border border-border bg-surface p-7">
            <p className="eyebrow">Autonomous policy</p>
            <ul className="mt-5 flex flex-col">
              {[
                ['Threat ≥ 80', 'Quarantine · open case', 'text-critical'],
                ['Threat 35–79', 'Flag · analyst review', 'text-suspicious'],
                ['DMARC reject + directive', 'Quarantine · notify exec', 'text-critical'],
                ['Threat < 35', 'Deliver · retain evidence 90d', 'text-safe'],
              ].map(([rule, action, tone]) => (
                <li key={rule} className="flex items-center justify-between gap-4 border-b border-border py-3 text-sm last:border-b-0">
                  <span className="font-mono text-xs text-muted-foreground">{rule}</span>
                  <span className={cn('text-right text-xs', tone)}>{action}</span>
                </li>
              ))}
            </ul>
          </Reveal>

          <Reveal delay={0.1} className="rounded-3xl border border-border bg-surface p-7">
            <p className="eyebrow">Connected sources</p>
            <ul className="mt-5 grid grid-cols-2 gap-3 text-sm">
              {['Gmail Workspace', 'Microsoft 365', 'SMTP Relay', 'Browser Extension'].map((s) => (
                <li key={s} className="flex items-center gap-2 text-foreground/80">
                  <span className="size-1.5 rounded-full bg-safe" /> {s}
                </li>
              ))}
            </ul>
          </Reveal>
        </div>
      </Section>
    </>
  )
}

function FeedCard({ item }: { item: FeedItem }) {
  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: -24, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.98 }}
      transition={{ type: 'spring', stiffness: 260, damping: 28 }}
      className={cn(
        'rounded-2xl border bg-surface p-6',
        item.action === 'QUARANTINED' ? 'border-critical/30 shadow-[0_0_48px_-24px_var(--critical)]' : 'border-border',
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className={cn('size-2 rounded-full', ACTION_BG[item.action])} />
          <span className={cn('eyebrow', verdictColor(item.action))}>{item.action}</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="font-mono text-xs text-muted-foreground">{item.time}</span>
          <span className={cn('font-mono text-lg tabular-nums', scoreColor(item.score))}>{item.score}%</span>
        </div>
      </div>
      <p className="mt-4 text-xl text-foreground text-pretty">{item.subject}</p>
      <p className="mt-1 font-mono text-xs text-muted-foreground">{item.from}</p>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-4">
        <ul className="flex flex-wrap gap-2">
          {item.signals.map((s) => (
            <li key={s} className="rounded-full border border-border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              {s}
            </li>
          ))}
        </ul>
        <Link
          href={`/investigation?id=${item.id}`}
          className="group inline-flex items-center gap-2 text-sm text-foreground/80 transition-colors hover:text-foreground"
        >
          Inspect Investigation
          <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
        </Link>
      </div>
    </motion.li>
  )
}
