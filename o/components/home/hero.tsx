'use client'

import { motion } from 'framer-motion'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { Section } from '@/components/ui/motion'
import { useIngest } from '@/components/shell/ingest-context'
import { cn } from '@/lib/utils'

const CHAIN = [
  { label: 'Email', value: 'finance@micros0ft-security.com', tone: 'text-foreground' },
  { label: 'Authentication', value: 'SPF FAIL · DKIM FAIL · DMARC FAIL', tone: 'text-critical' },
  { label: 'SMTP Relay Chain', value: 'M365 → smtp-relay.net → ⚠ frontier', tone: 'text-warning' },
  { label: 'Origin IP', value: '185.23.11.4 · Frankfurt, DE', tone: 'text-infra' },
  { label: 'Threat Intelligence', value: 'Credential phishing · 94%', tone: 'text-critical' },
  { label: 'Campaign Correlation', value: 'CAM-2026-08 · 4 previous cases', tone: 'text-attrib' },
  { label: 'Forensic Evidence', value: 'SHA-256 preserved · chain verified', tone: 'text-safe' },
]

export function Hero() {
  const { openIngest } = useIngest()
  return (
    <Section className="grid gap-16 pb-24 pt-16 md:pt-24 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:gap-12 lg:pb-32">
      <div className="flex flex-col items-start">
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6 }}
          className="eyebrow"
        >
          Autonomous Email Threat Intelligence
        </motion.p>
        <motion.h1
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
          className="display mt-6 text-[clamp(3.5rem,9vw,8.5rem)]"
        >
          Every email
          <br />
          has a story.
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="mt-8 max-w-lg text-lg leading-relaxed text-muted-foreground text-pretty"
        >
          TRACEGUARD autonomously analyzes incoming email, reconstructs its infrastructure, identifies deception,
          correlates threat campaigns, and preserves forensic evidence.
        </motion.p>
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.45 }}
          className="mt-10 flex flex-wrap items-center gap-6"
        >
          <button
            type="button"
            onClick={openIngest}
            className="rounded-full bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Analyze an Email
          </button>
          <Link
            href="/monitoring"
            className="group inline-flex items-center gap-2 text-sm text-foreground/80 transition-colors hover:text-foreground"
          >
            Explore Live Gateway
            <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
          </Link>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 1, delay: 0.2 }}
        className="relative"
      >
        <ChainVisual />
      </motion.div>
    </Section>
  )
}

function ChainVisual() {
  return (
    <div className="grid-bg relative overflow-hidden rounded-3xl border border-border bg-surface p-6 sm:p-10">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-infra/60 to-transparent" />
      <div className="flex items-center justify-between">
        <span className="eyebrow">Intelligence pipeline</span>
        <span className="eyebrow flex items-center gap-2 text-safe">
          <span className="size-1.5 rounded-full bg-safe tg-pulse" /> Live
        </span>
      </div>

      <ol className="relative mt-8 flex flex-col">
        <svg className="pointer-events-none absolute left-[11px] top-3 h-[calc(100%-1.5rem)] w-px" aria-hidden>
          <line x1="0.5" y1="0" x2="0.5" y2="100%" stroke="currentColor" className="text-border" />
          <line x1="0.5" y1="0" x2="0.5" y2="100%" stroke="currentColor" strokeWidth="1.5" className="tg-flow text-infra" />
        </svg>
        {CHAIN.map((step, i) => (
          <motion.li
            key={step.label}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5 + i * 0.18, duration: 0.5 }}
            className="relative flex items-start gap-5 py-3"
          >
            <span className="relative z-10 mt-1.5 flex size-6 items-center justify-center rounded-full border border-border bg-surface">
              <motion.span
                className={cn('size-1.5 rounded-full bg-current', step.tone)}
                animate={{ scale: [1, 1.6, 1], opacity: [1, 0.5, 1] }}
                transition={{ duration: 2.4, repeat: Infinity, delay: i * 0.3 }}
              />
            </span>
            <div className="min-w-0 flex-1">
              <p className="eyebrow">{step.label}</p>
              <p className={cn('mt-1 truncate font-mono text-sm', step.tone)}>{step.value}</p>
            </div>
          </motion.li>
        ))}
      </ol>

      <div className="mt-6 flex items-center justify-between rounded-2xl border border-critical/30 bg-critical/5 px-5 py-4">
        <span className="eyebrow text-critical">Final verdict</span>
        <span className="font-mono text-sm text-critical">MALICIOUS — 94%</span>
      </div>
    </div>
  )
}
