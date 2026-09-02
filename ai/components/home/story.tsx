'use client'

import { motion, useInView } from 'framer-motion'
import { useEffect, useRef, useState } from 'react'
import { Reveal, Section } from '@/components/ui/motion'
import { cn } from '@/lib/utils'

const UNFOLD = [
  { k: 'FROM', v: 'finance@micros0ft-security.com', tone: 'text-foreground' },
  { k: 'SPF', v: 'FAIL', tone: 'text-critical' },
  { k: 'DKIM', v: 'FAIL', tone: 'text-critical' },
  { k: 'SMTP ORIGIN', v: '185.23.11.4', tone: 'text-infra' },
  { k: 'DOMAIN', v: '3 days old', tone: 'text-warning' },
  { k: 'URL', v: 'IP literal detected', tone: 'text-warning' },
  { k: 'ATTACHMENT', v: 'Disguised executable', tone: 'text-critical' },
]

export function Story() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-120px' })
  const [step, setStep] = useState(-1)

  useEffect(() => {
    if (!inView) return
    let i = -1
    const tick = () => {
      i += 1
      setStep(i)
      if (i <= UNFOLD.length) setTimeout(tick, i === 0 ? 500 : 450)
    }
    const t = setTimeout(tick, 200)
    return () => clearTimeout(t)
  }, [inView])

  return (
    <Section className="py-24 lg:py-40">
      <Reveal className="mx-auto flex max-w-3xl flex-col items-center text-center">
        <h2 className="display text-[clamp(3rem,7vw,6.5rem)]">
          One email.
          <br />
          <span className="italic text-muted-foreground">Thousands of signals.</span>
        </h2>
        <p className="mt-8 max-w-xl text-lg leading-relaxed text-muted-foreground">
          TRACEGUARD doesn&apos;t simply classify messages as safe or malicious. It reconstructs what happened.
        </p>
      </Reveal>

      <div ref={ref} className="mx-auto mt-20 max-w-2xl">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="rounded-3xl border border-border bg-surface p-5 sm:p-8"
        >
          <div className="flex items-center justify-between border-b border-border pb-4">
            <div className="flex items-center gap-2">
              <span className="size-2 rounded-full bg-border" />
              <span className="size-2 rounded-full bg-border" />
              <span className="size-2 rounded-full bg-border" />
            </div>
            <span className="eyebrow">message.eml</span>
          </div>
          <div className="pt-5">
            <p className="text-lg text-foreground">Re: Payment confirmation needed</p>
            <p className="mt-1 text-sm text-muted-foreground">Please review the attached invoice and confirm the transfer today.</p>
          </div>

          <ol className="mt-8 flex flex-col">
            {UNFOLD.map((row, i) => {
              const shown = step >= i + 1
              return (
                <motion.li
                  key={row.k}
                  initial={false}
                  animate={{ opacity: shown ? 1 : 0.18, x: shown ? 0 : -6 }}
                  transition={{ duration: 0.45 }}
                  className="flex items-center justify-between gap-6 border-t border-border py-4 first:border-t-0"
                >
                  <span className="eyebrow">{row.k}</span>
                  <span className={cn('font-mono text-sm text-right', shown ? row.tone : 'text-muted-foreground')}>{row.v}</span>
                </motion.li>
              )
            })}
          </ol>

          <motion.div
            initial={false}
            animate={{ opacity: step > UNFOLD.length ? 1 : 0, y: step > UNFOLD.length ? 0 : 12 }}
            transition={{ duration: 0.6 }}
            className="mt-6 flex items-center justify-between rounded-2xl border border-critical/40 bg-critical/10 px-6 py-5 shadow-[0_0_60px_-20px_var(--critical)]"
          >
            <span className="eyebrow text-critical">Final verdict</span>
            <span className="display text-3xl text-critical sm:text-4xl">MALICIOUS — 94%</span>
          </motion.div>
        </motion.div>
      </div>
    </Section>
  )
}
