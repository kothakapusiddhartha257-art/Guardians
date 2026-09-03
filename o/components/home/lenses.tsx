'use client'

import { motion } from 'framer-motion'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { Reveal, Section } from '@/components/ui/motion'
import { GeoMap } from '@/components/forensics/geo-map'
import { RelayTrace } from '@/components/forensics/relay-trace'
import { INVESTIGATION } from '@/lib/traceguard'
import { cn } from '@/lib/utils'

function LensCard({
  title,
  cta,
  href,
  children,
  wide = false,
  delay = 0,
}: {
  title: string
  cta: string
  href: string
  children: React.ReactNode
  wide?: boolean
  delay?: number
}) {
  return (
    <Reveal as="li" delay={delay} className={cn(wide && 'lg:col-span-2')}>
      <article className="flex h-full flex-col overflow-hidden rounded-3xl border border-border bg-surface transition-colors hover:border-foreground/15">
        <div className="flex-1 border-b border-border p-6 sm:p-8">{children}</div>
        <div className="p-6 sm:p-8">
          <h3 className="display text-3xl">{title}</h3>
          <Link href={href} className="group mt-4 inline-flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
            {cta}
            <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
          </Link>
        </div>
      </article>
    </Reveal>
  )
}

const Mono = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <span className={cn('font-mono text-sm', className)}>{children}</span>
)

export function Lenses() {
  const inv = INVESTIGATION
  return (
    <Section className="py-24 lg:py-40">
      <Reveal className="max-w-3xl">
        <p className="eyebrow">Forensic lenses</p>
        <h2 className="display mt-5 text-[clamp(3rem,7vw,7rem)]">
          Eleven ways
          <br />
          to see the truth.
        </h2>
        <p className="mt-8 max-w-xl text-lg leading-relaxed text-muted-foreground">
          Every investigation begins with one email. Then TRACEGUARD reconstructs the entire story.
        </p>
      </Reveal>

      <ul className="mt-20 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* 1 Content */}
        <LensCard title="Understand what the attacker wants." cta="Explore Content Analysis" href="/investigation?lens=content">
          <p className="eyebrow">Content intelligence</p>
          <p className="mt-4 text-sm leading-7 text-muted-foreground">
            I need you to process an{' '}
            <Highlight intent="Urgency">URGENT</Highlight> request.{' '}
            <Highlight intent="Financial directive">Wire transfer immediately</Highlight> to the attached account.{' '}
            <Highlight intent="Isolation">Do not contact anyone</Highlight> until it is complete.
          </p>
        </LensCard>

        {/* 2 Headers */}
        <LensCard title="Find what the sender tried to hide." cta="Explore Header Forensics" href="/investigation?lens=headers">
          <p className="eyebrow">Header forensics</p>
          <dl className="mt-5 flex flex-col gap-4">
            <div>
              <dt className="eyebrow text-[10px]">From</dt>
              <dd><Mono>ceo@company.com</Mono></dd>
            </div>
            <div className="rounded-xl border border-critical/30 bg-critical/5 p-3">
              <dt className="eyebrow text-[10px] text-critical">Reply-To · mismatch</dt>
              <dd><Mono className="text-critical">payment@company-support.co</Mono></dd>
            </div>
          </dl>
        </LensCard>

        {/* 3 Auth */}
        <LensCard title="Verify who actually sent it." cta="Explore Authentication" href="/investigation?lens=authentication">
          <p className="eyebrow">Authentication</p>
          <div className="mt-5 grid grid-cols-2 gap-2">
            {[
              ['SPF', 'FAIL', 'text-critical'],
              ['DKIM', 'FAIL', 'text-critical'],
              ['DMARC', 'REJECT', 'text-critical'],
              ['ARC', 'PASS', 'text-safe'],
            ].map(([p, r, c]) => (
              <div key={p} className="rounded-xl border border-border bg-background/40 p-4">
                <p className="eyebrow text-[10px]">{p}</p>
                <p className={cn('mt-2 font-mono text-lg', c)}>{r}</p>
              </div>
            ))}
          </div>
        </LensCard>

        {/* 4 Relay */}
        <LensCard title="Follow the message back to its origin." cta="Explore Relay Trace" href="/investigation?lens=relay">
          <p className="eyebrow mb-5">SMTP relay trace</p>
          <RelayTrace hops={inv.hops.slice(0, 4)} />
        </LensCard>

        {/* 5 Geo — wide */}
        <LensCard title="Know where the infrastructure lives." cta="Explore GeoLocation" href="/investigation?lens=geolocation" wide>
          <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr] lg:items-center">
            <GeoMap route={inv.route} compact className="rounded-2xl border border-border bg-background/40" />
            <dl className="flex flex-col gap-5">
              <div>
                <dt className="eyebrow">Infrastructure location</dt>
                <dd className="mt-1 text-xl">Frankfurt, Germany</dd>
              </div>
              <div>
                <dt className="eyebrow">Confidence</dt>
                <dd className="mt-1 font-mono text-xl text-infra">83%</dd>
              </div>
              <div>
                <dt className="eyebrow">Human actor</dt>
                <dd className="mt-1 text-xl text-muted-foreground">Unknown / Proxied</dd>
              </div>
            </dl>
          </div>
        </LensCard>

        {/* 6 Domain */}
        <LensCard title="Detect identities designed to deceive." cta="Explore Domain Intelligence" href="/investigation?lens=domains">
          <p className="eyebrow">Domain intelligence</p>
          <div className="mt-5 flex flex-col gap-3">
            <Mono className="text-muted-foreground">microsoft.com</Mono>
            <span className="eyebrow">vs</span>
            <Mono className="text-lg">
              micr<span className="rounded bg-critical/20 px-1 text-critical">0</span>s0ft-security.com
            </Mono>
          </div>
          <div className="mt-6 grid grid-cols-3 gap-2 border-t border-border pt-5">
            <Stat k="Substitution" v="0 → o" />
            <Stat k="Domain age" v="3 days" tone="text-warning" />
            <Stat k="Risk" v="96%" tone="text-critical" />
          </div>
        </LensCard>

        {/* 7 URL */}
        <LensCard title="See where links really go." cta="Explore URL Forensics" href="/investigation?lens=urls">
          <p className="eyebrow">URL forensics</p>
          <ol className="mt-5 flex flex-col gap-2">
            <Step label="Displayed"><Mono>https://login.microsoft.com</Mono></Step>
            <Step label="Actually resolves to"><Mono className="text-warning">http://185.23.11.4/auth</Mono></Step>
            <Step label="302 redirect"><Mono className="text-muted-foreground">/r?u=0x3f</Mono></Step>
            <Step label="Destination"><Mono className="text-critical">Credential harvesting page</Mono></Step>
          </ol>
        </LensCard>

        {/* 8 Attachment */}
        <LensCard title="Trust the file, not its name." cta="Explore Attachment Forensics" href="/investigation?lens=attachments">
          <p className="eyebrow">Attachment forensics</p>
          <div className="mt-5 flex items-center gap-4">
            <div className="flex size-14 items-center justify-center rounded-xl border border-border bg-background/40">
              <Mono className="text-xs text-muted-foreground">.pdf</Mono>
            </div>
            <div>
              <Mono>invoice.pdf</Mono>
              <p className="mt-1 text-xs text-critical">Detected: Windows PE Executable</p>
            </div>
          </div>
          <div className="mt-6 grid grid-cols-2 gap-2 border-t border-border pt-5">
            <Stat k="Magic bytes" v="4D 5A" tone="text-critical" />
            <Stat k="Entropy" v="7.8" tone="text-warning" />
          </div>
        </LensCard>

        {/* 9 Campaign */}
        <LensCard title="Discover attacks that belong together." cta="Explore Campaign Graph" href="/investigation?lens=campaign">
          <p className="eyebrow">Campaign graph</p>
          <ol className="mt-5 flex flex-col items-start">
            {[
              ['Email', 'text-foreground'],
              ['Domain', 'text-warning'],
              ['IP', 'text-infra'],
              ['Attachment hash', 'text-critical'],
            ].map(([l, c], i) => (
              <li key={l} className="flex flex-col items-start">
                <motion.span
                  initial={{ opacity: 0, x: -6 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.12 }}
                  className="flex items-center gap-3 font-mono text-sm"
                >
                  <span className={cn('size-2 rounded-full bg-current', c)} />
                  {l}
                </motion.span>
                <span className="ml-[3px] my-1 h-4 w-px bg-border" aria-hidden />
              </li>
            ))}
            <li className="flex items-center gap-3 rounded-xl border border-attrib/30 bg-attrib/10 px-3 py-2 font-mono text-sm text-attrib">
              <span className="size-2 rounded-full bg-attrib" />4 previous cases
            </li>
          </ol>
        </LensCard>
      </ul>
    </Section>
  )
}

function Highlight({ children, intent }: { children: React.ReactNode; intent: string }) {
  return (
    <span className="relative inline-block rounded bg-critical/15 px-1 text-foreground">
      {children}
      <span className="eyebrow absolute -top-4 left-0 whitespace-nowrap text-[8px] text-critical">{intent}</span>
    </span>
  )
}

function Stat({ k, v, tone = 'text-foreground' }: { k: string; v: string; tone?: string }) {
  return (
    <div>
      <p className="eyebrow text-[10px]">{k}</p>
      <p className={cn('mt-1 font-mono text-sm', tone)}>{v}</p>
    </div>
  )
}

function Step({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <li className="rounded-xl border border-border bg-background/40 px-4 py-3">
      <p className="eyebrow text-[10px]">{label}</p>
      <p className="mt-1 truncate">{children}</p>
    </li>
  )
}
