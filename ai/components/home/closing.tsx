'use client'

import Link from 'next/link'
import { Reveal, Section } from '@/components/ui/motion'
import { useIngest } from '@/components/shell/ingest-context'

const CAPABILITIES = [
  'Live Threat Gateway',
  'Gmail integration',
  'Browser extension',
  '.EML / .MSG ingestion',
  'PDF forensic reports',
  'STIX 2.1 export',
  'Chain of custody',
  'Case management',
]

export function Closing() {
  const { openIngest } = useIngest()
  return (
    <div className="border-t border-border">
      <Section className="grid gap-12 py-24 lg:grid-cols-[1.3fr_1fr] lg:py-36">
        <Reveal>
          <p className="eyebrow">Get started</p>
          <h2 className="display mt-5 text-[clamp(3rem,7vw,7rem)]">
            From inbox
            <br />
            to evidence.
          </h2>
          <div className="mt-10 flex flex-wrap items-center gap-6">
            <button
              type="button"
              onClick={openIngest}
              className="rounded-full bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
            >
              Ingest Evidence
            </button>
            <Link href="/investigation" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Open a sample investigation →
            </Link>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <ul className="grid grid-cols-2 gap-x-6 border-t border-border">
            {CAPABILITIES.map((c) => (
              <li key={c} className="border-b border-border py-4 text-sm text-muted-foreground">
                {c}
              </li>
            ))}
          </ul>
        </Reveal>
      </Section>
    </div>
  )
}
