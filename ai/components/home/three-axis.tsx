'use client'

import { Reveal, Ring, Section } from '@/components/ui/motion'

const AXES = [
  {
    n: '01',
    name: 'Threat',
    value: 94,
    color: 'text-critical',
    question: 'How malicious is the email?',
    signals: ['Credential phishing', 'Financial pressure', 'Malicious URL', 'Deceptive sender'],
  },
  {
    n: '02',
    name: 'Infrastructure',
    value: 83,
    color: 'text-infra',
    question: 'How trustworthy is the infrastructure?',
    signals: ['SPF failure', 'DKIM inconsistency', 'Suspicious relay', 'Young domain'],
  },
  {
    n: '03',
    name: 'Attribution',
    value: 40,
    color: 'text-attrib',
    question: 'Can the infrastructure be linked to a campaign?',
    signals: ['IP reuse', 'Shared domains', 'Historical cases', 'Threat clusters'],
  },
]

export function ThreeAxis() {
  return (
    <div className="border-y border-border bg-surface/40">
      <Section className="py-24 lg:py-36">
        <div className="grid gap-10 lg:grid-cols-[1fr_1.2fr] lg:items-end">
          <Reveal>
            <p className="eyebrow">The three-axis intelligence model</p>
            <h2 className="display mt-5 text-[clamp(3rem,6.5vw,6rem)]">
              Three questions.
              <br />
              One verdict.
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="max-w-md text-lg leading-relaxed text-muted-foreground lg:ml-auto">
              Instead of simply showing one threat percentage, TRACEGUARD measures three independent dimensions —
              so an analyst always knows what is dangerous, what is untrustworthy, and what is connected.
            </p>
          </Reveal>
        </div>

        <ul className="mt-20 grid gap-4 lg:grid-cols-3">
          {AXES.map((a, i) => (
            <Reveal key={a.n} as="li" delay={i * 0.1}>
              <article className="flex h-full flex-col rounded-3xl border border-border bg-surface p-8 sm:p-10">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="eyebrow">{a.n}</p>
                    <h3 className="display mt-3 text-4xl">{a.name}</h3>
                  </div>
                  <Ring value={a.value} size={128} colorClass={a.color} />
                </div>
                <p className="mt-8 text-base text-muted-foreground">{a.question}</p>
                <ul className="mt-8 flex flex-col border-t border-border">
                  {a.signals.map((s) => (
                    <li key={s} className="flex items-center gap-3 border-b border-border py-3 text-sm">
                      <span className={`size-1.5 rounded-full bg-current ${a.color}`} />
                      {s}
                    </li>
                  ))}
                </ul>
              </article>
            </Reveal>
          ))}
        </ul>
      </Section>
    </div>
  )
}
