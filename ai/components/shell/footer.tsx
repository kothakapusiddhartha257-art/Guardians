import Link from 'next/link'

const MARQUEE = [
  'Autonomous Email Defense',
  'Forensic Intelligence',
  'Campaign Correlation',
  'Evidence You Can Trust',
  'SPF · DKIM · DMARC · ARC',
  'SMTP Trust Frontier',
  'Chain of Custody',
  'STIX 2.1 Export',
]

export function Footer() {
  const items = [...MARQUEE, ...MARQUEE]
  return (
    <footer className="border-t border-border">
      <div className="overflow-hidden border-b border-border py-4" aria-hidden>
        <div className="tg-marquee flex w-max gap-12 whitespace-nowrap">
          {items.map((m, i) => (
            <span key={i} className="eyebrow flex items-center gap-12 text-foreground/70">
              {m}
              <span className="size-1 rounded-full bg-muted-foreground/50" />
            </span>
          ))}
        </div>
      </div>
      <div className="mx-auto flex max-w-[1440px] flex-col gap-8 px-5 py-12 md:flex-row md:items-end md:justify-between md:px-10">
        <div>
          <p className="text-[15px] font-semibold tracking-[0.12em]">TRACEGUARD</p>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            AI-powered email threat detection, autonomous gateway, geolocation and digital forensic intelligence.
          </p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap gap-x-8 gap-y-3 text-sm text-muted-foreground">
          <Link href="/monitoring" className="hover:text-foreground">Gateway</Link>
          <Link href="/investigation" className="hover:text-foreground">Investigations</Link>
          <Link href="/cases" className="hover:text-foreground">Cases</Link>
          <Link href="/campaigns" className="hover:text-foreground">Campaigns</Link>
          <span>Browser Extension</span>
          <span>Gmail Integration</span>
        </nav>
      </div>
    </footer>
  )
}
