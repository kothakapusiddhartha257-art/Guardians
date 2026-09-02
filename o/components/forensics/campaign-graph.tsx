'use client'

import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import { cn } from '@/lib/utils'

export interface GraphNode {
  id: string
  label: string
  kind: 'email' | 'domain' | 'ip' | 'hash' | 'case'
  x: number
  y: number
  evidence?: string
}

export interface GraphEdge {
  from: string
  to: string
}

const KIND_COLOR: Record<GraphNode['kind'], string> = {
  email: 'var(--foreground)',
  domain: 'var(--warning)',
  ip: 'var(--infra)',
  hash: 'var(--critical)',
  case: 'var(--attrib)',
}

export const DEFAULT_NODES: GraphNode[] = [
  { id: 'email', label: 'TG-2026-0482', kind: 'email', x: 400, y: 60, evidence: 'Current investigation · Wire transfer BEC' },
  { id: 'domain', label: 'company-secure.com', kind: 'domain', x: 400, y: 170, evidence: 'Registered 3 days ago · Namecheap · privacy-protected' },
  { id: 'ip', label: '185.23.11.4', kind: 'ip', x: 400, y: 280, evidence: 'AS208091 · Frankfurt, DE · seen in 4 investigations' },
  { id: 'hash', label: 'c1f2…c1d2', kind: 'hash', x: 400, y: 390, evidence: 'PE executable disguised as invoice.pdf · entropy 7.8' },
  { id: 'c1', label: 'TG-2026-0466', kind: 'case', x: 130, y: 470, evidence: 'Payroll redirect · same origin IP' },
  { id: 'c2', label: 'TG-2026-0437', kind: 'case', x: 310, y: 490, evidence: 'Homoglyph portal · shared attachment hash' },
  { id: 'c3', label: 'TG-2026-0412', kind: 'case', x: 490, y: 490, evidence: 'Executive impersonation · same relay' },
  { id: 'c4', label: 'TG-2026-0398', kind: 'case', x: 670, y: 470, evidence: 'Wire fraud · same registrar & nameservers' },
  { id: 'd2', label: 'company-hr-portal.com', kind: 'domain', x: 160, y: 200, evidence: 'Sibling domain · same nameservers' },
  { id: 'd3', label: 'company-payments.co', kind: 'domain', x: 640, y: 200, evidence: 'Sibling domain · same registrant hash' },
  { id: 'ip2', label: '185.23.11.9', kind: 'ip', x: 640, y: 320, evidence: 'Adjacent host in the same /28 block' },
]

export const DEFAULT_EDGES: GraphEdge[] = [
  { from: 'email', to: 'domain' },
  { from: 'domain', to: 'ip' },
  { from: 'ip', to: 'hash' },
  { from: 'hash', to: 'c1' },
  { from: 'hash', to: 'c2' },
  { from: 'ip', to: 'c3' },
  { from: 'ip', to: 'c4' },
  { from: 'domain', to: 'd2' },
  { from: 'domain', to: 'd3' },
  { from: 'ip', to: 'ip2' },
  { from: 'd2', to: 'c1' },
  { from: 'ip2', to: 'c4' },
]

export function CampaignGraph({
  nodes = DEFAULT_NODES,
  edges = DEFAULT_EDGES,
  interactive = true,
  className,
}: {
  nodes?: GraphNode[]
  edges?: GraphEdge[]
  interactive?: boolean
  className?: string
}) {
  const [hover, setHover] = useState<GraphNode | null>(null)
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
  const connected = new Set(hover ? edges.filter((e) => e.from === hover.id || e.to === hover.id).flatMap((e) => [e.from, e.to]) : [])

  return (
    <div className={cn('relative', className)}>
      <svg viewBox="0 0 800 540" className="h-auto w-full" role="img" aria-label="Campaign correlation graph">
        {edges.map((e, i) => {
          const a = byId[e.from]
          const b = byId[e.to]
          if (!a || !b) return null
          const lit = hover && (e.from === hover.id || e.to === hover.id)
          return (
            <motion.line
              key={i}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={lit ? KIND_COLOR[hover!.kind] : 'rgba(255,255,255,0.14)'}
              strokeWidth={lit ? 1.5 : 1}
              initial={{ pathLength: 0, opacity: 0 }}
              whileInView={{ pathLength: 1, opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8, delay: i * 0.06 }}
            />
          )
        })}
        {nodes.map((n, i) => {
          const dimmed = hover && hover.id !== n.id && !connected.has(n.id)
          const r = n.kind === 'email' ? 10 : n.kind === 'case' ? 7 : 8
          return (
            <motion.g
              key={n.id}
              initial={{ opacity: 0, scale: 0.6 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 + i * 0.05 }}
              style={{ transformOrigin: `${n.x}px ${n.y}px`, cursor: interactive ? 'pointer' : 'default' }}
              onMouseEnter={() => interactive && setHover(n)}
              onMouseLeave={() => interactive && setHover(null)}
              onFocus={() => interactive && setHover(n)}
              onBlur={() => interactive && setHover(null)}
              tabIndex={interactive ? 0 : -1}
              animate={{ opacity: dimmed ? 0.25 : 1 }}
            >
              <motion.circle
                cx={n.x}
                cy={n.y}
                r={r + 8}
                fill={KIND_COLOR[n.kind]}
                opacity={0.12}
                animate={{ r: [r + 6, r + 12, r + 6] }}
                transition={{ duration: 3, repeat: Infinity, delay: i * 0.2 }}
              />
              <circle cx={n.x} cy={n.y} r={r} fill="var(--surface)" stroke={KIND_COLOR[n.kind]} strokeWidth={1.5} />
              <circle cx={n.x} cy={n.y} r={r / 2.6} fill={KIND_COLOR[n.kind]} />
              <text
                x={n.x}
                y={n.y + r + 16}
                textAnchor="middle"
                style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fill: 'var(--muted-foreground)', letterSpacing: 0.5 }}
              >
                {n.label}
              </text>
            </motion.g>
          )
        })}
      </svg>

      <AnimatePresence>
        {hover?.evidence && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 6 }}
            className="pointer-events-none absolute left-4 top-4 max-w-xs rounded-xl border border-border bg-surface-2/95 px-4 py-3 backdrop-blur"
          >
            <p className="eyebrow" style={{ color: KIND_COLOR[hover.kind] }}>
              {hover.kind}
            </p>
            <p className="mt-1 font-mono text-xs text-foreground">{hover.label}</p>
            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{hover.evidence}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
