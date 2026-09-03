'use client'

import { motion } from 'framer-motion'
import { Fragment } from 'react'
import type { Hop } from '@/lib/traceguard'
import { cn } from '@/lib/utils'

export function RelayTrace({ hops, detailed = false }: { hops: Hop[]; detailed?: boolean }) {
  return (
    <ol className="relative flex flex-col items-stretch">
      {hops.map((hop, i) => {
        const afterFrontier = hops.slice(0, i).some((h) => h.frontier)
        const dim = afterFrontier || !hop.trusted
        return (
          <Fragment key={hop.host + i}>
            <motion.li
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.12, duration: 0.5 }}
              className={cn(
                'flex items-center justify-between gap-6 rounded-2xl border px-5 py-4 transition-colors',
                dim ? 'border-critical/25 bg-critical/[0.04]' : 'border-border bg-surface',
                !hop.trusted && hop.host === 'UNKNOWN' && 'border-dashed',
              )}
            >
              <div className="min-w-0">
                <p className="eyebrow">{hop.label}</p>
                <p className={cn('mt-1 truncate font-mono text-sm', dim ? 'text-critical' : 'text-foreground')}>{hop.host}</p>
              </div>
              {hop.ip && <span className="shrink-0 font-mono text-xs text-muted-foreground">{hop.ip}</span>}
            </motion.li>

            {hop.frontier && (
              <motion.div
                initial={{ opacity: 0, scaleX: 0.6 }}
                whileInView={{ opacity: 1, scaleX: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12 + 0.2, duration: 0.7 }}
                className="relative my-3 flex items-center gap-4 py-2"
              >
                <span className="h-px flex-1 bg-gradient-to-r from-transparent via-warning to-warning shadow-[0_0_24px_var(--warning)]" />
                <span className="flex flex-col items-center">
                  <span className="eyebrow text-warning">⚠ Trust Frontier</span>
                  {detailed && <span className="eyebrow mt-1 text-[9px]">The last trusted hop</span>}
                </span>
                <span className="h-px flex-1 bg-gradient-to-l from-transparent via-warning to-warning shadow-[0_0_24px_var(--warning)]" />
              </motion.div>
            )}

            {!hop.frontier && i < hops.length - 1 && (
              <div className="flex justify-center py-1" aria-hidden>
                <span className={cn('h-5 w-px', dim ? 'bg-critical/40' : 'bg-border')} />
              </div>
            )}
          </Fragment>
        )
      })}
    </ol>
  )
}
