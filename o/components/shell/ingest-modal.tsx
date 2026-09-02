'use client'

import { AnimatePresence, motion } from 'framer-motion'
import { Check, FileUp, X } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useCallback, useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { useIngest } from './ingest-context'

const SCENARIOS = [
  { name: 'BEC Wire Fraud', verdict: 'MALICIOUS', score: 94 },
  { name: 'Office 365 Phishing', verdict: 'MALICIOUS', score: 81 },
  { name: 'Invoice Malware', verdict: 'MALICIOUS', score: 97 },
  { name: 'Clean Newsletter', verdict: 'CLEAN', score: 4 },
] as const

const STAGES = [
  { title: 'Ingesting evidence', proof: 'SHA-256 preserved' },
  { title: 'Reading message headers', proof: 'RFC 5322 normalized' },
  { title: 'Verifying identity', proof: 'SPF / DKIM / DMARC' },
  { title: 'Reconstructing route', proof: 'SMTP trust frontier' },
  { title: 'Analyzing intent', proof: 'NLP engine' },
  { title: 'Correlating intelligence', proof: 'Campaign graph' },
]

type Phase = 'idle' | 'running' | 'done'

export function IngestModal() {
  const { open, closeIngest } = useIngest()
  const router = useRouter()
  const [phase, setPhase] = useState<Phase>('idle')
  const [stage, setStage] = useState(0)
  const [scenario, setScenario] = useState<(typeof SCENARIOS)[number]>(SCENARIOS[0])
  const [dragging, setDragging] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const reset = useCallback(() => {
    setPhase('idle')
    setStage(0)
    setFileName(null)
  }, [])

  const close = useCallback(() => {
    closeIngest()
    setTimeout(reset, 300)
  }, [closeIngest, reset])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, close])

  useEffect(() => {
    if (phase !== 'running') return
    if (stage >= STAGES.length) {
      const t = setTimeout(() => setPhase('done'), 500)
      return () => clearTimeout(t)
    }
    const t = setTimeout(() => setStage((s) => s + 1), 650)
    return () => clearTimeout(t)
  }, [phase, stage])

  const start = (s: (typeof SCENARIOS)[number], name?: string) => {
    setScenario(s)
    if (name) setFileName(name)
    setStage(0)
    setPhase('running')
  }

  const onFiles = (files: FileList | null) => {
    const f = files?.[0]
    if (!f) return
    start(SCENARIOS[0], f.name)
  }

  const openInvestigation = () => {
    close()
    router.push('/investigation')
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-end justify-center bg-background/70 p-0 backdrop-blur-md sm:items-center sm:p-6"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={close}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="ingest-title"
            onClick={(e) => e.stopPropagation()}
            initial={{ y: 40, opacity: 0, scale: 0.98 }}
            animate={{ y: 0, opacity: 1, scale: 1 }}
            exit={{ y: 20, opacity: 0, scale: 0.98 }}
            transition={{ type: 'spring', stiffness: 260, damping: 26 }}
            className="relative w-full max-w-3xl overflow-hidden rounded-t-3xl border border-border bg-surface sm:rounded-3xl"
          >
            <button
              type="button"
              onClick={close}
              aria-label="Close"
              className="absolute right-4 top-4 rounded-full p-2 text-muted-foreground transition-colors hover:bg-surface-2 hover:text-foreground"
            >
              <X className="size-4" />
            </button>

            <div className="px-6 pb-8 pt-10 sm:px-12 sm:pb-12 sm:pt-14">
              <p className="eyebrow">Evidence Ingestion</p>

              <AnimatePresence mode="wait">
                {phase === 'idle' && (
                  <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    <h2 id="ingest-title" className="display mt-3 text-5xl sm:text-6xl">
                      Bring the evidence.
                    </h2>

                    <div
                      onDragOver={(e) => {
                        e.preventDefault()
                        setDragging(true)
                      }}
                      onDragLeave={() => setDragging(false)}
                      onDrop={(e) => {
                        e.preventDefault()
                        setDragging(false)
                        onFiles(e.dataTransfer.files)
                      }}
                      className={cn(
                        'mt-10 flex flex-col items-center justify-center gap-4 rounded-2xl border border-dashed px-6 py-14 text-center transition-colors',
                        dragging ? 'border-infra bg-infra/5' : 'border-border bg-background/40',
                      )}
                    >
                      <FileUp className="size-6 text-muted-foreground" strokeWidth={1.5} aria-hidden />
                      <p className="font-mono text-xs uppercase tracking-[0.18em] text-foreground">Drop .EML or .MSG</p>
                      <span className="eyebrow">or</span>
                      <button
                        type="button"
                        onClick={() => inputRef.current?.click()}
                        className="rounded-full border border-border px-5 py-2 text-sm transition-colors hover:bg-surface-2"
                      >
                        Browse Files
                      </button>
                      <input
                        ref={inputRef}
                        type="file"
                        accept=".eml,.msg"
                        className="sr-only"
                        onChange={(e) => onFiles(e.target.files)}
                      />
                    </div>

                    <p className="eyebrow mt-10">Try a forensic scenario</p>
                    <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
                      {SCENARIOS.map((s) => (
                        <button
                          key={s.name}
                          type="button"
                          onClick={() => start(s, `${s.name.toLowerCase().replace(/\s+/g, '-')}.eml`)}
                          className="rounded-xl border border-border bg-background/40 px-4 py-4 text-left text-sm transition-colors hover:border-foreground/20 hover:bg-surface-2"
                        >
                          {s.name}
                        </button>
                      ))}
                    </div>
                  </motion.div>
                )}

                {phase === 'running' && (
                  <motion.div key="running" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    <h2 id="ingest-title" className="display mt-3 text-4xl sm:text-5xl">
                      Reconstructing the story.
                    </h2>
                    <p className="mt-3 font-mono text-xs text-muted-foreground">{fileName}</p>

                    <ol className="mt-10 flex flex-col">
                      {STAGES.map((s, i) => {
                        const done = i < stage
                        const active = i === stage
                        return (
                          <li key={s.title} className="flex gap-5">
                            <div className="flex flex-col items-center">
                              <span
                                className={cn(
                                  'flex size-6 shrink-0 items-center justify-center rounded-full border text-[10px] transition-colors',
                                  done
                                    ? 'border-safe bg-safe text-primary-foreground'
                                    : active
                                      ? 'border-infra text-infra'
                                      : 'border-border text-muted-foreground',
                                )}
                              >
                                {done ? <Check className="size-3" strokeWidth={3} /> : i + 1}
                              </span>
                              {i < STAGES.length - 1 && (
                                <span className={cn('my-1 w-px flex-1 transition-colors', done ? 'bg-safe/50' : 'bg-border')} />
                              )}
                            </div>
                            <div className="pb-6">
                              <p
                                className={cn(
                                  'font-mono text-xs uppercase tracking-[0.16em] transition-colors',
                                  done || active ? 'text-foreground' : 'text-muted-foreground/60',
                                )}
                              >
                                {s.title}
                                {active && <span className="ml-2 inline-block size-1.5 rounded-full bg-infra tg-pulse" />}
                              </p>
                              <AnimatePresence>
                                {done && (
                                  <motion.p
                                    initial={{ opacity: 0, y: -4 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className="mt-1 text-sm text-safe"
                                  >
                                    ✓ {s.proof}
                                  </motion.p>
                                )}
                              </AnimatePresence>
                            </div>
                          </li>
                        )
                      })}
                    </ol>
                  </motion.div>
                )}

                {phase === 'done' && (
                  <motion.div key="done" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                    <h2 id="ingest-title" className="display mt-3 text-4xl sm:text-5xl">
                      Final verdict.
                    </h2>
                    <div className="mt-10 flex flex-col gap-6 rounded-2xl border border-border bg-background/40 p-8 sm:flex-row sm:items-end sm:justify-between">
                      <div>
                        <p className="eyebrow">{fileName}</p>
                        <p
                          className={cn(
                            'display mt-3 text-6xl sm:text-7xl',
                            scenario.verdict === 'CLEAN' ? 'text-safe' : 'text-critical',
                          )}
                        >
                          {scenario.verdict}
                        </p>
                      </div>
                      <div className="text-left sm:text-right">
                        <p className="eyebrow">Threat score</p>
                        <p className="mt-2 font-mono text-4xl">{scenario.score}%</p>
                      </div>
                    </div>
                    <div className="mt-8 flex flex-wrap gap-3">
                      <button
                        type="button"
                        onClick={openInvestigation}
                        className="rounded-full bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground"
                      >
                        Open Investigation →
                      </button>
                      <button
                        type="button"
                        onClick={reset}
                        className="rounded-full border border-border px-5 py-2.5 text-sm transition-colors hover:bg-surface-2"
                      >
                        Analyze another
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
