'use client'

import { createContext, useCallback, useContext, useMemo, useState } from 'react'

interface IngestContextValue {
  open: boolean
  openIngest: () => void
  closeIngest: () => void
}

const IngestContext = createContext<IngestContextValue | null>(null)

export function IngestProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const openIngest = useCallback(() => setOpen(true), [])
  const closeIngest = useCallback(() => setOpen(false), [])
  const value = useMemo(() => ({ open, openIngest, closeIngest }), [open, openIngest, closeIngest])
  return <IngestContext.Provider value={value}>{children}</IngestContext.Provider>
}

export function useIngest() {
  const ctx = useContext(IngestContext)
  if (!ctx) throw new Error('useIngest must be used within IngestProvider')
  return ctx
}
