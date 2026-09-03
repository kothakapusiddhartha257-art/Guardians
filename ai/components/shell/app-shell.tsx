'use client'

import { IngestProvider } from './ingest-context'
import { IngestModal } from './ingest-modal'
import { Nav } from './nav'
import { Footer } from './footer'

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <IngestProvider>
      <Nav />
      <main className="min-h-[calc(100vh-4rem)]">{children}</main>
      <Footer />
      <IngestModal />
    </IngestProvider>
  )
}
