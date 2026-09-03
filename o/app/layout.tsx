import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { Geist, Geist_Mono, Instrument_Serif } from 'next/font/google'
import { AppShell } from '@/components/shell/app-shell'
import './globals.css'

const geist = Geist({ subsets: ['latin'], variable: '--font-geist' })
const geistMono = Geist_Mono({ subsets: ['latin'], variable: '--font-geist-mono' })
const instrument = Instrument_Serif({
  subsets: ['latin'],
  weight: '400',
  style: ['normal', 'italic'],
  variable: '--font-instrument',
})

export const metadata: Metadata = {
  title: 'TRACEGUARD AI — Autonomous Email Defense',
  description:
    'AI-powered email threat detection, autonomous email gateway, geolocation and digital forensic intelligence platform. Every email leaves a trail.',
  generator: 'v0.app',
  icons: { icon: [{ url: '/icon.svg', type: 'image/svg+xml' }] },
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#080B12',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      className={`bg-background ${geist.variable} ${geistMono.variable} ${instrument.variable}`}
    >
      <body className="antialiased">
        <AppShell>{children}</AppShell>
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
