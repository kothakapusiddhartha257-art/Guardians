'use client'

import { useEffect, useRef, useState } from 'react'
import { FEED_POOL, FEED_SEED, GATEWAY_METRICS, type FeedItem } from '@/lib/traceguard'

/**
 * Live gateway stream.
 * Connects to NEXT_PUBLIC_TRACEGUARD_WS when configured (expects JSON FeedItem frames),
 * otherwise simulates arrivals so the gateway stays alive in preview.
 */
export function useGatewayStream(maxItems = 8) {
  const [items, setItems] = useState<FeedItem[]>(FEED_SEED)
  const [metrics, setMetrics] = useState(GATEWAY_METRICS)
  const [connected, setConnected] = useState(false)
  const counter = useRef(483)

  useEffect(() => {
    const push = (item: FeedItem) => {
      setItems((prev) => [item, ...prev].slice(0, maxItems))
      setMetrics((m) => ({
        inbound: m.inbound + 1,
        quarantined: m.quarantined + (item.action === 'QUARANTINED' ? 1 : 0),
        flagged: m.flagged + (item.action === 'FLAGGED' ? 1 : 0),
        delivered: m.delivered + (item.action === 'DELIVERED' ? 1 : 0),
      }))
    }

    const url = process.env.NEXT_PUBLIC_TRACEGUARD_WS
    if (url) {
      const ws = new WebSocket(url)
      ws.onopen = () => setConnected(true)
      ws.onclose = () => setConnected(false)
      ws.onmessage = (e) => {
        try {
          push(JSON.parse(e.data) as FeedItem)
        } catch {
          // ignore malformed frames
        }
      }
      return () => ws.close()
    }

    setConnected(true)
    let poolIndex = 0
    const id = setInterval(() => {
      const base = FEED_POOL[poolIndex % FEED_POOL.length]
      poolIndex += 1
      counter.current += 1
      const now = new Date()
      push({
        ...base,
        id: `TG-2026-${String(counter.current).padStart(4, '0')}`,
        time: now.toTimeString().slice(0, 8),
      })
    }, 4200)
    return () => clearInterval(id)
  }, [maxItems])

  return { items, metrics, connected }
}
