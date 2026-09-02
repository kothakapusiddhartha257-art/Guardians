'use client'

import { motion } from 'framer-motion'
import { ComposableMap, Geographies, Geography, Line, Marker } from 'react-simple-maps'
import land from 'world-atlas/land-110m.json'

interface Point {
  name: string
  coords: [number, number]
}

export function GeoMap({ route, className, compact = false }: { route: Point[]; className?: string; compact?: boolean }) {
  return (
    <div className={className}>
      <ComposableMap
        projection="geoNaturalEarth1"
        projectionConfig={{ scale: compact ? 120 : 150, center: [30, 20] }}
        width={800}
        height={compact ? 360 : 420}
        style={{ width: '100%', height: 'auto' }}
        aria-label="World map showing the email infrastructure route"
      >
        <Geographies geography={land}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="var(--surface-2)"
                stroke="rgba(255,255,255,0.08)"
                strokeWidth={0.5}
                style={{ default: { outline: 'none' }, hover: { outline: 'none' }, pressed: { outline: 'none' } }}
              />
            ))
          }
        </Geographies>
        {route.slice(0, -1).map((p, i) => (
          <Line
            key={p.name}
            from={p.coords}
            to={route[i + 1].coords}
            stroke="var(--infra)"
            strokeWidth={1.25}
            strokeLinecap="round"
            className="tg-flow"
            style={{ animationDelay: `${i * 0.4}s` }}
          />
        ))}
        {route.map((p, i) => {
          const last = i === route.length - 1
          const origin = i === route.length - 2
          return (
            <Marker key={p.name} coordinates={p.coords}>
              <motion.circle
                r={origin ? 10 : 6}
                fill={origin ? 'var(--infra)' : 'var(--foreground)'}
                opacity={0.15}
                animate={{ r: origin ? [8, 16, 8] : [5, 9, 5] }}
                transition={{ duration: 2.4, repeat: Infinity, delay: i * 0.3 }}
              />
              <circle r={origin ? 3.5 : 2.5} fill={origin ? 'var(--infra)' : last ? 'var(--muted-foreground)' : 'var(--foreground)'} />
              <text
                textAnchor="start"
                x={8}
                y={4}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fill: 'var(--muted-foreground)', letterSpacing: 1 }}
              >
                {p.name.toUpperCase()}
              </text>
            </Marker>
          )
        })}
      </ComposableMap>
    </div>
  )
}
