/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        app: 'rgb(var(--bg-app-rgb) / <alpha-value>)',
        surface: 'rgb(var(--bg-surface-rgb) / <alpha-value>)',
        surfaceSecondary: 'rgb(var(--bg-surface-secondary-rgb) / <alpha-value>)',
        surfaceElevated: 'rgb(var(--bg-elevated-rgb) / <alpha-value>)',
        surfaceSubtle: 'rgb(var(--bg-surface-secondary-rgb) / <alpha-value>)',
        surfaceLight: 'rgb(var(--bg-elevated-rgb) / <alpha-value>)',
        background: 'rgb(var(--bg-app-rgb) / <alpha-value>)',

        border: 'rgb(var(--border-subtle-rgb) / <alpha-value>)',
        borderSubtle: 'rgb(var(--border-subtle-rgb) / <alpha-value>)',
        borderStrong: 'rgb(var(--border-strong-rgb) / <alpha-value>)',
        borderHover: 'rgb(var(--border-strong-rgb) / <alpha-value>)',
        
        primaryText: 'rgb(var(--text-primary-rgb) / <alpha-value>)',
        secondaryText: 'rgb(var(--text-secondary-rgb) / <alpha-value>)',
        mutedText: 'rgb(var(--text-muted-rgb) / <alpha-value>)',

        primary: 'rgb(var(--accent-primary-rgb) / <alpha-value>)',
        primaryDark: 'rgb(var(--accent-primary-dark-rgb) / <alpha-value>)',
        accent: 'rgb(var(--accent-secondary-rgb) / <alpha-value>)',
        accentSecondary: 'rgb(var(--accent-secondary-rgb) / <alpha-value>)',
        infra: 'rgb(var(--infra-rgb) / <alpha-value>)',
        attribution: 'rgb(var(--attribution-rgb) / <alpha-value>)',

        threatCritical: 'rgb(var(--threat-critical-rgb) / <alpha-value>)',
        threatHigh: 'rgb(var(--threat-high-rgb) / <alpha-value>)',
        threatWarning: 'rgb(var(--threat-warning-rgb) / <alpha-value>)',
        threatMedium: 'rgb(var(--threat-warning-rgb) / <alpha-value>)',
        threatLow: 'rgb(var(--threat-safe-rgb) / <alpha-value>)',
        threatSafe: 'rgb(var(--threat-safe-rgb) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        display: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      letterSpacing: {
        tightest: '-0.035em',
        tighter: '-0.025em',
        tight: '-0.015em',
        widest: '0.12em',
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'elevated': '0 8px 30px rgba(0, 0, 0, 0.25)',
        'glow-critical': '0 0 24px rgba(255, 92, 92, 0.25)',
        'glow-primary': '0 0 24px rgba(79, 140, 255, 0.25)',
      }
    },
  },
  plugins: [],
}
