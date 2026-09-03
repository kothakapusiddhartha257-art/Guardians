import React, { createContext, useContext, useEffect, useState } from 'react';

export type Theme = 'obsidian' | 'forensic-paper' | 'deep-space' | 'midnight-violet';

export interface ThemeDefinition {
  id: Theme;
  name: string;
  tag: string;
  mode: 'dark' | 'light';
  description: string;
  bgHex: string;
  surfaceHex: string;
  accentHex: string;
  textHex: string;
}

export const THEMES: ThemeDefinition[] = [
  {
    id: 'obsidian',
    name: 'Obsidian Forensics',
    tag: 'Default SOC',
    mode: 'dark',
    description: 'Dark navy forensic cyber intelligence interface',
    bgHex: '#080B12',
    surfaceHex: '#111827',
    accentHex: '#4F8CFF',
    textHex: '#F5F1EA'
  },
  {
    id: 'forensic-paper',
    name: 'Forensic Paper',
    tag: 'Light Evidence Dossier',
    mode: 'light',
    description: 'Light court-grade digital evidence report',
    bgHex: '#F4F1EA',
    surfaceHex: '#FFFFFF',
    accentHex: '#2563EB',
    textHex: '#18202B'
  },
  {
    id: 'deep-space',
    name: 'Deep Space Intelligence',
    tag: 'Cyan Command Center',
    mode: 'dark',
    description: 'Deep blue intelligence platform with cyan accents',
    bgHex: '#050816',
    surfaceHex: '#0A1022',
    accentHex: '#38BDF8',
    textHex: '#E6EDF7'
  },
  {
    id: 'midnight-violet',
    name: 'Midnight Violet',
    tag: 'AI Horizon',
    mode: 'dark',
    description: 'Modern sophisticated dark violet intelligence interface',
    bgHex: '#0B0814',
    surfaceHex: '#151025',
    accentHex: '#9B8CFF',
    textHex: '#F5F3FF'
  }
];

interface ThemeContextType {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  currentThemeDef: ThemeDefinition;
  themes: ThemeDefinition[];
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const STORAGE_KEY = 'traceguard_theme';

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<Theme>(() => {
    const saved = localStorage.getItem(STORAGE_KEY) as string;
    // Map any legacy theme keys to new ones
    if (saved === 'theme-obsidian' || saved === 'obsidian') return 'obsidian';
    if (saved === 'theme-forensic-paper' || saved === 'forensic-paper') return 'forensic-paper';
    if (saved === 'theme-deep-space' || saved === 'deep-space') return 'deep-space';
    if (saved === 'theme-midnight-violet' || saved === 'midnight-violet') return 'midnight-violet';
    return 'obsidian';
  });

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme);
    localStorage.setItem(STORAGE_KEY, newTheme);
  };

  useEffect(() => {
    const root = document.documentElement;
    // Set both data-theme attribute and class on root HTML element
    root.setAttribute('data-theme', theme);
    root.className = `theme-${theme}`;

    const activeDef = THEMES.find((t) => t.id === theme) || THEMES[0];
    root.style.colorScheme = activeDef.mode;

    // Broadcast to chrome extension storage if running inside extension host
    const win = window as any;
    if (typeof win.chrome !== 'undefined' && win.chrome.storage && win.chrome.storage.local) {
      win.chrome.storage.local.set({ traceguard_theme: theme });
    }
  }, [theme]);

  const currentThemeDef = THEMES.find((t) => t.id === theme) || THEMES[0];

  return (
    <ThemeContext.Provider value={{ theme, setTheme, currentThemeDef, themes: THEMES }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
