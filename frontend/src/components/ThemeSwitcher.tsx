import React, { useState, useRef, useEffect } from 'react';
import { Palette, Check, ChevronDown } from 'lucide-react';
import { useTheme, THEMES, Theme } from '../context/ThemeContext';

export const ThemeSwitcher: React.FC = () => {
  const { theme: currentTheme, setTheme, currentThemeDef } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surface hover:bg-surfaceElevated border border-border hover:border-borderStrong text-secondaryText hover:text-primaryText text-xs font-mono transition-all shadow-sm"
        title="Change Visual Theme"
      >
        <div className="flex items-center gap-1.5">
          <div className="flex -space-x-1 items-center">
            <span
              className="w-2.5 h-2.5 rounded-full border border-border"
              style={{ backgroundColor: currentThemeDef.bgHex }}
            />
            <span
              className="w-2.5 h-2.5 rounded-full border border-border"
              style={{ backgroundColor: currentThemeDef.accentHex }}
            />
          </div>
          <span className="hidden md:inline font-sans font-semibold text-xs text-primaryText">
            {currentThemeDef.name.split(' ')[0]}
          </span>
        </div>
        <ChevronDown className={`w-3 h-3 text-mutedText transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-72 rounded-2xl bg-surfaceElevated border border-borderStrong shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
          <div className="px-3 py-2 border-b border-border mb-1.5 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Palette className="w-3.5 h-3.5 text-primary" />
              <span className="eyebrow text-[10px]">Appearance Theme</span>
            </div>
            <span className="eyebrow text-[9px] text-mutedText">{currentThemeDef.mode.toUpperCase()}</span>
          </div>

          <div className="space-y-1">
            {THEMES.map((t) => {
              const isSelected = t.id === currentTheme;
              return (
                <button
                  key={t.id}
                  onClick={() => {
                    setTheme(t.id);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center justify-between p-2.5 rounded-xl text-left transition-all ${
                    isSelected
                      ? 'bg-surface border border-primary/50 text-primaryText shadow-sm'
                      : 'hover:bg-surface/60 text-secondaryText hover:text-primaryText border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    {/* Dual Color Swatch */}
                    <div
                      className="w-7 h-7 rounded-lg border border-borderStrong flex items-center justify-center flex-shrink-0 relative overflow-hidden shadow-inner"
                      style={{ backgroundColor: t.bgHex }}
                    >
                      <div
                        className="w-3.5 h-3.5 rounded-full shadow-md"
                        style={{ backgroundColor: t.accentHex }}
                      />
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-primaryText leading-none truncate">{t.name}</span>
                        {t.mode === 'light' && (
                          <span className="px-1 py-0.2 rounded text-[8px] font-mono bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                            Light
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-mutedText mt-0.5 truncate">{t.description}</div>
                    </div>
                  </div>

                  {isSelected && (
                    <div className="w-4 h-4 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 ml-2">
                      <Check className="w-3 h-3 text-primary" />
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
