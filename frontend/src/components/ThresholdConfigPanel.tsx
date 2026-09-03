import React, { useState, useEffect } from 'react';
import { X, Sliders, CheckCircle2, AlertTriangle, Save } from 'lucide-react';

interface ThresholdConfigPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

export const ThresholdConfigPanel: React.FC<ThresholdConfigPanelProps> = ({ isOpen, onClose, onSaved }) => {
  const [policy, setPolicy] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    fetch('/api/v1/mailboxes/policy')
      .then((res) => res.json())
      .then((data) => {
        setPolicy(data);
        setLoading(false);
      })
      .catch((e) => {
        console.error(e);
        setLoading(false);
      });
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async () => {
    setSaving(true);
    try {
      await fetch('/api/v1/mailboxes/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policy)
      });
      setSuccess(true);
      if (onSaved) onSaved();
      setTimeout(() => {
        setSuccess(false);
        onClose();
      }, 700);
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  const toggleOverrideRule = (ruleId: string) => {
    if (!policy) return;
    const updated = policy.active_override_rules.map((r: any) =>
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r
    );
    setPolicy({ ...policy, active_override_rules: updated });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-surfaceElevated border border-border rounded-3xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border/70 bg-surfaceSubtle">
          <div className="flex items-center gap-3">
            <div className="size-9 rounded-xl bg-primary/15 flex items-center justify-center text-primary">
              <Sliders className="size-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-primaryText">Response Policy & Sensitivity Thresholds</h2>
              <p className="eyebrow text-[10px] text-mutedText">Autonomous Action Tiers & Overrides</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-xl text-mutedText hover:text-primaryText hover:bg-surface transition-colors">
            <X className="size-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {loading ? (
            <div className="py-8 text-center text-xs font-mono text-mutedText">Loading policy parameters...</div>
          ) : (
            <>
              {/* Threshold Tiers */}
              <div className="space-y-3">
                <label className="eyebrow block">
                  Action Severity Thresholds
                </label>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 rounded-2xl bg-threatSafe/10 border border-threatSafe/25 space-y-1">
                    <span className="font-bold text-threatSafe block">DELIVER (Safe)</span>
                    <span className="font-mono text-secondaryText">0% – 39% Threat Score</span>
                  </div>

                  <div className="p-3.5 rounded-2xl bg-threatMedium/10 border border-threatMedium/25 space-y-1">
                    <span className="font-bold text-threatMedium block">FLAG (Low Risk)</span>
                    <span className="font-mono text-secondaryText">40% – 59% Threat Score</span>
                  </div>

                  <div className="p-3.5 rounded-2xl bg-threatHigh/10 border border-threatHigh/25 space-y-1">
                    <span className="font-bold text-threatHigh block">FLAG / CAUTION</span>
                    <span className="font-mono text-secondaryText">60% – 79% Threat Score</span>
                  </div>

                  <div className="p-3.5 rounded-2xl bg-threatCritical/10 border border-threatCritical/25 space-y-1">
                    <span className="font-bold text-threatCritical block">QUARANTINE (Malicious)</span>
                    <span className="font-mono text-secondaryText">80% – 100% Threat Score</span>
                  </div>
                </div>
              </div>

              {/* Catastrophic Override Rules */}
              <div className="space-y-3 pt-4 border-t border-border/60">
                <div className="flex items-center justify-between">
                  <div>
                    <label className="eyebrow block">
                      Catastrophic Override Rules
                    </label>
                    <p className="text-[11px] text-secondaryText">
                      Isolates email on single fatal indicator regardless of score dilution
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={policy?.enable_overrides ?? true}
                    onChange={(e) => setPolicy({ ...policy, enable_overrides: e.target.checked })}
                    className="size-4 accent-primary rounded cursor-pointer"
                  />
                </div>

                <div className="space-y-2.5">
                  {policy?.active_override_rules?.map((rule: any) => (
                    <div
                      key={rule.id}
                      onClick={() => toggleOverrideRule(rule.id)}
                      className={`p-3.5 rounded-2xl border cursor-pointer transition-all flex items-start justify-between gap-3 ${
                        rule.enabled
                          ? 'bg-surface border-primary/40'
                          : 'bg-surfaceSubtle/50 border-border/50 opacity-60'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-primaryText">{rule.id}: {rule.name}</span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-extrabold bg-threatCritical/20 text-threatCritical">
                            {rule.min_action}
                          </span>
                        </div>
                        <p className="text-[11px] font-mono text-mutedText">{rule.condition}</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => {}}
                        className="size-4 accent-primary rounded mt-0.5"
                      />
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border/70 bg-surfaceSubtle flex items-center justify-between">
          {success ? (
            <span className="text-xs font-bold text-threatSafe flex items-center gap-1.5">
              <CheckCircle2 className="size-4" /> Policy Parameters Updated!
            </span>
          ) : <span />}
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:text-primaryText transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-lg shadow-primary/25 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center gap-2"
            >
              <Save className="size-4" />
              <span>Apply Policy Parameters</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
