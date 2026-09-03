import React, { useState } from 'react';
import { X, Sparkles, ShieldAlert, ShieldCheck, FileCode, CheckCircle2, ArrowRight, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface DemoScenarioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const DemoScenarioModal: React.FC<DemoScenarioModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const { enterDemo } = useAuth();
  const [selectedScenario, setSelectedScenario] = useState('bec_wire_transfer');
  const [isLaunching, setIsLaunching] = useState(false);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'bec_wire_transfer',
      badge: 'HIGH SEVERITY',
      badgeColor: 'text-threatCritical bg-threatCritical/10 border-threatCritical/30',
      title: 'Business Email Compromise (BEC) Wire Fraud',
      desc: 'CEO executive spoof requesting emergency $50,000 wire transfer with Reply-To domain manipulation.',
      threat: 'CRITICAL / 94%'
    },
    {
      id: 'credential_harvesting',
      badge: 'CREDENTIAL PHISH',
      badgeColor: 'text-threatHigh bg-threatHigh/10 border-threatHigh/30',
      title: 'Microsoft 365 Zero-Point Phishing',
      desc: 'Lookalike login portal with homoglyph brand spoofing and DMARC authentication rejection.',
      threat: 'SUSPICIOUS / 82%'
    },
    {
      id: 'malware_executable',
      badge: 'BINARY PAYLOAD',
      badgeColor: 'text-threatCritical bg-threatCritical/10 border-threatCritical/30',
      title: 'Invoice Masqueraded Executable Malware',
      desc: 'Windows PE binary disguised as Invoice_9921.pdf with bulletproof hosting relay.',
      threat: 'CRITICAL / 96%'
    },
    {
      id: 'clean_newsletter',
      badge: 'VERIFIED BENIGN',
      badgeColor: 'text-threatSafe bg-threatSafe/10 border-threatSafe/30',
      title: 'Enterprise Cloud Security Advisory',
      desc: 'Cryptographically authenticated corporate security digest passing SPF, DKIM, and DMARC.',
      threat: 'SAFE / 4%'
    }
  ];

  const handleLaunch = async () => {
    setIsLaunching(true);
    try {
      await enterDemo(selectedScenario);
      onSuccess();
      onClose();
    } catch (e) {
      console.error(e);
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-xl rounded-3xl bg-surface border border-border shadow-2xl p-6 sm:p-8 space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-border/80">
          <div className="flex items-center gap-3">
            <span className="p-2.5 rounded-xl bg-primary/10 text-primary border border-primary/20">
              <Sparkles className="size-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="eyebrow text-[10px] text-primary">Simulation Sandbox</span>
                <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-primary/20 text-primary border border-primary/30">
                  DEMO MODE
                </span>
              </div>
              <h2 className="text-xl font-black text-primaryText tracking-tight">Select Demo Scenario</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-secondaryText hover:text-primaryText hover:bg-surfaceSubtle transition-colors"
          >
            <X className="size-5" />
          </button>
        </div>

        <p className="text-xs text-secondaryText leading-relaxed">
          No external credentials required. Evaluates simulated high-fidelity RFC822 forensic payloads directly in the 11-stage analysis DAG.
        </p>

        {/* Scenarios Grid */}
        <div className="space-y-3">
          {scenarios.map((sc) => {
            const isSelected = selectedScenario === sc.id;
            return (
              <div
                key={sc.id}
                onClick={() => setSelectedScenario(sc.id)}
                className={`p-4 rounded-2xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-surfaceElevated border-primary shadow-md shadow-primary/10 ring-1 ring-primary'
                    : 'bg-surfaceSubtle border-border hover:border-border/80 hover:bg-surfaceElevated'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded-md text-[9px] font-mono font-bold border ${sc.badgeColor}`}>
                        {sc.badge}
                      </span>
                      <h4 className="text-sm font-bold text-primaryText">{sc.title}</h4>
                    </div>
                    <p className="text-xs text-secondaryText">{sc.desc}</p>
                  </div>
                  <span className="font-mono text-xs font-bold text-primaryText shrink-0 pt-0.5">
                    {sc.threat}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-border/80">
          <span className="text-[11px] font-mono text-mutedText">
            Instant Seeded Evaluation
          </span>
          <button
            onClick={handleLaunch}
            disabled={isLaunching}
            className="px-6 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-lg shadow-primary/20 transition-all flex items-center gap-2 disabled:opacity-50"
          >
            {isLaunching ? <Loader2 className="size-3.5 animate-spin" /> : <ArrowRight className="size-3.5" />}
            <span>Launch Demo Environment</span>
          </button>
        </div>

      </div>
    </div>
  );
};
