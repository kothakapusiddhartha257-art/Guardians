import React from 'react';
import { CheckCircle2, Chrome, ExternalLink, Puzzle, ShieldCheck } from 'lucide-react';

const steps = [
  ['Open Extensions', 'In Chrome, Edge, or Brave, open chrome://extensions in a new tab.'],
  ['Enable Developer mode', 'Turn on Developer mode using the switch in the top-right corner.'],
  ['Load the folder', 'Click Load unpacked and select D:\\p-1\\extension.'],
  ['Pin TRACEGUARD', 'Pin TRACEGUARD AI from the browser extensions menu, then open Gmail.'],
  ['Inspect an email', 'Open an email and use the TRACEGUARD panel to request its read-only analysis.'],
];

export const ExtensionSetup: React.FC = () => (
  <div className="p-6 sm:p-8 max-w-6xl mx-auto space-y-7 animate-in fade-in duration-300">
    <section className="rounded-3xl border border-border bg-surface shadow-xl p-7 sm:p-10 overflow-hidden relative">
      <div className="absolute -right-16 -top-16 size-64 rounded-full bg-primary/10 blur-3xl" />
      <div className="relative grid lg:grid-cols-[1.15fr_.85fr] gap-8 items-center">
        <div><div className="inline-flex items-center gap-2 text-primary eyebrow"><Puzzle className="size-4" /> Browser extension</div><h1 className="mt-3 text-4xl font-black text-primaryText">Add TRACEGUARD to Gmail</h1><p className="mt-3 max-w-xl text-secondaryText leading-relaxed">See a threat verdict and investigation context while reading an email. The extension sends the email to your local TRACEGUARD analysis service only when you ask it to inspect.</p></div>
        <div className="rounded-2xl border border-primary/20 bg-primary/5 p-6 space-y-3"><Chrome className="size-9 text-primary" /><h2 className="font-bold text-primaryText">Chromium browsers supported</h2><p className="text-sm text-secondaryText">Chrome, Microsoft Edge and Brave can load this local development extension.</p><div className="text-xs font-mono text-primaryText bg-surface px-3 py-2 rounded-lg border border-border">D:\\p-1\\extension</div></div>
      </div>
    </section>
    <section className="rounded-3xl border border-border bg-surface p-7 sm:p-8"><div className="flex items-center gap-3 mb-7"><ShieldCheck className="size-6 text-threatSafe" /><div><h2 className="text-2xl font-black text-primaryText">Install in five steps</h2><p className="text-sm text-mutedText mt-1">You only need to do this once on this computer.</p></div></div><div className="grid md:grid-cols-2 xl:grid-cols-5 gap-4">{steps.map(([heading, description], index) => <article key={heading} className="p-5 rounded-2xl bg-surfaceSubtle border border-border min-h-48"><div className="size-8 rounded-full bg-primary text-white flex items-center justify-center text-sm font-black">{index + 1}</div><h3 className="mt-5 font-bold text-primaryText">{heading}</h3><p className="mt-2 text-sm text-secondaryText leading-relaxed">{description}</p></article>)}</div></section>
    <section className="rounded-2xl border border-threatSafe/30 bg-threatSafe/5 px-6 py-5 flex flex-col sm:flex-row gap-4 sm:items-center sm:justify-between"><div className="flex gap-3"><CheckCircle2 className="size-5 shrink-0 mt-0.5 text-threatSafe" /><p className="text-sm text-secondaryText"><strong className="text-primaryText">Before opening Gmail:</strong> keep the TRACEGUARD backend running at <code className="font-mono text-primary">127.0.0.1:8000</code>. The extension is configured to reach the local service.</p></div><a href="chrome://extensions" className="inline-flex shrink-0 items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-primary text-white font-bold text-sm"><ExternalLink className="size-4" /> Open Extensions</a></section>
  </div>
);
