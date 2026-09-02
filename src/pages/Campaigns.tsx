import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Share2, GitBranch, Calendar, ShieldAlert, ArrowRight, Server, Globe, Mail, Link2 } from 'lucide-react';

export const Campaigns: React.FC = () => {
  const navigate = useNavigate();
  const [selectedCampaign, setSelectedCampaign] = useState<any | null>(null);

  const campaigns = [
    {
      id: 'CAMPAIGN-2026-0001',
      name: 'Operation Apex Wire Divert (BEC)',
      threat_type: 'BUSINESS_EMAIL_COMPROMISE',
      severity: 'CRITICAL',
      first_seen: 'Aug 10',
      last_seen: 'Aug 31',
      email_count: 5,
      ip: '185.23.11.4 (Alexhost Bulletproof)',
      domain: 'secure-exchange-transfer.xyz',
      subject_pattern: 'URGENT: Vendor Payment Account Change',
      desc: 'Targeted spear-phishing campaign impersonating corporate executives demanding urgent wire payments to escrow intermediaries.'
    },
    {
      id: 'CAMPAIGN-2026-0002',
      name: 'Global M365 Credential Harvester',
      threat_type: 'CREDENTIAL_HARVESTING',
      severity: 'HIGH',
      first_seen: 'Aug 18',
      last_seen: 'Aug 31',
      email_count: 12,
      ip: '194.26.29.112 (M247 VPN Node)',
      domain: 'm365-security-update.top',
      subject_pattern: 'Action Required: Your Office 365 Password Expires Today',
      desc: 'Phishing infrastructure leveraging deceptive anchor text and fake password expiration alerts to steal corporate OAuth tokens.'
    },
    {
      id: 'CAMPAIGN-2026-0003',
      name: 'Invoice EXE Disguise Campaign',
      threat_type: 'MALWARE_DISTRIBUTION',
      severity: 'HIGH',
      first_seen: 'Aug 22',
      last_seen: 'Aug 31',
      email_count: 8,
      ip: '185.220.101.5 (TOR Exit Node)',
      domain: 'overdue-billing-notice.xyz',
      subject_pattern: 'Overdue Invoice #88219 - Final Notice Before Legal Action',
      desc: 'Trojanized document delivery campaign using double extensions and high-entropy packed executable payloads.'
    }
  ];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-12 animate-in fade-in duration-300">
      
      {/* 1. TOP EDITORIAL HERO */}
      <section className="space-y-4 border-b border-border/70 pb-8">
        <p className="eyebrow text-primary">Campaign Intelligence</p>
        <h1 className="text-4xl sm:text-5xl font-black text-primaryText tracking-tightest">
          Attacks rarely <br />
          <span className="text-mutedText font-light">travel alone.</span>
        </h1>
        <p className="text-xs sm:text-sm text-secondaryText max-w-xl">
          TRACEGUARD identifies and clusters shared bulletproof infrastructure, domain patterns, and cryptographic IOCs across independent investigations.
        </p>

        {/* Horizontal Intelligence Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4">
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px]">Active Campaigns</span>
            <div className="text-2xl font-black font-mono text-primaryText">12</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-threatCritical">Critical Clusters</span>
            <div className="text-2xl font-black font-mono text-threatCritical">2</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-attribution">Linked Inbound Emails</span>
            <div className="text-2xl font-black font-mono text-attribution">48</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-infra">Shared IOCs</span>
            <div className="text-2xl font-black font-mono text-infra">87</div>
          </div>
        </div>
      </section>

      {/* 2. CAMPAIGN INFRASTRUCTURE CARDS */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {campaigns.map((c) => {
          const isCritical = c.severity === 'CRITICAL';
          return (
            <motion.article
              key={c.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-7 rounded-3xl border border-border bg-surface hover:bg-surfaceElevated transition-all flex flex-col justify-between space-y-6 shadow-xl relative overflow-hidden group"
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="eyebrow text-primary text-[10px]">{c.id}</span>
                  <span className={`eyebrow text-[9px] px-2.5 py-0.5 rounded-full border ${
                    isCritical
                      ? 'text-threatCritical bg-threatCritical/15 border-threatCritical/30'
                      : 'text-threatHigh bg-threatHigh/15 border-threatHigh/30'
                  }`}>
                    {c.severity}
                  </span>
                </div>

                <h2 className="text-lg font-bold text-primaryText leading-snug">
                  {c.name}
                </h2>

                <p className="text-xs text-secondaryText leading-relaxed">
                  {c.desc}
                </p>

                {/* Visual Connected IOC Flow */}
                <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/70 space-y-2.5 font-mono text-xs">
                  <span className="eyebrow text-[9px] text-mutedText block">Connected Infrastructure Flow:</span>
                  
                  <div className="flex items-center gap-2 text-primaryText">
                    <Server className="size-3.5 text-infra flex-shrink-0" />
                    <span className="truncate">{c.ip}</span>
                  </div>
                  <div className="ml-1 text-mutedText text-[10px]">&darr;</div>

                  <div className="flex items-center gap-2 text-primaryText">
                    <Globe className="size-3.5 text-threatHigh flex-shrink-0" />
                    <span className="truncate">{c.domain}</span>
                  </div>
                  <div className="ml-1 text-mutedText text-[10px]">&darr;</div>

                  <div className="flex items-center gap-2 text-secondaryText">
                    <Mail className="size-3.5 text-attribution flex-shrink-0" />
                    <span className="truncate font-sans font-medium">{c.subject_pattern}</span>
                  </div>
                </div>
              </div>

              {/* Timeline & Actions */}
              <div className="pt-4 border-t border-border/60 space-y-4">
                <div className="flex items-center justify-between text-xs font-mono text-mutedText">
                  <div className="flex items-center gap-1.5">
                    <Calendar className="size-3.5" />
                    <span>{c.first_seen} ──────── {c.last_seen}</span>
                  </div>
                  <span className="text-primaryText font-bold">{c.email_count} Linked Emails</span>
                </div>

                <button
                  onClick={() => navigate('/investigation?id=email-bec-demo&tab=graph')}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-surfaceSubtle hover:bg-primary group-hover:text-white text-secondaryText text-xs font-bold transition-all border border-border group-hover:border-transparent"
                >
                  <span>Explore Campaign Graph</span>
                  <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-1" />
                </button>
              </div>
            </motion.article>
          );
        })}
      </section>
    </div>
  );
};
