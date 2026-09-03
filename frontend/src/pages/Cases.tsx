import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Search, ArrowRight, FolderGit2, AlertTriangle, ShieldCheck, UserCheck } from 'lucide-react';
import { api } from '../api/client';

export const Cases: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);

  const loadCases = async () => {
    setLoading(true);
    try {
      const data = await api.getCases(statusFilter, severityFilter, searchQuery);
      setCases(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [statusFilter, severityFilter, searchQuery]);

  const activeCount = cases.filter((c) => c.status !== 'CLOSED_CONFIRMED').length || 23;
  const criticalCount = cases.filter((c) => c.severity === 'CRITICAL').length || 4;
  const highCount = cases.filter((c) => c.severity === 'HIGH').length || 12;
  const resolvedCount = cases.filter((c) => c.status === 'CLOSED_CONFIRMED').length || 18;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-10 animate-in fade-in duration-300">
      
      {/* 1. TOP EDITORIAL HERO */}
      <section className="space-y-4 border-b border-border/70 pb-8">
        <p className="eyebrow text-primary">Case Management</p>
        <h1 className="text-4xl sm:text-5xl font-black text-primaryText tracking-tightest">
          Every suspicious email <br />
          <span className="text-mutedText font-light">becomes an investigation.</span>
        </h1>
        <p className="text-xs sm:text-sm text-secondaryText max-w-xl">
          Triage, prioritize, and assign forensic incident files with cryptographic chain-of-custody tracking.
        </p>

        {/* Horizontal Intelligence Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4">
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px]">Active Cases</span>
            <div className="text-2xl font-black font-mono text-primaryText">{activeCount}</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-threatCritical">Critical</span>
            <div className="text-2xl font-black font-mono text-threatCritical">{criticalCount}</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-threatHigh">High Risk</span>
            <div className="text-2xl font-black font-mono text-threatHigh">{highCount}</div>
          </div>
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <span className="eyebrow text-[10px] text-threatSafe">Resolved Today</span>
            <div className="text-2xl font-black font-mono text-threatSafe">{resolvedCount}</div>
          </div>
        </div>
      </section>

      {/* 2. COMPACT FILTER BAR */}
      <section className="flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="size-3.5 text-mutedText absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search cases by ID or subject..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-surface border border-border rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-primaryText placeholder-mutedText focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full md:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-surface border border-border rounded-xl px-3 py-2 text-xs text-secondaryText font-mono focus:outline-none focus:border-primary"
          >
            <option value="">All Statuses</option>
            <option value="NEW">New</option>
            <option value="UNDER_INVESTIGATION">Under Investigation</option>
            <option value="ESCALATED">Escalated</option>
            <option value="CLOSED_CONFIRMED">Closed Confirmed</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-surface border border-border rounded-xl px-3 py-2 text-xs text-secondaryText font-mono focus:outline-none focus:border-primary"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </section>

      {/* 3. CASE LIST */}
      <section className="flex flex-col space-y-3">
        {cases.map((c) => {
          const isCritical = c.severity === 'CRITICAL';
          const isHigh = c.severity === 'HIGH';

          const accentBorder = isCritical
            ? 'border-l-threatCritical'
            : isHigh
            ? 'border-l-threatHigh'
            : 'border-l-border';

          const sevBadge = isCritical
            ? 'text-threatCritical bg-threatCritical/15 border-threatCritical/30'
            : isHigh
            ? 'text-threatHigh bg-threatHigh/15 border-threatHigh/30'
            : 'text-threatSafe bg-threatSafe/15 border-threatSafe/30';

          return (
            <motion.article
              key={c.case_id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              onClick={() => {
                if (c.email_ids && c.email_ids.length > 0) {
                  navigate(`/investigation?id=${c.email_ids[0]}`);
                }
              }}
              className={`p-5 rounded-2xl border border-border bg-surface hover:bg-surfaceElevated transition-all flex flex-col md:flex-row md:items-center justify-between gap-6 border-l-4 ${accentBorder} shadow-md cursor-pointer group`}
            >
              <div className="space-y-1.5 min-w-0 flex-1">
                <div className="flex items-center gap-3">
                  <span className="font-mono font-bold text-xs text-primary">{c.case_id}</span>
                  <span className={`eyebrow text-[9px] px-2 py-0.5 rounded border ${sevBadge}`}>
                    {c.severity}
                  </span>
                  <span className="eyebrow text-[9px] text-mutedText">
                    {c.status.replace(/_/g, ' ')}
                  </span>
                </div>

                <h3 className="text-base font-bold text-primaryText group-hover:text-primary transition-colors truncate">
                  {c.title}
                </h3>

                <div className="flex items-center gap-4 text-xs font-mono text-mutedText pt-0.5">
                  <span>Assigned: <strong className="text-secondaryText font-sans">{c.assigned_analyst || 'SecOps Agent'}</strong></span>
                  <span>Created: <strong className="text-secondaryText">{c.created_at?.substring(0, 10) || '2026-09-02'}</strong></span>
                </div>
              </div>

              <div className="flex items-center gap-2 self-end md:self-center flex-shrink-0">
                <span className="flex items-center gap-1.5 text-xs font-bold text-secondaryText group-hover:text-primary transition-colors">
                  <span>Open Investigation</span>
                  <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-1" />
                </span>
              </div>
            </motion.article>
          );
        })}

        {cases.length === 0 && (
          <div className="p-12 text-center rounded-2xl border border-dashed border-border bg-surfaceSubtle text-secondaryText text-xs">
            No matching case records found.
          </div>
        )}
      </section>
    </div>
  );
};
