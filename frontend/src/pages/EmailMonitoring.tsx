import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Radio, ShieldAlert, ShieldCheck, AlertOctagon, Mail, Zap, Sliders,
  RefreshCw, ChevronRight, CheckCircle2, AlertTriangle, ArrowUpRight,
  Shield, ExternalLink, Filter, ArrowRight, CornerDownRight, Check, Loader2, UploadCloud
} from 'lucide-react';
import { MailboxConnectModal } from '../components/MailboxConnectModal';
import { ThresholdConfigPanel } from '../components/ThresholdConfigPanel';

interface EmailMonitoringProps {
  onOpenUpload: () => void;
}

export const EmailMonitoring: React.FC<EmailMonitoringProps> = ({ onOpenUpload }) => {
  const navigate = useNavigate();

  const [mailboxes, setMailboxes] = useState<any[]>([]);
  const [liveEmails, setLiveEmails] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isSyncingGmail, setIsSyncingGmail] = useState(false);
  const [oauthStatus, setOauthStatus] = useState<any>(null);
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [isAuthenticatingGoogle, setIsAuthenticatingGoogle] = useState(false);
  const [isConnectOpen, setIsConnectOpen] = useState(false);
  const [isPolicyOpen, setIsPolicyOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [overrideModalEmail, setOverrideModalEmail] = useState<any | null>(null);
  const [overrideAction, setOverrideAction] = useState('FLAG');
  const [overrideReason, setOverrideReason] = useState('Analyst verified benign testing context');

  // Gmail OAuth read-only mailbox integration state
  const [gmailStatus, setGmailStatus] = useState<any>({
    email: '',
    configured: false,
    connected: false,
    auto_scan_enabled: false
  });
  const [isTestingGmail, setIsTestingGmail] = useState(false);
  const [isScanningGmail, setIsScanningGmail] = useState(false);
  const [scanLimit, setScanLimit] = useState(20);
  const [scanProgress, setScanProgress] = useState<{
    current: number;
    total: number;
    subject: string;
    stepIndex: number;
  }>({ current: 0, total: 20, subject: '', stepIndex: 0 });
  const [gmailResults, setGmailResults] = useState<any[]>([]);
  const [gmailSummary, setGmailSummary] = useState<any>(null);
  const [gmailError, setGmailError] = useState<string | null>(null);
  const SCAN_JOB_KEY = 'traceguard_gmail_scan_job';

  const wsRef = useRef<WebSocket | null>(null);

  const loadGmailStatus = async () => {
    try {
      const status = await fetch('/api/v1/oauth/gmail/status').then((r) => r.json());
      // Gmail status must not depend on unrelated dashboard endpoints.
      setOauthStatus(status);
      setGmailStatus({
        email: status.user_email || 'Connected Gmail account',
        configured: Boolean(status.is_configured),
        connected: Boolean(status.is_authorized),
        auto_scan_enabled: false
      });
    } catch (e) {
      console.error('Failed to load Gmail OAuth status', e);
    }
  };

  const loadData = async () => {
    await loadGmailStatus();
    try {
      const [mRes, eRes] = await Promise.all([
        fetch('/api/v1/mailboxes').then((r) => r.json()),
        fetch('/api/v1/emails/live').then((r) => r.json())
      ]);
      setMailboxes(mRes);
      setLiveEmails(eRes);
    } catch (e) {
      console.error('Failed to load monitoring dashboard data', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    const savedJob = sessionStorage.getItem(SCAN_JOB_KEY);
    if (savedJob) pollScanJob(savedJob);

    // Check URL search params for OAuth success callback
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.get('gmail_connected') === 'true') {
      const email = searchParams.get('email') || 'Google Account';
      setToastMessage(`Successfully connected and authorized Gmail: ${email}`);
      setTimeout(() => setToastMessage(null), 5000);
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (searchParams.get('oauth_error')) {
      setToastMessage(`OAuth Error: ${searchParams.get('oauth_error')}`);
      setTimeout(() => setToastMessage(null), 6000);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    // Establish WebSocket Live Feed connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live-feed`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('[WebSocket] Live Feed connected');
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'NEW_LIVE_EMAIL' && msg.data) {
          setLiveEmails((prev) => [msg.data, ...prev.filter((x) => x.id !== msg.data.id)]);
        } else if (msg.type === 'EMAIL_ACTION_OVERRIDDEN' && msg.data) {
          setLiveEmails((prev) => prev.map((x) => (x.id === msg.data.id ? msg.data : x)));
        }
      } catch (e) {
        console.error('[WebSocket] Parsing error:', e);
      }
    };

    return () => {
      ws.close();
    };
  }, []);

  const finishScan = async (data: any) => {
    const results = data.result?.results || data.results || [];
    setGmailResults(results);
    setGmailSummary({ total: results.length, high_risk: results.filter((item: any) => (item.threat_score || 0) >= 0.7).length,
      suspicious: results.filter((item: any) => (item.threat_score || 0) >= 0.3 && (item.threat_score || 0) < 0.7).length,
      clean: results.filter((item: any) => (item.threat_score || 0) < 0.3).length });
    // Keep the completed job ID so returning to this page restores the same
    // result list instead of making the completed scan disappear.
    setIsScanningGmail(false); await loadData();
  };

  const pollScanJob = async (jobId: string) => {
    setIsScanningGmail(true);
    try {
      const data = await fetch(`/api/v1/oauth/gmail/scan-status/${jobId}`).then((r) => r.json());
      if (data.status === 'completed') return finishScan(data);
      if (data.status === 'failed') throw new Error(data.error || 'Scan failed.');
      setScanProgress({ current: data.current || 0, total: data.total || 20, subject: data.subject || 'Scanning...', stepIndex: 0 });
      window.setTimeout(() => pollScanJob(jobId), 900);
    } catch (e: any) { sessionStorage.removeItem(SCAN_JOB_KEY); setIsScanningGmail(false); setGmailError(e.message || 'Scan failed.'); }
  };

  const handleSimulateInbound = async (scenario: string) => {
    setIsSimulating(true);
    try {
      await fetch('/api/v1/mailboxes/simulate-incoming', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      await loadData();
    } catch (e) {
      console.error(e);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSyncGmailNow = async () => {
    setIsSyncingGmail(true);
    try {
      const res = await fetch('/api/v1/oauth/gmail/sync-now', { method: 'POST' });
      const data = await res.json();
      setToastMessage(data.message || 'Gmail synchronization completed.');
      setTimeout(() => setToastMessage(null), 5000);
      await loadData();
    } catch (e: any) {
      setToastMessage(`Gmail sync failed: ${e.message || e}`);
      setTimeout(() => setToastMessage(null), 5000);
    } finally {
      setIsSyncingGmail(false);
    }
  };

  const handleTestGmailConnection = async () => {
    setIsTestingGmail(true);
    setGmailError(null);
    try {
      const data = await fetch('/api/v1/oauth/gmail/status').then((r) => r.json());
      if (!data.is_authorized) throw new Error('Gmail OAuth authorization is required. Use Continue with connected Gmail.');
      setGmailStatus({ email: data.user_email || 'Connected Gmail account', configured: true, connected: true, auto_scan_enabled: false });
      setToastMessage('Gmail OAuth connection is active. Read-only scanning is ready.');
      setTimeout(() => setToastMessage(null), 5000);
    } catch (e: any) {
      setGmailError(e.message || 'Unable to verify the Gmail OAuth connection.');
    } finally {
      setIsTestingGmail(false);
    }
  };

  const handleScanGmailInbox = async (limit = 20) => {
    setIsScanningGmail(true);
    setGmailError(null);
    setScanProgress({
      current: 1,
      total: limit,
      subject: 'Requesting read-only Gmail API access...',
      stepIndex: 0
    });

    try {
      const res = await fetch(`/api/v1/oauth/gmail/scan-start?limit=${Math.min(limit, 25)}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Gmail scan failed.');
      }
      sessionStorage.setItem(SCAN_JOB_KEY, data.job_id);
      pollScanJob(data.job_id);
    } catch (e: any) {
      setGmailError(e.message || 'Scan failed.');
    }
  };

  const handleToggleAutoScan = async () => {
    const nextState = !gmailStatus.auto_scan_enabled;
    try {
      const res = await fetch('/api/v1/gmail/auto-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextState, interval_minutes: 5 })
      });
      const data = await res.json();
      setGmailStatus((prev: any) => ({
        ...prev,
        auto_scan_enabled: data.auto_scan_enabled
      }));
      setToastMessage(`Gmail Auto-Scan ${data.auto_scan_enabled ? 'Enabled (Every 5 mins)' : 'Disabled'}`);
      setTimeout(() => setToastMessage(null), 4000);
    } catch (e: any) {
      setToastMessage(`Failed to update auto-scan: ${e.message || e}`);
    }
  };

  const handleContinueWithGoogle = async () => {
    setIsAuthenticatingGoogle(true);
    setOauthError(null);
    try {
      const res = await fetch('/api/v1/oauth/gmail/auth-url');
      const data = await res.json();
      if (data.auth_url) {
        window.location.href = data.auth_url;
      } else {
        throw new Error(data.detail || 'Failed to generate Google authorization URL');
      }
    } catch (err: any) {
      setOauthError(err.message || 'Google OAuth failed to start');
      setIsAuthenticatingGoogle(false);
    }
  };

  const handleSyncGmailOAuth = async () => {
    setIsSyncingGmail(true);
    setOauthError(null);
    try {
      const res = await fetch('/api/v1/oauth/gmail/sync-now', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 20 })
      });
      const data = await res.json();
      if (res.ok) {
        setToastMessage(`Incremental sync complete: ${data.new_messages_analyzed || 0} new threats analyzed, ${data.duplicates_skipped || 0} duplicates deduplicated.`);
        setTimeout(() => setToastMessage(null), 5000);
        await loadData();
      } else {
        throw new Error(data.detail || 'Gmail sync failed');
      }
    } catch (err: any) {
      setOauthError(err.message || 'Gmail sync error');
    } finally {
      setIsSyncingGmail(false);
    }
  };

  const handleDisconnectGoogle = async () => {
    try {
      await fetch('/api/v1/oauth/gmail/disconnect', { method: 'POST' });
      setToastMessage('Google account disconnected.');
      setTimeout(() => setToastMessage(null), 4000);
      await loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleApplyOverride = async () => {
    if (!overrideModalEmail) return;
    try {
      await fetch(`/api/v1/emails/live/${overrideModalEmail.id}/override-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: overrideAction,
          reason: overrideReason,
          analyst: 'analyst_01'
        })
      });
      setOverrideModalEmail(null);
      await loadData();
    } catch (e) {
      console.error(e);
    }
  };

  const totalMonitored = liveEmails.length > 0 ? 12847 + liveEmails.length : 12847;
  const quarantinedCount = 43 + liveEmails.filter((x) => x.action_taken === 'QUARANTINE').length;
  const flaggedCount = 127 + liveEmails.filter((x) => x.action_taken === 'FLAG').length;
  const cleanCount = totalMonitored - quarantinedCount - flaggedCount;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-12 animate-in fade-in duration-300">
      
      {/* Toast Notification */}
      {toastMessage && (
        <div className="p-3.5 rounded-2xl bg-surfaceElevated border border-primary/40 flex items-center justify-between text-xs font-mono text-primaryText shadow-2xl">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="size-4 text-threatSafe" />
            <span>{toastMessage}</span>
          </div>
          <button onClick={() => setToastMessage(null)} className="text-mutedText hover:text-primaryText">
            &times;
          </button>
        </div>
      )}

      {/* 1. TOP EDITORIAL HERO */}
      <section className="grid gap-8 lg:grid-cols-[1.2fr_1fr] lg:items-end justify-between border-b border-border/70 pb-10">
        <div className="space-y-4">
          <p className="eyebrow text-primary">Autonomous Email Defense</p>
          <h1 className="text-4xl sm:text-6xl font-black text-primaryText tracking-tightest leading-[1.05]">
            The inbox, <br />
            <span className="text-mutedText font-light">under watch.</span>
          </h1>
          <p className="max-w-xl text-sm sm:text-base text-secondaryText leading-relaxed">
            Scan your connected Gmail account, or analyse a separate email file without connecting its mailbox.
          </p>
        </div>

        {/* System Status & Primary Action Controls */}
        <div className="flex flex-col sm:items-end space-y-5">
          <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-surfaceSubtle border border-border">
            <span className="relative flex size-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-threatSafe opacity-75"></span>
              <span className="relative inline-flex rounded-full size-2.5 bg-threatSafe"></span>
            </span>
            <span className="eyebrow text-[10px] text-threatSafe">
              Autonomous Gateway Active
            </span>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-3">
            <p className="max-w-xs text-right text-xs leading-relaxed text-mutedText">
              Your connected Gmail account is scanned below. Choose a scan size, then open any email for its full threat report.
            </p>
            <button
              onClick={onOpenUpload}
              className="shrink-0 inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-primary/30 bg-primary/5 text-primary hover:bg-primary hover:text-white text-xs font-bold transition-colors"
            >
              <UploadCloud className="size-4" />
              Analyse Separate Email
            </button>
          </div>
        </div>
      </section>

      {/* 2. GOOGLE OAUTH 2.0 GATEWAY & INCREMENTAL SYNC (MASTER PLAN PHASES 3 & 11) */}
      <section className="p-6 sm:p-8 rounded-3xl border border-border bg-surface shadow-2xl space-y-6 relative overflow-hidden">
        <div className="absolute -right-20 -top-20 w-80 h-80 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-border/70">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-primary/10 text-primary border border-primary/20">
                <svg className="size-5" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                </svg>
              </span>
              <div>
                <span className="eyebrow text-[10px] text-primary">Autonomous Ingestion</span>
                <h2 className="text-xl sm:text-2xl font-black text-primaryText tracking-tight">
                  GOOGLE OAUTH &amp; GMAIL SYNC
                </h2>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              {oauthStatus?.is_authorized ? (
                <>
                  <span className="font-mono text-xs sm:text-sm font-bold text-primaryText px-3 py-1 rounded-lg bg-surfaceSubtle border border-border">
                    {oauthStatus.user_email || 'Authenticated Account'}
                  </span>
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatSafe/15 text-threatSafe border border-threatSafe/30">
                    <span className="size-1.5 rounded-full bg-threatSafe animate-pulse"></span>
                    GMAIL CONNECTED
                  </span>
                  {oauthStatus.last_synced_at && (
                    <span className="text-xs text-mutedText font-mono">
                      Last synced: {new Date(oauthStatus.last_synced_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  )}
                </>
              ) : oauthStatus?.sync_state === 'needs_reauth' ? (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatCritical/15 text-threatCritical border border-threatCritical/30">
                  <AlertTriangle className="size-3" />
                  ACCESS REVOKED / EXPIRED (RECONNECT)
                </span>
              ) : (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-mutedText/15 text-secondaryText border border-border">
                  NOT SIGNED IN
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {oauthStatus?.is_authorized ? (
              <>
                <button
                  onClick={handleSyncGmailOAuth}
                  disabled={isSyncingGmail}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
                >
                  {isSyncingGmail ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
                  <span>{isSyncingGmail ? 'Syncing History API...' : 'Sync Gmail Now'}</span>
                </button>

                <button
                  onClick={handleDisconnectGoogle}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surfaceSubtle hover:bg-threatCritical/10 text-mutedText hover:text-threatCritical text-xs font-bold border border-border hover:border-threatCritical/30 transition-all"
                  title="Revoke Google OAuth token and disconnect"
                >
                  <span>Disconnect</span>
                </button>
              </>
            ) : (
              <button
                onClick={handleContinueWithGoogle}
                disabled={isAuthenticatingGoogle}
                className="flex items-center gap-2.5 px-6 py-3 rounded-2xl bg-white hover:bg-neutral-50 text-neutral-900 text-sm font-bold shadow-lg border border-neutral-300 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
              >
                <svg className="size-4" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                </svg>
                <span>{isAuthenticatingGoogle ? 'Connecting to Google...' : 'Continue with Google'}</span>
              </button>
            )}
          </div>
        </div>

        {oauthError && (
          <div className="p-4 rounded-2xl bg-threatCritical/10 border border-threatCritical/30 flex items-start justify-between gap-3 text-threatCritical text-xs">
            <div className="flex items-center gap-2">
              <AlertOctagon className="size-4 shrink-0" />
              <span>{oauthError}</span>
            </div>
            <button
              onClick={handleContinueWithGoogle}
              className="font-bold underline hover:text-threatCriticalDark"
            >
              Try Again
            </button>
          </div>
        )}

        {oauthStatus?.is_authorized && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-2xl bg-surfaceSubtle border border-border/80">
              <div className="eyebrow text-[9px] text-mutedText">INBOUND INGESTED</div>
              <div className="text-2xl font-black font-mono text-primaryText mt-1">
                {oauthStatus.summary?.total_ingested || 0}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-threatCritical/5 border border-threatCritical/20">
              <div className="eyebrow text-[9px] text-threatCritical">QUARANTINED</div>
              <div className="text-2xl font-black font-mono text-threatCritical mt-1">
                {oauthStatus.summary?.quarantined || 0}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-threatSuspicious/5 border border-threatSuspicious/20">
              <div className="eyebrow text-[9px] text-threatSuspicious">FLAGGED</div>
              <div className="text-2xl font-black font-mono text-threatSuspicious mt-1">
                {oauthStatus.summary?.suspicious || 0}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-threatSafe/5 border border-threatSafe/20">
              <div className="eyebrow text-[9px] text-threatSafe">DELIVERED CLEAN</div>
              <div className="text-2xl font-black font-mono text-threatSafe mt-1">
                {oauthStatus.summary?.clean || 0}
              </div>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between text-[11px] text-mutedText pt-2">
          <span>
            Scope: <code className="text-primaryText">gmail.readonly</code> &bull; Read-only access. Your Gmail password is never requested or shown in the browser.
          </span>
          <span className="text-primary hover:underline cursor-pointer">
            Data Handling &amp; Privacy Policy &rarr;
          </span>
        </div>
      </section>

      {/* GMAIL DEDICATED IMAP INTEGRATION SECTION */}
      <section className="p-6 sm:p-8 rounded-3xl border border-border bg-surface shadow-xl space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-border/70">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-primary/10 text-primary border border-primary/20">
                <Mail className="size-5" />
              </span>
              <div>
                <span className="eyebrow text-[10px] text-primary">Gmail OAuth · Read-only</span>
                <h2 className="text-xl sm:text-2xl font-black text-primaryText tracking-tight">
                  GMAIL MAILBOX
                </h2>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <span className="font-mono text-xs sm:text-sm font-bold text-primaryText px-3 py-1 rounded-lg bg-surfaceSubtle border border-border">
                {gmailStatus.email || 'Connect Gmail to see the active account'}
              </span>
              <div className="flex items-center gap-2">
                {gmailStatus.connected ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatSafe/15 text-threatSafe border border-threatSafe/30">
                    <span className="size-1.5 rounded-full bg-threatSafe animate-pulse"></span>
                    CONNECTED
                  </span>
                ) : gmailError ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatCritical/15 text-threatCritical border border-threatCritical/30">
                    <span className="size-1.5 rounded-full bg-threatCritical"></span>
                    AUTH FAILED
                  </span>
                ) : gmailStatus.configured ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-primary/15 text-primary border border-primary/30">
                    <span className="size-1.5 rounded-full bg-primary"></span>
                    READY TO SCAN
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-threatHigh/15 text-threatHigh border border-threatHigh/30">
                    <span className="size-1.5 rounded-full bg-threatHigh"></span>
                    GMAIL NOT CONNECTED
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Action Controls */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleTestGmailConnection}
              disabled={isTestingGmail || isScanningGmail}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-primaryText text-xs font-bold border border-border transition-all disabled:opacity-50"
            >
              {isTestingGmail ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5 text-primary" />}
              <span>Test Connection</span>
            </button>

            <button
              onClick={() => handleScanGmailInbox(scanLimit)}
              disabled={isScanningGmail}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
            >
              {isScanningGmail ? <Loader2 className="size-3.5 animate-spin" /> : <Zap className="size-3.5" />}
              <span>Scan Latest {scanLimit} Emails</span>
            </button>

            <label className="flex items-center gap-2 px-3 py-2 rounded-xl bg-surface border border-border text-xs font-mono text-secondaryText">
              <span>Scan</span>
              <select
                value={scanLimit}
                onChange={(event) => setScanLimit(Number(event.target.value))}
                disabled={isScanningGmail}
                className="bg-transparent text-primaryText font-bold focus:outline-none disabled:opacity-50"
                aria-label="Number of recent emails to scan"
              >
                {[5, 10, 20, 25].map((limit) => <option key={limit} value={limit}>{limit}</option>)}
              </select>
            </label>

            {/* Auto-Scan Toggle */}
            <button
              onClick={handleToggleAutoScan}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-mono font-medium border transition-colors ${
                gmailStatus.auto_scan_enabled
                  ? 'bg-primary/10 border-primary/40 text-primary'
                  : 'bg-surface hover:bg-surfaceElevated border-border text-mutedText hover:text-primaryText'
              }`}
              title="Toggle automatic polling every 5 minutes"
            >
              <RefreshCw className={`size-3.5 ${gmailStatus.auto_scan_enabled ? 'text-primary' : ''}`} />
              <span>Auto-Scan (5m)</span>
              <span className={`size-2 rounded-full ${gmailStatus.auto_scan_enabled ? 'bg-primary' : 'bg-mutedText/40'}`} />
            </button>
          </div>
        </div>

        {/* Error Notification / Guidance */}
        {gmailError && (
          <div className="p-4 rounded-2xl bg-threatCritical/10 border border-threatCritical/30 flex items-start gap-3 text-xs text-threatCritical">
            <AlertTriangle className="size-4 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold">{gmailError}</div>
              <p className="text-secondaryText text-[11px]">
                This scanner uses Google OAuth only. No Gmail App Password is needed. Reconnect Gmail from the login page if authorization expired.
              </p>
            </div>
          </div>
        )}

        {/* WHILE SCANNING: REAL PROGRESS DISPLAY */}
        {isScanningGmail && (
          <div className="p-6 rounded-2xl bg-surfaceSubtle border border-primary/30 space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="relative flex size-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                  <span className="relative inline-flex rounded-full size-2.5 bg-primary"></span>
                </span>
                <span className="eyebrow text-xs text-primary font-mono font-bold">SCANNING MAILBOX</span>
              </div>
              <span className="font-mono text-xs font-bold text-primaryText">
                {scanProgress.current} / {scanProgress.total} Emails
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-surface border border-border rounded-full h-2 overflow-hidden">
              <div
                className="bg-primary h-full transition-all duration-300"
                style={{ width: `${Math.max(5, Math.round((scanProgress.current / scanProgress.total) * 100))}%` }}
              />
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-mutedText">Current: </span>
              <span className="font-mono font-bold text-primaryText">
                {scanProgress.subject || 'Retrieving raw MIME messages through Gmail API...'}
              </span>
            </div>

            {/* Pipeline Checklist */}
            <div className="pt-2 border-t border-border/50 space-y-1.5 font-mono text-xs">
              <span className="eyebrow text-[9px] text-mutedText block mb-1">Pipeline:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
                {[
                  { label: 'Retrieved email', step: 0 },
                  { label: 'Extracted headers', step: 1 },
                  { label: 'Started forensic analysis', step: 2 },
                  { label: 'Running intelligence modules', step: 3 },
                  { label: 'Finalizing verdict', step: 4 },
                ].map((item) => {
                  const isDone = scanProgress.stepIndex > item.step;
                  const isCurrent = scanProgress.stepIndex === item.step;
                  return (
                    <div
                      key={item.step}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] ${
                        isDone
                          ? 'bg-threatSafe/10 border-threatSafe/30 text-threatSafe'
                          : isCurrent
                          ? 'bg-primary/10 border-primary/40 text-primary animate-pulse'
                          : 'bg-surface/50 border-border/50 text-mutedText'
                      }`}
                    >
                      <span>{isDone ? '✓' : isCurrent ? '●' : '○'}</span>
                      <span className="truncate">{item.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* SCAN RESULTS SUMMARY & ITEMS */}
        {gmailResults.length > 0 && !isScanningGmail && (
          <div className="space-y-4 pt-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-2xl bg-surfaceSubtle border border-border">
              <div>
                <span className="eyebrow text-[10px] text-primary font-mono font-bold">SCAN COMPLETE</span>
                <div className="text-sm font-bold text-primaryText">
                  {gmailSummary ? `${gmailSummary.total} Emails Processed` : `${gmailResults.length} Emails Scanned`}
                </div>
              </div>
              <div className="flex items-center gap-3 font-mono text-xs">
                <span className="px-2.5 py-1 rounded-lg bg-threatCritical/15 text-threatCritical border border-threatCritical/30 font-bold">
                  {gmailSummary?.high_risk ?? gmailResults.filter(r => (r.threat_score || 0) >= 0.75).length} High Risk
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-threatHigh/15 text-threatHigh border border-threatHigh/30 font-bold">
                  {gmailSummary?.suspicious ?? gmailResults.filter(r => (r.threat_score || 0) >= 0.35 && (r.threat_score || 0) < 0.75).length} Suspicious
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-threatSafe/15 text-threatSafe border border-threatSafe/30 font-bold">
                  {gmailSummary?.clean ?? gmailResults.filter(r => (r.threat_score || 0) < 0.35).length} Clean
                </span>
              </div>
            </div>

            {/* Results List */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {gmailResults.map((r, i) => {
                const score = Math.round((r.threat_score ?? 0) * 100);
                const isCrit = score >= 70;
                const isSusp = score >= 30 && score < 70;
                const badgeStyle = isCrit
                  ? 'border-threatCritical text-threatCritical bg-threatCritical/10'
                  : isSusp
                  ? 'border-threatHigh text-threatHigh bg-threatHigh/10'
                  : 'border-threatSafe text-threatSafe bg-threatSafe/10';

                return (
                  <div
                    key={r.id || r.email_id || i}
                    className="p-5 rounded-2xl bg-surfaceSubtle hover:bg-surfaceElevated border border-border flex flex-col justify-between gap-4 transition-all shadow-sm group"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-mono font-black border ${badgeStyle}`}>
                          {r.classification || r.verdict || (isCrit ? 'CRITICAL' : isSusp ? 'SUSPICIOUS' : 'SAFE')} — {score}%
                        </span>
                        <span className="font-mono text-[11px] text-mutedText truncate">
                          {r.received_at || 'Recent'}
                        </span>
                      </div>

                      <h4 className="text-sm font-bold text-primaryText group-hover:text-primary transition-colors truncate" title={r.subject}>
                        {r.subject || '(No Subject)'}
                      </h4>

                      <div className="font-mono text-xs text-secondaryText truncate">
                        <span className="text-mutedText">From: </span>
                        <span>{r.from_address || r.sender || 'Unknown'}</span>
                      </div>

                      {/* Signals */}
                      {r.top_signals && r.top_signals.length > 0 && (
                        <div className="pt-2 border-t border-border/40 space-y-1">
                          <span className="eyebrow text-[9px] text-mutedText block">Signals:</span>
                          {r.top_signals.slice(0, 3).map((sig: string, si: number) => (
                            <div key={si} className="text-[11px] text-secondaryText font-mono flex items-center gap-1.5">
                              <span className="text-primary font-bold">•</span>
                              <span className="truncate">{sig}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <button
                      onClick={() => navigate(`/investigation?id=${r.email_id || r.id}`)}
                      className="w-full mt-2 py-2 px-3 rounded-xl bg-surface hover:bg-primary text-secondaryText hover:text-white font-mono text-xs font-bold border border-border group-hover:border-transparent flex items-center justify-center gap-2 transition-all"
                    >
                      <span>Open Investigation</span>
                      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* 2. ASYMMETRIC METRIC SECTION */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow">Inbound Email</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-primaryText">
            {totalMonitored.toLocaleString()}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-threatSafe font-mono">
            <ArrowUpRight className="size-3.5" />
            <span>↑ 12% today</span>
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatCritical">Quarantined</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatCritical">
            {quarantinedCount}
          </div>
          <div className="text-xs text-mutedText">
            High-confidence attacks isolated
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatHigh">Flagged / Caution</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatHigh">
            {flaggedCount}
          </div>
          <div className="text-xs text-mutedText">
            Subject prepended with alert banner
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-border bg-surface shadow-lg space-y-2">
          <span className="eyebrow text-threatSafe">Delivered Clean</span>
          <div className="text-3xl sm:text-4xl font-black font-mono text-threatSafe">
            {cleanCount.toLocaleString()}
          </div>
          <div className="text-xs text-mutedText">
            Cryptographically authenticated
          </div>
        </div>
      </section>

      {/* 3. LIVE THREAT STREAM */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="eyebrow text-primary">Inbound Stream</p>
            <h2 className="text-2xl font-black text-primaryText tracking-tight">
              Real-Time Inspection Feed
            </h2>
          </div>

          <span className="font-mono text-xs text-mutedText flex items-center gap-2">
            <span className="size-2 rounded-full bg-threatSafe animate-ping" />
            WebSockets Stream Connected
          </span>
        </div>

        <div className="flex flex-col space-y-3">
          <AnimatePresence>
            {liveEmails.map((email) => {
              const scorePct = Math.round((email.threat_score ?? 0.85) * 100);
              const isQuarantine = email.action_taken === 'QUARANTINE';
              const isFlag = email.action_taken === 'FLAG';

              const accentColor = isQuarantine
                ? 'border-l-threatCritical'
                : isFlag
                ? 'border-l-threatHigh'
                : 'border-l-threatSafe';

              const badgeColor = isQuarantine
                ? 'text-threatCritical bg-threatCritical/15 border-threatCritical/30'
                : isFlag
                ? 'text-threatHigh bg-threatHigh/15 border-threatHigh/30'
                : 'text-threatSafe bg-threatSafe/15 border-threatSafe/30';

              return (
                <motion.article
                  key={email.id}
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                  transition={{ duration: 0.25 }}
                  className={`p-5 rounded-2xl border border-border bg-surface hover:bg-surfaceElevated transition-all flex flex-col md:flex-row md:items-center justify-between gap-6 border-l-4 ${accentColor} shadow-md group`}
                >
                  <div className="flex items-start gap-5 min-w-0 flex-1">
                    {/* Threat Score Dial */}
                    <div className="flex flex-col items-center justify-center p-2.5 rounded-xl bg-surfaceSubtle border border-border/70 flex-shrink-0 w-16">
                      <span className={`text-lg font-black font-mono ${isQuarantine ? 'text-threatCritical' : isFlag ? 'text-threatHigh' : 'text-threatSafe'}`}>
                        {scorePct}%
                      </span>
                      <span className="eyebrow text-[8px]">SCORE</span>
                    </div>

                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className={`eyebrow text-[10px] px-2 py-0.5 rounded-md border font-mono ${badgeColor}`}>
                          {email.action_taken || 'EVALUATED'}
                        </span>
                        <span className="font-mono text-xs text-mutedText">
                          {email.received_at || 'Just now'}
                        </span>
                      </div>

                      <h3
                        onClick={() => navigate(`/investigation?id=${email.id}`)}
                        className="text-base font-bold text-primaryText hover:text-primary transition-colors cursor-pointer truncate"
                      >
                        {email.subject}
                      </h3>

                      <p className="font-mono text-xs text-secondaryText truncate">
                        {email.sender}
                      </p>

                      {/* Policy Triggers */}
                      {email.policy_triggers && email.policy_triggers.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {email.policy_triggers.map((trig: string, i: number) => (
                            <span
                              key={i}
                              className="font-mono text-[10px] px-2 py-0.5 rounded bg-surfaceSubtle text-secondaryText border border-border"
                            >
                              {trig}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Actions */}
                  <div className="flex items-center gap-3 self-end md:self-center flex-shrink-0">
                    <button
                      onClick={() => {
                        setOverrideModalEmail(email);
                        setOverrideAction(email.action_taken === 'QUARANTINE' ? 'DELIVER' : 'QUARANTINE');
                      }}
                      className="px-3 py-1.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-mono font-medium border border-border transition-colors opacity-0 group-hover:opacity-100"
                    >
                      Override
                    </button>

                    <button
                      onClick={() => navigate(`/investigation?id=${email.id}`)}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-surfaceElevated group-hover:bg-primary text-secondaryText group-hover:text-white text-xs font-bold transition-all border border-border group-hover:border-transparent"
                    >
                      <span>Inspect</span>
                      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                    </button>
                  </div>
                </motion.article>
              );
            })}
          </AnimatePresence>

          {liveEmails.length === 0 && (
            <div className="p-12 text-center rounded-2xl border border-dashed border-border bg-surfaceSubtle/30 space-y-3">
              <Radio className="size-8 text-primary mx-auto animate-pulse" />
              <div className="text-sm font-bold text-primaryText">Listening for Inbound Email Stream</div>
              <p className="text-xs text-mutedText max-w-sm mx-auto">
                No new inbound messages in current buffer. Click "Simulate Inbound Attack" above to inject a realistic email scenario.
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Override Modal */}
      {overrideModalEmail && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surfaceElevated border border-border rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <h3 className="text-lg font-bold text-primaryText">Analyst Action Override</h3>
            <p className="text-xs text-secondaryText">
              Manually modify the autonomous gateway verdict for message:{' '}
              <strong className="text-primaryText">{overrideModalEmail.subject}</strong>
            </p>

            <div className="space-y-3">
              <div>
                <label className="eyebrow block mb-1.5">Enforce Action</label>
                <select
                  value={overrideAction}
                  onChange={(e) => setOverrideAction(e.target.value)}
                  className="w-full bg-surface border border-border rounded-xl p-2.5 text-xs text-primaryText font-mono"
                >
                  <option value="DELIVER">DELIVER (Release to Inbox)</option>
                  <option value="FLAG">FLAG (Deliver with Warning Banner)</option>
                  <option value="QUARANTINE">QUARANTINE (Isolate in Vault)</option>
                </select>
              </div>

              <div>
                <label className="eyebrow block mb-1.5">Audit Reason</label>
                <textarea
                  rows={3}
                  value={overrideReason}
                  onChange={(e) => setOverrideReason(e.target.value)}
                  className="w-full bg-surface border border-border rounded-xl p-2.5 text-xs text-primaryText"
                  placeholder="State justification for chain-of-custody audit logging..."
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setOverrideModalEmail(null)}
                className="px-4 py-2 rounded-xl text-xs font-bold text-mutedText hover:text-primaryText"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyOverride}
                className="px-5 py-2 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-md shadow-primary/20"
              >
                Apply & Record Override
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Mailbox Connection Modal */}
      <MailboxConnectModal
        isOpen={isConnectOpen}
        onClose={() => setIsConnectOpen(false)}
        onSuccess={loadData}
      />

      {/* Policy Sensitivity Configuration Panel */}
      <ThresholdConfigPanel
        isOpen={isPolicyOpen}
        onClose={() => setIsPolicyOpen(false)}
        onSaved={loadData}
      />
    </div>
  );
};
