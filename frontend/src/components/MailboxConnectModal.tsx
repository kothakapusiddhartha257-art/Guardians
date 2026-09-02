import React, { useState, useEffect } from 'react';
import { X, Mail, Server, Shield, Sparkles, CheckCircle2, AlertCircle, RefreshCw, ExternalLink, KeyRound } from 'lucide-react';

interface MailboxConnectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConnected?: () => void;
  onSuccess?: () => void;
}

export const MailboxConnectModal: React.FC<MailboxConnectModalProps> = ({ isOpen, onClose, onConnected, onSuccess }) => {
  const [provider, setProvider] = useState<'simulator' | 'imap' | 'gmail' | 'outlook'>('gmail');
  const [displayName, setDisplayName] = useState('SecOps Corporate Mailbox');
  
  // IMAP fields
  const [host, setHost] = useState('imap.gmail.com');
  const [port, setPort] = useState(993);
  const [username, setUsername] = useState('security@company.com');
  const [password, setPassword] = useState('');

  // Gmail OAuth fields
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [oauthStatus, setOauthStatus] = useState<any>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/v1/oauth/gmail/status')
        .then((res) => res.json())
        .then((data) => setOauthStatus(data))
        .catch((e) => console.error(e));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleStartGoogleOAuth = async () => {
    setLoading(true);
    setError(null);
    try {
      if (clientId && clientSecret) {
        await fetch('/api/v1/oauth/gmail/credentials', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ client_id: clientId, client_secret: clientSecret })
        });
      }

      const res = await fetch('/api/v1/oauth/gmail/auth-url');
      const data = await res.json();

      if (data.auth_url) {
        window.location.href = data.auth_url;
      } else {
        throw new Error('Could not generate Google authorization URL');
      }
    } catch (err: any) {
      setError(err.message || 'OAuth authorization failed to initiate');
      setLoading(false);
    }
  };

  const handleConnect = async () => {
    setLoading(true);
    setError(null);
    try {
      let credentials: any = {};
      if (provider === 'imap') {
        credentials = { host, port, username, password, use_ssl: true };
      } else if (provider === 'gmail') {
        credentials = { access_token: 'oauth_gmail_token', refresh_token: 'oauth_gmail_refresh' };
      } else if (provider === 'outlook') {
        credentials = { access_token: 'oauth_graph_token', client_id: 'entra_client_id' };
      }

      await fetch('/api/v1/mailboxes/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          display_name: displayName,
          credentials
        })
      });

      if (onConnected) onConnected();
      if (onSuccess) onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to connect mailbox');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-surfaceElevated border border-border rounded-3xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border/70 bg-surfaceSubtle">
          <div className="flex items-center gap-3">
            <div className="size-9 rounded-xl bg-primary/15 flex items-center justify-center text-primary">
              <Mail className="size-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-primaryText">Connect Inbound Mailbox Gateway</h2>
              <p className="eyebrow text-[10px] text-mutedText">Google OAuth 2.0, Microsoft Graph & IMAP IDLE</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-xl text-mutedText hover:text-primaryText hover:bg-surface transition-colors">
            <X className="size-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {error && (
            <div className="p-3.5 rounded-xl bg-threatCritical/10 border border-threatCritical/30 flex items-center gap-3 text-threatCritical text-xs font-semibold">
              <AlertCircle className="size-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Provider Selection */}
          <div className="space-y-2.5">
            <label className="eyebrow block">
              Mailbox Ingestion Provider
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              <button
                type="button"
                onClick={() => { setProvider('gmail'); setDisplayName('Corporate Gmail Gateway'); }}
                className={`p-3.5 rounded-2xl border text-center transition-all ${
                  provider === 'gmail'
                    ? 'border-primary bg-primary/10 text-primaryText font-bold shadow-sm'
                    : 'border-border bg-surface text-secondaryText hover:text-primaryText'
                }`}
              >
                <Mail className="size-4 mx-auto mb-1 text-threatCritical" />
                <span className="text-xs block font-bold">Gmail OAuth</span>
                <span className="eyebrow text-[8px] opacity-70 block font-normal">Google API</span>
              </button>

              <button
                type="button"
                onClick={() => { setProvider('simulator'); setDisplayName('Live Threat Gateway Simulator'); }}
                className={`p-3.5 rounded-2xl border text-center transition-all ${
                  provider === 'simulator'
                    ? 'border-primary bg-primary/10 text-primaryText font-bold shadow-sm'
                    : 'border-border bg-surface text-secondaryText hover:text-primaryText'
                }`}
              >
                <Sparkles className="size-4 mx-auto mb-1 text-primary" />
                <span className="text-xs block font-bold">Simulator</span>
                <span className="eyebrow text-[8px] opacity-70 block font-normal">Demo Stream</span>
              </button>

              <button
                type="button"
                onClick={() => { setProvider('imap'); setDisplayName('Corporate IMAP Gateway'); }}
                className={`p-3.5 rounded-2xl border text-center transition-all ${
                  provider === 'imap'
                    ? 'border-primary bg-primary/10 text-primaryText font-bold shadow-sm'
                    : 'border-border bg-surface text-secondaryText hover:text-primaryText'
                }`}
              >
                <Server className="size-4 mx-auto mb-1 text-threatHigh" />
                <span className="text-xs block font-bold">IMAP IDLE</span>
                <span className="eyebrow text-[8px] opacity-70 block font-normal">App Password</span>
              </button>

              <button
                type="button"
                onClick={() => { setProvider('outlook'); setDisplayName('Microsoft 365 Exchange'); }}
                className={`p-3.5 rounded-2xl border text-center transition-all ${
                  provider === 'outlook'
                    ? 'border-primary bg-primary/10 text-primaryText font-bold shadow-sm'
                    : 'border-border bg-surface text-secondaryText hover:text-primaryText'
                }`}
              >
                <Shield className="size-4 mx-auto mb-1 text-infra" />
                <span className="text-xs block font-bold">MS Graph</span>
                <span className="eyebrow text-[8px] opacity-70 block font-normal">Webhooks</span>
              </button>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="eyebrow block mb-1.5">Mailbox Connection Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full bg-surface border border-border rounded-xl px-3 py-2 text-xs text-primaryText font-mono focus:outline-none focus:border-primary"
              />
            </div>

            {/* GMAIL OAUTH 2.0 VIEW */}
            {provider === 'gmail' && (
              <div className="space-y-4 pt-1">
                <div className="p-4 rounded-2xl bg-surface border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <KeyRound className="size-4 text-threatCritical" />
                      <span className="text-xs font-bold text-primaryText">Google OAuth 2.0 Integration</span>
                    </div>
                    {oauthStatus?.is_authorized ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-threatSafe/20 text-threatSafe border border-threatSafe/30 flex items-center gap-1">
                        <CheckCircle2 className="size-3" />
                        AUTHORIZED ({oauthStatus.user_email})
                      </span>
                    ) : (
                      <span className="eyebrow text-[9px] text-threatHigh">
                        Ready for Consent
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-secondaryText leading-relaxed">
                    Uses Google OAuth 2.0 token authorization with scopes <code className="font-mono text-[11px] text-primary">https://mail.google.com/</code> and <code className="font-mono text-[11px] text-primary">gmail.modify</code>. Automatically manages token renewals and reversible quarantine labeling (<code className="font-mono text-[11px] text-threatCritical">TRACEGUARD_QUARANTINE</code>).
                  </p>

                  <div className="grid grid-cols-1 gap-2.5 pt-1 text-xs">
                    <div>
                      <label className="eyebrow block mb-1 text-[10px]">Google Client ID (Optional custom)</label>
                      <input
                        type="text"
                        value={clientId}
                        onChange={(e) => setClientId(e.target.value)}
                        placeholder="719283...apps.googleusercontent.com"
                        className="w-full bg-surfaceSubtle border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono text-[11px]"
                      />
                    </div>
                    <div>
                      <label className="eyebrow block mb-1 text-[10px]">Google Client Secret (Optional custom)</label>
                      <input
                        type="password"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                        placeholder="GOCSPX-••••••••••••"
                        className="w-full bg-surfaceSubtle border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono text-[11px]"
                      />
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      type="button"
                      onClick={handleStartGoogleOAuth}
                      disabled={loading}
                      className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-red-500/20 transition-all"
                    >
                      <Mail className="size-4" />
                      <span>{loading ? 'Initiating OAuth...' : 'Sign in & Authorize with Google'}</span>
                      <ExternalLink className="size-3.5 opacity-80" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* IMAP VIEW */}
            {provider === 'imap' && (
              <div className="grid grid-cols-2 gap-3 pt-1">
                <div>
                  <label className="eyebrow block mb-1">IMAP Server Host</label>
                  <input
                    type="text"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="imap.gmail.com"
                    className="w-full bg-surface border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono"
                  />
                </div>
                <div>
                  <label className="eyebrow block mb-1">Port</label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                    className="w-full bg-surface border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono"
                  />
                </div>
                <div>
                  <label className="eyebrow block mb-1">Username / Email</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="user@domain.com"
                    className="w-full bg-surface border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono"
                  />
                </div>
                <div>
                  <label className="eyebrow block mb-1">App Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-surface border border-border rounded-xl px-3 py-2 text-xs text-primaryText focus:outline-none focus:border-primary font-mono"
                  />
                </div>
              </div>
            )}

            {/* OUTLOOK VIEW */}
            {provider === 'outlook' && (
              <div className="p-4 rounded-2xl bg-surface border border-border text-xs text-secondaryText space-y-1.5">
                <div className="font-bold text-primaryText flex items-center gap-1.5">
                  <CheckCircle2 className="size-4 text-threatSafe" />
                  Microsoft Graph Webhook Subscription Active
                </div>
                <p className="text-[11px] text-mutedText">
                  Subscribes to <code className="font-mono text-primary">/messages</code> notifications with scheduled renewal before 4230-minute expiry and automated move to <code className="font-mono text-threatCritical">TRACEGUARD Quarantine</code> folder.
                </p>
              </div>
            )}

            {/* SIMULATOR VIEW */}
            {provider === 'simulator' && (
              <div className="p-4 rounded-2xl bg-primary/10 border border-primary/20 text-xs text-primary space-y-1">
                <div className="font-bold flex items-center gap-1.5">
                  <Sparkles className="size-4" />
                  One-Click Live Demo Simulation Active
                </div>
                <p className="text-[11px] text-secondaryText">
                  Simulates realistic inbound attacks (BEC, Credential Harvester, Invoice Malware) arriving in real time without external credentials.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border/70 bg-surfaceSubtle flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:text-primaryText transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConnect}
            disabled={loading}
            className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark disabled:opacity-50 text-white text-xs font-bold shadow-lg shadow-primary/25 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center gap-2"
          >
            {loading ? <RefreshCw className="size-4 animate-spin" /> : <CheckCircle2 className="size-4" />}
            <span>Activate Mailbox Ingestion Gateway</span>
          </button>
        </div>
      </div>
    </div>
  );
};
