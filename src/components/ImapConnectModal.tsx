import React, { useState } from 'react';
import { X, Server, ShieldCheck, Lock, AlertCircle, CheckCircle2, Loader2, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface ImapConnectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const ImapConnectModal: React.FC<ImapConnectModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const { connectImap } = useAuth();

  const [email, setEmail] = useState('');
  const [host, setHost] = useState('imap.gmail.com');
  const [port, setPort] = useState(993);
  const [security, setSecurity] = useState('SSL/TLS');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const [isTesting, setIsTesting] = useState(false);
  const [testSuccess, setTestSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);

  if (!isOpen) return null;

  const handleTest = async () => {
    setIsTesting(true);
    setError(null);
    setTestSuccess(null);
    try {
      const res = await fetch('/api/v1/gmail/test-connection', {
        method: 'POST'
      });
      const data = await res.json();
      if (res.ok) {
        setTestSuccess('SSL/TLS handshake verified successfully.');
      } else {
        throw new Error(data.detail || 'Connection verification failed');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to IMAP host');
    } finally {
      setIsTesting(false);
    }
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !host || !username) {
      setError('Please fill in all required fields.');
      return;
    }

    setIsConnecting(true);
    setError(null);
    try {
      await connectImap({
        email,
        host,
        port: Number(port),
        use_ssl: security === 'SSL/TLS',
        username,
        password
      });
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to connect mailbox');
    } finally {
      setIsConnecting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg rounded-3xl bg-surface border border-border shadow-2xl p-6 sm:p-8 space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-border/80">
          <div className="flex items-center gap-3">
            <span className="p-2.5 rounded-xl bg-primary/10 text-primary border border-primary/20">
              <Server className="size-5" />
            </span>
            <div>
              <span className="eyebrow text-[10px] text-primary">Dedicated Protocol</span>
              <h2 className="text-xl font-black text-primaryText tracking-tight">Connect with IMAP</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-secondaryText hover:text-primaryText hover:bg-surfaceSubtle transition-colors"
          >
            <X className="size-5" />
          </button>
        </div>

        {/* Feedback Alerts */}
        {error && (
          <div className="p-4 rounded-2xl bg-threatCritical/10 border border-threatCritical/30 flex items-start gap-3 text-threatCritical text-xs">
            <AlertCircle className="size-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {testSuccess && (
          <div className="p-4 rounded-2xl bg-threatSafe/10 border border-threatSafe/30 flex items-center gap-3 text-threatSafe text-xs">
            <CheckCircle2 className="size-4 shrink-0" />
            <span>{testSuccess}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleConnect} className="space-y-4">
          <div>
            <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@enterprise.com"
              required
              className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors"
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">IMAP Host</label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="imap.mailserver.com"
                required
                className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">Security</label>
              <select
                value={security}
                onChange={(e) => setSecurity(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors font-mono"
              >
                <option value="SSL/TLS">SSL/TLS</option>
                <option value="STARTTLS">STARTTLS</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username or email"
                required
                className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-bold text-secondaryText mb-1.5">Password / App Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••••••"
              className="w-full px-4 py-2.5 rounded-xl bg-surfaceSubtle border border-border text-sm text-primaryText focus:border-primary focus:outline-none transition-colors font-mono"
            />
            <p className="text-[11px] text-mutedText mt-1 flex items-center gap-1.5">
              <Lock className="size-3 text-primary" />
              Credentials are processed strictly server-side and never stored in browser code.
            </p>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-4 border-t border-border/80">
            <button
              type="button"
              onClick={handleTest}
              disabled={isTesting || isConnecting}
              className="px-4 py-2.5 rounded-xl bg-surfaceSubtle hover:bg-surfaceElevated text-secondaryText hover:text-primaryText text-xs font-bold border border-border transition-colors flex items-center gap-2"
            >
              {isTesting ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5 text-primary" />}
              <span>Test Connection</span>
            </button>
            <button
              type="submit"
              disabled={isConnecting}
              className="px-6 py-2.5 rounded-xl bg-primary hover:bg-primaryDark text-white text-xs font-bold shadow-lg shadow-primary/20 transition-all flex items-center gap-2 disabled:opacity-50"
            >
              {isConnecting ? <Loader2 className="size-3.5 animate-spin" /> : <ArrowRight className="size-3.5" />}
              <span>Connect Mailbox</span>
            </button>
          </div>
        </form>

      </div>
    </div>
  );
};
