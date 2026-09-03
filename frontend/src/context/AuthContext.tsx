import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

export interface Mailbox {
  id: string;
  provider: 'gmail' | 'microsoft' | 'imap' | 'demo';
  email: string;
  display_name: string;
  status: 'CONNECTED' | 'DISCONNECTED' | 'NEEDS_REAUTH' | 'ERROR';
  last_synced_at?: string;
  created_at?: string;
}

export interface UserSession {
  email: string;
  provider: string;
  role: string;
  authenticated_at?: string;
}

interface AuthContextType {
  user: UserSession | null;
  activeMailbox: Mailbox | null;
  connectedMailboxes: Mailbox[];
  isAuthenticated: boolean;
  isLoading: boolean;
  authError: string | null;
  login: (username: string, password: string) => Promise<void>;
  enterDemo: (scenario?: string) => Promise<void>;
  logout: () => Promise<void>;
  selectMailbox: (id: string) => Promise<void>;
  disconnectMailbox: (id: string) => Promise<void>;
  connectImap: (settings: { email: string; host: string; port: number; use_ssl: boolean; username: string; password?: string }) => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const DEMO_SESSION_KEY = 'traceguard_demo_session';
const TOKEN_KEY = 'access_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(null);
  const [activeMailbox, setActiveMailbox] = useState<Mailbox | null>(null);
  const [connectedMailboxes, setConnectedMailboxes] = useState<Mailbox[]>([]);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  // ---------------------------------------------------------
  // Demo session (offline / no-backend fallback, entered explicitly)
  // ---------------------------------------------------------

  const createDemoSession = (scenario: string = 'bec_wire_transfer') => {
    const demoMailbox: Mailbox = {
      id: 'mb-demo-01',
      provider: 'demo',
      email: 'demo.analyst@traceguard.sec',
      display_name: `Demo Environment (${scenario.replace(/_/g, ' ').toUpperCase()})`,
      status: 'CONNECTED',
      last_synced_at: new Date().toISOString()
    };

    const demoUser: UserSession = {
      email: 'demo.analyst@traceguard.sec',
      provider: 'demo',
      role: 'SOC Analyst (Demonstration Mode)',
      authenticated_at: new Date().toISOString()
    };

    setUser(demoUser);
    setActiveMailbox(demoMailbox);
    setConnectedMailboxes([demoMailbox]);
    setIsAuthenticated(true);

    sessionStorage.setItem(
      DEMO_SESSION_KEY,
      JSON.stringify({ user: demoUser, activeMailbox: demoMailbox, connectedMailboxes: [demoMailbox] })
    );
  };

  // ---------------------------------------------------------
  // Real backend login
  // ---------------------------------------------------------

  const login = async (username: string, password: string) => {
    setAuthError(null);
    try {
      const data = await api.login(username, password);
      localStorage.setItem(TOKEN_KEY, data.access_token);

      const usr: UserSession = {
        email: data.username,
        provider: 'backend',
        role: data.role,
        authenticated_at: new Date().toISOString()
      };

      setUser(usr);
      setIsAuthenticated(true);

      // Pull mailboxes now that we're authenticated
      try {
        const mailboxes = await api.getMailboxes();
        setConnectedMailboxes(mailboxes || []);
        setActiveMailbox(mailboxes?.[0] || null);
      } catch {
        setConnectedMailboxes([]);
        setActiveMailbox(null);
      }
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Login failed');
      throw err;
    }
  };

  // ---------------------------------------------------------
  // Refresh authentication session on load
  // ---------------------------------------------------------

  const refreshSession = async () => {
    setIsLoading(true);
    setAuthError(null);

    const token = localStorage.getItem(TOKEN_KEY);

    if (token) {
      try {
        const data = await api.getSession();
        if (data?.authenticated && data?.user) {
          setUser(data.user);
          setIsAuthenticated(true);
          setActiveMailbox(data.active_mailbox || null);
          setConnectedMailboxes(data.connected_mailboxes || []);
          setIsLoading(false);
          return;
        }
      } catch {
        // token invalid/expired — client.ts already cleared it on 401
        localStorage.removeItem(TOKEN_KEY);
      }
    }

    // Local Gmail OAuth is a valid website sign-in for this single-user,
    // local deployment. The backend keeps the OAuth token server-side; the
    // browser only sees an authorization status, never the Gmail token.
    try {
      const response = await fetch('/api/v1/oauth/gmail/status');
      const gmail = await response.json();
      if (gmail?.is_authorized) {
        const mailbox: Mailbox = {
          id: 'mb-gmail-oauth',
          provider: 'gmail',
          email: gmail.user_email || 'Connected Gmail account',
          display_name: 'Gmail · Read-only Threat Monitoring',
          status: 'CONNECTED',
          last_synced_at: new Date().toISOString()
        };
        setUser({ email: mailbox.email, provider: 'gmail', role: 'Gmail Threat Analyst', authenticated_at: new Date().toISOString() });
        setActiveMailbox(mailbox);
        setConnectedMailboxes([mailbox]);
        setIsAuthenticated(true);
        setIsLoading(false);
        return;
      }
    } catch {
      // Gmail is optional; continue with the normal local login/demo flow.
    }

    // Fall back to a previously-entered demo session, if any
    const demoFlag = sessionStorage.getItem(DEMO_SESSION_KEY);
    if (demoFlag) {
      try {
        const demoObj = JSON.parse(demoFlag);
        if (demoObj.user) {
          setUser(demoObj.user);
          setActiveMailbox(demoObj.activeMailbox || null);
          setConnectedMailboxes(demoObj.connectedMailboxes || []);
          setIsAuthenticated(true);
          setIsLoading(false);
          return;
        }
      } catch {
        sessionStorage.removeItem(DEMO_SESSION_KEY);
      }
    }

    // Not authenticated at all
    setUser(null);
    setIsAuthenticated(false);
    setIsLoading(false);
  };

  useEffect(() => {
    refreshSession();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---------------------------------------------------------
  // Demo mode (explicit entry point, e.g. "Try Demo" button)
  // ---------------------------------------------------------

  const enterDemo = async (scenario: string = 'bec_wire_transfer') => {
    createDemoSession(scenario);
  };

  // ---------------------------------------------------------
  // Logout
  // ---------------------------------------------------------

  const logout = async () => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      try {
        await api.logout();
      } catch {
        // Backend unreachable — clear client state anyway
      }
    }

    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(DEMO_SESSION_KEY);

    setUser(null);
    setActiveMailbox(null);
    setConnectedMailboxes([]);
    setIsAuthenticated(false);
  };

  // ---------------------------------------------------------
  // Select mailbox
  // ---------------------------------------------------------

  const selectMailbox = async (id: string) => {
    const found = connectedMailboxes.find((m) => m.id === id);
    if (!found) return;

    setActiveMailbox(found);

    const demoFlag = sessionStorage.getItem(DEMO_SESSION_KEY);
    if (demoFlag) {
      try {
        const demoObj = JSON.parse(demoFlag);
        demoObj.activeMailbox = found;
        sessionStorage.setItem(DEMO_SESSION_KEY, JSON.stringify(demoObj));
      } catch {
        // ignore malformed session data
      }
    }
  };

  // ---------------------------------------------------------
  // Disconnect mailbox
  // ---------------------------------------------------------

  const disconnectMailbox = async (id: string) => {
    const remaining = connectedMailboxes.filter((m) => m.id !== id);
    setConnectedMailboxes(remaining);

    if (activeMailbox?.id === id) {
      if (remaining.length > 0) {
        setActiveMailbox(remaining[0]);
      } else {
        setActiveMailbox(null);
        setIsAuthenticated(false);
        setUser(null);
        localStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(DEMO_SESSION_KEY);
      }
    }
  };

  // The supplied P1 backend is an email analyzer, not a mailbox service.
  // Keep this connection local and never retain the submitted password.
  const connectImap = async (settings: { email: string; host: string; port: number; use_ssl: boolean; username: string; password?: string }) => {
    const mailbox: Mailbox = {
      id: `mb-imap-${crypto.randomUUID()}`,
      provider: 'imap',
      email: settings.email,
      display_name: `IMAP · ${settings.host}:${settings.port}`,
      status: 'CONNECTED',
      last_synced_at: new Date().toISOString()
    };
    setConnectedMailboxes((current) => [...current, mailbox]);
    setActiveMailbox(mailbox);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        activeMailbox,
        connectedMailboxes,
        isAuthenticated,
        isLoading,
        authError,
        login,
        enterDemo,
        logout,
        selectMailbox,
        disconnectMailbox,
        connectImap,
        refreshSession
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
