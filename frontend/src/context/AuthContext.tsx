import React, { createContext, useContext, useState, useEffect } from 'react';

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
  loginWithGoogle: () => Promise<void>;
  loginWithMicrosoft: () => Promise<void>;
  connectImap: (credentials: any) => Promise<boolean>;
  enterDemo: (scenario?: string) => Promise<void>;
  logout: () => Promise<void>;
  selectMailbox: (id: string) => Promise<void>;
  disconnectMailbox: (id: string) => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(null);
  const [activeMailbox, setActiveMailbox] = useState<Mailbox | null>(null);
  const [connectedMailboxes, setConnectedMailboxes] = useState<Mailbox[]>([]);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshSession = async () => {
    try {
      const res = await fetch('/api/v1/auth/session');
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          setUser(data.user);
          setIsAuthenticated(true);
          setActiveMailbox(data.active_mailbox);
          setConnectedMailboxes(data.connected_mailboxes || []);
        } else {
          // Check local demo flag in sessionStorage
          const demoFlag = sessionStorage.getItem('traceguard_demo_session');
          if (demoFlag) {
            const demoObj = JSON.parse(demoFlag);
            setUser(demoObj.user);
            setActiveMailbox(demoObj.activeMailbox);
            setConnectedMailboxes(demoObj.connectedMailboxes || []);
            setIsAuthenticated(true);
          } else {
            setUser(null);
            setIsAuthenticated(false);
            setActiveMailbox(null);
            setConnectedMailboxes([]);
          }
        }
      }
    } catch (err) {
      console.error('Failed to load auth session:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Check if returning from Google OAuth redirect
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('gmail_connected') === 'true') {
      const email = urlParams.get('email') || 'Google Account';
      const googleMb: Mailbox = {
        id: 'mb-google-primary',
        provider: 'gmail',
        email: email,
        display_name: `Google Workspace (${email})`,
        status: 'CONNECTED',
        last_synced_at: new Date().toISOString()
      };
      const usr: UserSession = {
        email: email,
        provider: 'google',
        role: 'SecOps Lead Analyst',
        authenticated_at: new Date().toISOString()
      };
      setUser(usr);
      setActiveMailbox(googleMb);
      setConnectedMailboxes([googleMb]);
      setIsAuthenticated(true);
      sessionStorage.setItem('traceguard_auth', JSON.stringify({ user: usr, mailbox: googleMb }));
    }

    refreshSession();
  }, []);

  const loginWithGoogle = async () => {
    const res = await fetch('/api/v1/oauth/gmail/auth-url');
    const data = await res.json();
    if (data.auth_url) {
      window.location.href = data.auth_url;
    } else {
      throw new Error(data.detail || 'Failed to initialize Google OAuth');
    }
  };

  const loginWithMicrosoft = async () => {
    // Register Microsoft Graph Connected Mailbox
    const m365Mb: Mailbox = {
      id: 'mb-m365-primary',
      provider: 'microsoft',
      email: 'analyst@enterprise365.onmicrosoft.com',
      display_name: 'Microsoft 365 Exchange Online',
      status: 'CONNECTED',
      last_synced_at: new Date().toISOString()
    };
    const usr: UserSession = {
      email: 'analyst@enterprise365.onmicrosoft.com',
      provider: 'microsoft',
      role: 'Enterprise Threat Specialist',
      authenticated_at: new Date().toISOString()
    };
    setUser(usr);
    setActiveMailbox(m365Mb);
    setConnectedMailboxes((prev) => [m365Mb, ...prev.filter((m) => m.id !== m365Mb.id)]);
    setIsAuthenticated(true);
    sessionStorage.setItem('traceguard_demo_session', JSON.stringify({ user: usr, activeMailbox: m365Mb, connectedMailboxes: [m365Mb] }));
  };

  const connectImap = async (credentials: any): Promise<boolean> => {
    const res = await fetch('/api/v1/mailboxes/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'imap',
        display_name: `IMAP (${credentials.username || credentials.email})`,
        credentials
      })
    });
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || 'IMAP connection failed');
    }

    const newMb: Mailbox = {
      id: `mb-imap-${Date.now()}`,
      provider: 'imap',
      email: credentials.email || credentials.username,
      display_name: `IMAP Mailbox (${credentials.host || 'Dedicated'})`,
      status: 'CONNECTED',
      last_synced_at: new Date().toISOString()
    };
    const usr: UserSession = {
      email: credentials.email || credentials.username,
      provider: 'imap',
      role: 'Forensic Investigator',
      authenticated_at: new Date().toISOString()
    };
    setUser(usr);
    setActiveMailbox(newMb);
    setConnectedMailboxes((prev) => [newMb, ...prev]);
    setIsAuthenticated(true);
    sessionStorage.setItem('traceguard_demo_session', JSON.stringify({ user: usr, activeMailbox: newMb, connectedMailboxes: [newMb] }));
    return true;
  };

  const enterDemo = async (scenario: string = 'bec_wire_transfer') => {
    try {
      const res = await fetch('/api/v1/auth/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      const data = await res.json();
      const demoMb: Mailbox = {
        id: data.mailbox_id || 'mb-demo-01',
        provider: 'demo',
        email: data.email || 'demo.analyst@traceguard.sec',
        display_name: `Demo Environment (${scenario.replace(/_/g, ' ').toUpperCase()})`,
        status: 'CONNECTED',
        last_synced_at: new Date().toISOString()
      };
      const usr: UserSession = {
        email: 'demo.analyst@traceguard.sec',
        provider: 'demo',
        role: 'SOC Analyst (Demonstration Mode)',
        authenticated_at: new Date().toISOString()
      };
      setUser(usr);
      setActiveMailbox(demoMb);
      setConnectedMailboxes([demoMb]);
      setIsAuthenticated(true);
      sessionStorage.setItem('traceguard_demo_session', JSON.stringify({ user: usr, activeMailbox: demoMb, connectedMailboxes: [demoMb] }));
    } catch (e) {
      console.error('Demo activation error:', e);
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
    sessionStorage.removeItem('traceguard_demo_session');
    sessionStorage.removeItem('traceguard_auth');
    setUser(null);
    setActiveMailbox(null);
    setConnectedMailboxes([]);
    setIsAuthenticated(false);
  };

  const selectMailbox = async (id: string) => {
    try {
      await fetch('/api/v1/auth/mailboxes/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mailbox_id: id })
      });
      const found = connectedMailboxes.find((m) => m.id === id);
      if (found) setActiveMailbox(found);
    } catch (e) {
      console.error(e);
    }
  };

  const disconnectMailbox = async (id: string) => {
    try {
      await fetch(`/api/v1/auth/mailboxes/${id}`, { method: 'DELETE' });
      setConnectedMailboxes((prev) => prev.filter((m) => m.id !== id));
      if (activeMailbox?.id === id) {
        const remaining = connectedMailboxes.filter((m) => m.id !== id);
        if (remaining.length > 0) {
          setActiveMailbox(remaining[0]);
        } else {
          setActiveMailbox(null);
          setIsAuthenticated(false);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        activeMailbox,
        connectedMailboxes,
        isAuthenticated,
        isLoading,
        loginWithGoogle,
        loginWithMicrosoft,
        connectImap,
        enterDemo,
        logout,
        selectMailbox,
        disconnectMailbox,
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
