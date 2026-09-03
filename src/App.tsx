import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { UploadModal } from './components/UploadModal';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { EmailMonitoring } from './pages/EmailMonitoring';
import { Investigation } from './pages/Investigation';
import { Cases } from './pages/Cases';
import { Campaigns } from './pages/Campaigns';

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: any }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  componentDidCatch(error: any, errorInfo: any) {
    console.error('[ErrorBoundary caught error]:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#07090E] text-white flex flex-col items-center justify-center p-8 space-y-4 font-mono">
          <div className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-[#EAB308]">
            <span className="text-2xl font-bold">🛡️</span>
          </div>
          <h2 className="text-xl font-bold">TRACEGUARD ACTIVE</h2>
          <p className="text-xs text-neutral-400 max-w-md text-center">
            Standalone interface initialized. Click below to enter the Live Threat Gateway.
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.href = '/monitoring';
            }}
            className="px-5 py-2.5 rounded-xl bg-[#EAB308] hover:bg-amber-500 text-black font-bold text-xs transition-colors"
          >
            Launch Threat Gateway
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// Protected Route Guard
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#07090E] text-white">
        <div className="flex items-center gap-3 font-mono text-xs">
          <span className="size-2 rounded-full bg-[#EAB308] animate-ping"></span>
          <span>ESTABLISHING TRACEGUARD SECURE GATEWAY...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

// Root Redirector based on session state
const RootRedirector: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return null;
  return <Navigate to={isAuthenticated ? "/monitoring" : "/login"} replace />;
};

function MainLayout() {
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const location = useLocation();
  const isLoginPage = location.pathname === '/login';

  return (
    <div className="min-h-screen bg-app text-primaryText flex flex-col selection:bg-primary selection:text-white transition-colors duration-200">
      {!isLoginPage && <Navbar onOpenUpload={() => setIsUploadOpen(true)} />}
      
      <main className="flex-1 bg-app">
        <Routes>
          {/* Default entry redirect */}
          <Route path="/" element={<RootRedirector />} />
          <Route path="/login" element={<Login />} />

          {/* Protected Application Routes */}
          <Route
            path="/monitoring"
            element={
              <ProtectedRoute>
                <EmailMonitoring />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard onOpenUpload={() => setIsUploadOpen(true)} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/investigation"
            element={
              <ProtectedRoute>
                <Investigation />
              </ProtectedRoute>
            }
          />
          <Route
            path="/report/:id"
            element={
              <ProtectedRoute>
                <Investigation />
              </ProtectedRoute>
            }
          />
          <Route
            path="/report"
            element={
              <ProtectedRoute>
                <Investigation />
              </ProtectedRoute>
            }
          />
          <Route
            path="/cases"
            element={
              <ProtectedRoute>
                <Cases />
              </ProtectedRoute>
            }
          />
          <Route
            path="/campaigns"
            element={
              <ProtectedRoute>
                <Campaigns />
              </ProtectedRoute>
            }
          />

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      <UploadModal isOpen={isUploadOpen} onClose={() => setIsUploadOpen(false)} />
    </div>
  );
}

export function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <AuthProvider>
          <BrowserRouter>
            <MainLayout />
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
