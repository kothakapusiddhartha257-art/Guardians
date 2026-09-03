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
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <MainLayout />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
