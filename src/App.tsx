import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { Navbar } from './components/Navbar';
import { UploadModal } from './components/UploadModal';
import { Dashboard } from './pages/Dashboard';
import { EmailMonitoring } from './pages/EmailMonitoring';
import { Investigation } from './pages/Investigation';
import { Cases } from './pages/Cases';
import { Campaigns } from './pages/Campaigns';

export function App() {
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  return (
    <ThemeProvider>
      <BrowserRouter>
        <div className="min-h-screen bg-app text-primaryText flex flex-col selection:bg-primary selection:text-white transition-colors duration-200">
          <Navbar onOpenUpload={() => setIsUploadOpen(true)} />
          
          <main className="flex-1 bg-app">
            <Routes>
              <Route path="/" element={<Dashboard onOpenUpload={() => setIsUploadOpen(true)} />} />
              <Route path="/monitoring" element={<EmailMonitoring />} />
              <Route path="/investigation" element={<Investigation />} />
              <Route path="/report/:id" element={<Investigation />} />
              <Route path="/report" element={<Investigation />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/campaigns" element={<Campaigns />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>

          <UploadModal isOpen={isUploadOpen} onClose={() => setIsUploadOpen(false)} />
        </div>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
