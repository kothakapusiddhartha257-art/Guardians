import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { X, UploadCloud, FileText, CheckCircle2, Sparkles, AlertTriangle } from 'lucide-react';
import { api } from '../api/client';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const DEMO_SAMPLES = [
  {
    id: 'bec',
    name: 'BEC Wire Transfer Fraud',
    desc: 'Spoofed CEO, Reply-To mismatch, urgent wire transfer directive',
    content: `Received: from mail-relay.internal.acme.com (10.0.1.5) by mx.acme.com with ESMTP id m12345; Mon, 31 Aug 2026 10:22:02 +0000
Received: from mail.secure-exchange-transfer.xyz (185.23.11.4) by mail-relay.internal.acme.com with ESMTPS id b67890; Mon, 31 Aug 2026 10:21:58 +0000
Received: from unknown (192.168.1.100) by mail.secure-exchange-transfer.xyz with HTTP; Mon, 31 Aug 2026 10:21:50 +0000
From: "CEO John Smith" <john.smith@acme.com>
Reply-To: "Executive Remittance" <finance-executive@secure-exchange-transfer.xyz>
Return-Path: <bounce@secure-exchange-transfer.xyz>
To: "Sarah Connor - Accounts Payable" <sarah.c@acme.com>
Subject: URGENT: Vendor Payment Account Change & Wire Transfer Directive
Date: Mon, 31 Aug 2026 10:21:45 +0000
Message-ID: <20260831102145.98765@secure-exchange-transfer.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Sarah,

I am currently in board meetings and unavailable by phone. We have an urgent vendor payment of $142,500 that must be settled immediately before close of business today.

The vendor's standard banking details have been updated due to an annual audit. Do not use the old banking information on file. Please remit the wire transfer to our new designated intermediary escrow account right away:

Beneficiary: Apex Logistics Holding LLC
Routing Number: 021000021
Account Number: 884920194829
Amount: $142,500.00 USD

Please reply directly to this email with the wire confirmation receipt as soon as processed. Treat this with immediate priority.

Regards,
John Smith
Chief Executive Officer
Acme Corporation`
  },
  {
    id: 'credential',
    name: 'Office 365 Credential Harvest',
    desc: 'Anchor text deception, IP-literal phishing link, homoglyph domain',
    content: `Received: from inbound.acme.com (10.0.1.2) by mx.acme.com with ESMTP id p9876; Mon, 31 Aug 2026 09:15:00 +0000
Received: from mail.m365-security-update.top (194.26.29.112) by inbound.acme.com with ESMTPS id q5432; Mon, 31 Aug 2026 09:14:55 +0000
From: "Microsoft 365 Support Team" <admin@m365-security-update.top>
Reply-To: "Microsoft Account Security" <support@m365-security-update.top>
To: "Employee" <staff@acme.com>
Subject: Action Required: Your Office 365 Password Expires in 24 Hours
Date: Mon, 31 Aug 2026 09:14:50 +0000
Message-ID: <00129384812@m365-security-update.top>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h2>Microsoft 365 Security Notice</h2>
<p>Your corporate Microsoft 365 access password will expire in 24 hours. To prevent account suspension and maintain uninterrupted email access, please verify your password immediately.</p>
<p><a href="http://194.26.29.112/auth/m365/login.php">https://login.microsoftonline.com/common/oauth2/authorize</a></p>
<p>If you do not verify your credentials within 24 hours, your mailbox will be locked by IT administration.</p>
</body>
</html>`
  },
  {
    id: 'malware',
    name: 'Invoice Malware (.exe disguised as .pdf)',
    desc: 'Executable magic bytes, double extension, TOR exit node relay',
    content: `Received: from mx.acme.com (10.0.1.1) by internal.acme.com id mal01; Mon, 31 Aug 2026 08:00:00 +0000
Received: from tor-relay.31173services.net (185.220.101.5) by mx.acme.com id mal02; Mon, 31 Aug 2026 07:59:50 +0000
From: "Billing Dept" <invoices@overdue-billing-notice.xyz>
To: "Accounting" <accounting@acme.com>
Subject: Overdue Invoice #88219 - Final Notice Before Legal Action
Date: Mon, 31 Aug 2026 07:59:40 +0000
Message-ID: <invoice-88219@overdue-billing-notice.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_MAL_99"

------=_Part_MAL_99
Content-Type: text/plain; charset=UTF-8

Attached is the final overdue invoice #88219.

------=_Part_MAL_99
Content-Type: application/pdf; name="Overdue_Invoice_8821.pdf.exe"
Content-Disposition: attachment; filename="Overdue_Invoice_8821.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_MAL_99--`
  }
];

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStage, setCurrentStage] = useState('');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSelectDemo = (content: string) => {
    setRawText(content);
    setSelectedFile(null);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setRawText('');
    }
  };

  const handleSubmit = async () => {
    if (!selectedFile && !rawText.trim()) {
      setError('Please upload an .eml file or select a threat preset');
      return;
    }

    setError(null);
    setIsProcessing(true);
    setProgress(10);
    setCurrentStage('Establishing Cryptographic Chain of Custody & Ingestion...');

    try {
      const res = await api.uploadEmail(selectedFile || undefined, rawText || undefined);
      
      const stages = [
        { name: 'MIME & Header Normalization (RFC 5322/2047)...', p: 30 },
        { name: 'Parallel Forensics: SPF, DKIM, DMARC, ARC Verification...', p: 50 },
        { name: 'SMTP Trust-Frontier Reconstruction & GeoIP Resolution...', p: 70 },
        { name: 'Domain Age Risk, URL Deception & Static Attachment Check...', p: 85 },
        { name: 'Decision-Level Risk Fusion & Cross-Case Graph Correlation...', p: 98 }
      ];

      for (const s of stages) {
        setCurrentStage(s.name);
        setProgress(s.p);
        await new Promise((r) => setTimeout(r, 220));
      }

      setProgress(100);
      setCurrentStage('Analysis Complete! Loading Evidence Dossier...');
      
      setTimeout(() => {
        setIsProcessing(false);
        onClose();
        navigate(`/investigation?id=${res.email_id}`);
      }, 300);

    } catch (err: any) {
      setIsProcessing(false);
      setError(err.message || 'Analysis pipeline execution failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-surfaceElevated border border-border rounded-3xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border/70 bg-surfaceSubtle">
          <div className="flex items-center gap-3">
            <div className="size-9 rounded-xl bg-primary/15 flex items-center justify-center text-primary">
              <UploadCloud className="size-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-primaryText">Ingest Digital Evidence (.EML)</h2>
              <p className="eyebrow text-[10px] text-mutedText">RFC 5322 MIME Parser & Automated Forensics DAG</p>
            </div>
          </div>
          {!isProcessing && (
            <button onClick={onClose} className="p-1.5 rounded-xl text-mutedText hover:text-primaryText hover:bg-surface transition-colors">
              <X className="size-5" />
            </button>
          )}
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {error && (
            <div className="p-3.5 rounded-xl bg-threatCritical/10 border border-threatCritical/30 flex items-center gap-3 text-threatCritical text-xs font-semibold">
              <AlertTriangle className="size-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {isProcessing ? (
            <div className="py-14 px-6 flex flex-col items-center justify-center text-center space-y-6">
              <div className="relative">
                <div className="size-16 rounded-full border-2 border-primary/20 border-t-primary animate-spin flex items-center justify-center" />
                <Sparkles className="size-6 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-pulse" />
              </div>
              <div className="space-y-2 max-w-md">
                <h3 className="text-lg font-bold text-primaryText">Executing Forensics DAG Pipeline</h3>
                <p className="text-xs font-mono text-primary animate-pulse">{currentStage}</p>
              </div>
              <div className="w-full max-w-md bg-surfaceSubtle rounded-full h-1.5 overflow-hidden border border-border/60">
                <div
                  className="h-full bg-primary transition-all duration-300 rounded-full"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <span className="eyebrow text-[10px]">{progress}% Complete</span>
            </div>
          ) : (
            <>
              {/* Presets */}
              <div className="space-y-2.5">
                <label className="eyebrow block">
                  Quick Load Demo Threat Scenarios
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {DEMO_SAMPLES.map((sample) => (
                    <button
                      key={sample.id}
                      onClick={() => handleSelectDemo(sample.content)}
                      className="p-3.5 rounded-2xl bg-surface hover:bg-surfaceElevated border border-border hover:border-primary/50 text-left transition-all group"
                    >
                      <div className="text-xs font-bold text-primaryText group-hover:text-primary transition-colors flex items-center justify-between">
                        <span>{sample.name}</span>
                        <FileText className="size-3.5 opacity-60 group-hover:opacity-100" />
                      </div>
                      <p className="text-[10.5px] text-secondaryText mt-1 line-clamp-2">{sample.desc}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Upload Dropzone */}
              <div className="space-y-2.5">
                <label className="eyebrow block">
                  Upload .EML File
                </label>
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all ${
                    selectedFile
                      ? 'border-threatSafe/50 bg-threatSafe/5'
                      : 'border-border hover:border-primary/60 bg-surfaceSubtle hover:bg-surface'
                  }`}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".eml,.msg,.txt"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  <div className="flex flex-col items-center gap-2">
                    <div className="size-10 rounded-xl bg-surface flex items-center justify-center text-secondaryText">
                      <UploadCloud className="size-5" />
                    </div>
                    {selectedFile ? (
                      <div className="flex items-center gap-2 text-threatSafe text-xs font-mono font-bold">
                        <CheckCircle2 className="size-4" />
                        <span>{selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                      </div>
                    ) : (
                      <>
                        <p className="text-xs font-semibold text-primaryText">
                          Click to browse or drag & drop an <code className="text-primary font-mono">.eml</code> file
                        </p>
                        <p className="eyebrow text-[10px]">RFC 5322 raw email messages up to 25MB</p>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Raw MIME Text Area */}
              <div className="space-y-2">
                <label className="eyebrow block">
                  Or Paste Raw MIME / Header Text
                </label>
                <textarea
                  value={rawText}
                  onChange={(e) => {
                    setRawText(e.target.value);
                    setSelectedFile(null);
                  }}
                  placeholder="Received: from ...&#10;From: ...&#10;Subject: ...&#10;&#10;Email body..."
                  rows={4}
                  className="w-full bg-surface border border-border rounded-2xl p-3 text-xs font-mono text-primaryText placeholder-mutedText focus:outline-none focus:border-primary transition-colors"
                />
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {!isProcessing && (
          <div className="px-6 py-4 border-t border-border/70 bg-surfaceSubtle flex items-center justify-end gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-secondaryText hover:text-primaryText transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={!selectedFile && !rawText.trim()}
              className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primaryDark disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold shadow-lg shadow-primary/25 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center gap-2"
            >
              <Sparkles className="size-4" />
              <span>Launch Investigation Pipeline</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
