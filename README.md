# TRACEGUARD AI — Frontend Platform

**Autonomous Email Threat Defense, Digital Evidence & Forensic Intelligence Platform**

This is the standalone frontend repository and workspace for **TRACEGUARD AI**. It contains the complete user interface, editorial entry experience, interactive forensic investigation workstation, and multi-mailbox connection flows.

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- [npm](https://www.npmjs.com/)

### Installation & Launch

```bash
# 1. Install dependencies
npm install

# 2. Start development server
npm run dev
```

The application will be running at:
👉 **`http://127.0.0.1:5173/`** (automatically redirects to **`/login`**)

---

## 🖥️ What's Included

### 1. Editorial Entry Experience (`/login`)
- Atmospheric **SideRays** volumetric lighting background engine.
- Editorial typography: *"EVERY EMAIL LEAVES A TRAIL."*
- Forensic intelligence progression pipeline: `EMAIL ──▶ IDENTITY ──▶ INFRASTRUCTURE ──▶ INTELLIGENCE ──▶ VERDICT`.
- **Google OAuth 2.0**: Direct PKCE sign-in with Google.
- **Microsoft 365 / Exchange**: Enterprise OAuth sign-in.
- **IMAP Connection Modal**: Secure Host, Port 993, SSL/TLS, and credential handling.
- **Demo Sandbox Environment**: Instant launcher for seeded threat scenarios (BEC Wire Transfer, M365 Phish, Binary Malware, Clean Advisory) without requiring external credentials.

### 2. Live Threat Gateway (`/monitoring`)
- Real-time inbound threat stream.
- Live threat classification pills: `CRITICAL`, `SUSPICIOUS`, `SAFE`.
- Mailbox status indicators (`● Gmail Connected`, `● Demo Mode`, etc.).
- Direct drill-down to forensic investigations.

### 3. Forensic Investigation Workstation (`/investigation` & `/report/:id`)
- 11-stage forensic dossier inspection.
- Leaflet map visualization for SMTP relay hops and geographical server origin tracing.
- Cryptographic authentication results: SPF, DKIM, DMARC, ARC.
- Masqueraded attachment & PE header analysis.
- Tamper-evident SHA-256 digital evidence chain.
- Exportable STIX 2.1 threat intelligence bundles and PDF forensic reports.

### 4. SOC Dashboard (`/dashboard`)
- Real-time threat volume trend charts (Recharts).
- 3-axis threat evaluation scorecards (Threat Severity, Infrastructure Trust, Attribution Confidence).
- Recent threat activity feed.

### 5. Case Management (`/cases`) & Threat Campaigns (`/campaigns`)
- Centralized SOC incident triage.
- Threat actor attribution and campaign cluster correlation graphs.

---

## 🛠️ Build for Production

```bash
# Build optimized production bundle
npm run build

# Preview production build locally
npm run preview
```

---

## 🔌 Backend Connectivity

- When paired with the FastAPI backend, requests are automatically proxied to `http://127.0.0.1:8000`.
- When run completely standalone, the built-in fallback client (`src/api/client.ts`) provides high-fidelity forensic data so that every page, chart, and modal is fully functional.
