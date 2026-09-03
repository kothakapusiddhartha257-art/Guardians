# TRACEGUARD AI — Chrome Extension (Manifest V3)

Thin-client Chromium browser extension for real-time Gmail threat inspection and forensic intelligence.

---

## 🚀 Key Features (v2)

1. **Thin-Client Forensic Ingestion**: Zero mock/client-side scoring. Raw RFC822 EML bytes are fetched via Gmail API (`format=raw`) and ingested into TRACEGUARD's 11-step Forensic DAG engine.
2. **Google OAuth 2.0 with Backend Exchange**: Authorizes `gmail.readonly` via Google Consent screen. Token exchange happens server-side without exposing secrets in the extension.
3. **Batch Inbox Scanning**: Inspects 10, 20, or 50 recent messages with real-time stage progress (`Evidence Preservation`, `Header Parsing`, `Cryptographic Auth`, `SMTP Relay Trace`, `ML & Homoglyphs`, `Campaign Correlation`).
4. **Shadow DOM In-Email Injection**: Injects `#traceguard-root` into Gmail with zero CSS bleed. Shows instant threat verdict banner and slide-out 400px forensic dossier.
5. **Multi-Theme Support**: Obsidian Forensics, Forensic Paper, Deep Space, and Midnight Violet.

---

## 🛠️ How to Install in Chrome / Brave / Edge

1. Open your browser and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` folder inside this repository:
   ```
   c:\Users\mukes\OneDrive\Desktop\MTZ!\extension
   ```
5. Click the TRACEGUARD extension icon in your browser toolbar.
6. Click **"Authorize with Google OAuth"** or **"Run Forensic Inbox Scan"**.
