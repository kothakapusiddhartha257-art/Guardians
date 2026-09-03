# TRACEGUARD AI — Chromium Browser Extension (Manifest V3)
## AI-Powered Email Threat Detection, In-Page Forensics & Gateway Bridge

Thin-client Chromium browser extension for Google Chrome, Brave, and Microsoft Edge. Provides real-time email threat detection, an overview of detected enterprise threats, instant forensic scanning, and deep redirection to the TRACEGUARD AI SOC console.

---

## 🚀 Key Features

1. **Threat Overview & SOC Intelligence:**
   - Real-time enterprise threat metrics (Ingested Emails, Critical Threats, Active Cases, Threat Clusters) queried directly from the local API gateway (`http://127.0.0.1:8000`).
   - Recent threat feed showing threat scores, severity pills, and 1-click inspection of historical attacks.
2. **Instant Threat Scanner:**
   - **Pre-configured Attack Vectors**: Launch instant scans of real attack scenarios (*BEC Wire Transfer Fraud $142.5K*, *Microsoft 365 Credential Harvester*, *Ransomware Invoice .pdf.exe*, *Clean Corporate Newsletter*).
   - **Active Webmail Tab Inspector**: One-click extraction and real-time analysis of the email currently open in Gmail or Outlook.
   - **Custom Raw EML Input**: Paste custom MIME headers or raw text for immediate 11-stage DAG processing.
3. **Direct Main Website Redirection:**
   - **Header Quick-Action**: Prominent `Web Console ↗` button always visible to launch `http://127.0.0.1:5173`.
   - **Overview Launcher**: Direct link to open the full SOC Operations Dashboard.
   - **Deep Forensic Dossier Link**: Every scanned email includes an `OPEN FULL INVESTIGATION ON MAIN WEBSITE ↗` button that deep-links directly to `http://127.0.0.1:5173/investigation?id={email_id}`.
4. **Google Workspace / Gmail OAuth 2.0 Ingestion:**
   - Authorizes read-only access (`gmail.readonly`) with token exchange handled securely by the backend gateway.
   - Batch inbox scanning (10, 20, or 50 messages) with live stage-by-stage DAG progress bar.
5. **In-Page Shadow DOM Gmail Injection:**
   - Injects `#traceguard-root` into Gmail with zero style leakage.
   - Renders instant threat verdict banners and slide-out 400px forensic dossiers.
6. **Multi-Theme Support:**
   - Obsidian (default), Forensic Paper, Deep Space, and Midnight Violet.

---

## 🛠️ Step-by-Step Installation (Chrome / Brave / Edge)

1. Open your browser and navigate to the extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
2. Toggle on **Developer mode** in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the extension directory in this workspace:
   ```
   c:\Users\mukes\OneDrive\Desktop\Guardians-sid\extension
   ```
5. The **TRACEGUARD AI — Email Threat Intelligence** extension will appear in your toolbar.
6. Pin the extension to your toolbar for quick access.

---

## ⚡ How to Use

### 1. View Threat Overview
- Click the TRACEGUARD shield icon in your browser toolbar.
- The **Overview** tab displays real-time SOC threat metrics and recent flagged emails.
- Click **"🌐 Open Main Website Console (Dashboard) ↗"** to jump straight into the full web application at `http://127.0.0.1:5173`.

### 2. Run a Threat Scan
- Click the **Scanner** tab in the popup.
- Choose an attack scenario (e.g. *Critical BEC Wire Transfer*) and click **"⚡ Launch Forensic Threat Scan"**.
- Watch the live 11-stage pipeline progress and inspect the resulting **3-Axis Threat Score**, **Sender Identity Spoof Analysis**, and **SPF/DKIM/DMARC** protocol checks.
- Click **"OPEN FULL INVESTIGATION ON MAIN WEBSITE ↗"** to view the interactive flight-path GeoIP map, vertical SMTP relay trust frontier, and cross-case indicator graph on `http://127.0.0.1:5173`.

### 3. Inspect Active Gmail / Outlook Email
- Open any email in `https://mail.google.com/`.
- In the TRACEGUARD popup, click **"Scan Open Webmail Tab"**.
- The in-page content script extracts the email and displays the threat verdict.
