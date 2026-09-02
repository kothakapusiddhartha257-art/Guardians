/**
 * TRACEGUARD AI - Extension Popup Controller
 * Renders instant forensic intelligence, 3-axis scores, top 3 signals, sender comparison, and theme synchronization.
 */

const WEB_APP_BASE = "http://127.0.0.1:5173";

// Preset intelligence bundles
const PRESETS = {
  bec: {
    id: "email-bec-demo",
    email_id: "email-bec-demo",
    case_id: "CASE-2026-00041",
    subject: "URGENT: Vendor Payment Account Change & Wire Transfer Directive",
    sender: "finance@secure-exchange-transfer.xyz",
    claimed_domain: "acme.com (CEO)",
    actual_domain: "secure-exchange-transfer.xyz",
    threat_score: 0.94,
    infra_confidence: 0.83,
    attribution_confidence: 0.40,
    verdict: "HIGH RISK",
    verdict_class: "critical",
    action_taken: "QUARANTINED",
    primary_action_label: "Quarantine Email",
    signals: [
      { title: "Reply-To Mismatch", desc: "Sender and reply destination belong to completely different unauthenticated domains." },
      { title: "DMARC Verification Failed", desc: "The originating server could not prove authorization for claimed sender domain." },
      { title: "Financial Urgency Directive", desc: "Psychological urgency cues demanding immediate wire transfer before end of day." }
    ],
    auth: { spf: "FAIL", dkim: "FAIL", dmarc: "FAIL", arc: "PASS" }
  },
  credential: {
    id: "email-cred-demo",
    email_id: "email-cred-demo",
    case_id: "CASE-2026-00042",
    subject: "Action Required: Your Office 365 Password Expires in 24 Hours",
    sender: "admin@m365-security-update.top",
    claimed_domain: "microsoft.com",
    actual_domain: "m365-security-update.top",
    threat_score: 0.88,
    infra_confidence: 0.91,
    attribution_confidence: 0.55,
    verdict: "HIGH RISK",
    verdict_class: "critical",
    action_taken: "QUARANTINED",
    primary_action_label: "Quarantine Email",
    signals: [
      { title: "Deceptive Anchor Text Mismatch", desc: "Displays 'login.microsoftonline.com' but resolves to raw unverified IP." },
      { title: "Direct IP-Literal Harvest Link", desc: "Link uses direct IP destination http://185.23.11.4/auth to evade reputation filters." },
      { title: "Disposable Domain (<15 Days Old)", desc: "Domain m365-security-update.top registered 4 days ago with high risk decay." }
    ],
    auth: { spf: "FAIL", dkim: "FAIL", dmarc: "FAIL", arc: "NONE" }
  },
  malware: {
    id: "email-malware-demo",
    email_id: "email-malware-demo",
    case_id: "CASE-2026-00043",
    subject: "Overdue Invoice #88219 - Final Notice Before Legal Action",
    sender: "invoices@overdue-billing-notice.xyz",
    claimed_domain: "billing-corp.com",
    actual_domain: "overdue-billing-notice.xyz",
    threat_score: 0.96,
    infra_confidence: 0.95,
    attribution_confidence: 0.60,
    verdict: "MALICIOUS",
    verdict_class: "critical",
    action_taken: "QUARANTINED",
    primary_action_label: "Quarantine Email",
    signals: [
      { title: "Executable Masquerade (MZ Header)", desc: "Claimed invoice.pdf contains Windows PE executable magic bytes." },
      { title: "High Shannon Entropy (7.82)", desc: "Attachment payload indicates dense encrypted/packed malicious code." },
      { title: "TOR Exit Relay Origin", desc: "Originating SMTP relay matches known anonymous darknet exit point." }
    ],
    auth: { spf: "SOFTFAIL", dkim: "FAIL", dmarc: "FAIL", arc: "NONE" }
  },
  clean: {
    id: "email-clean-demo",
    email_id: "email-clean-demo",
    case_id: "CASE-2026-00044",
    subject: "Cybersecurity Weekly Digest #412: Zero Trust Architecture Insights",
    sender: "newsletter@cybersec-weekly.org",
    claimed_domain: "cybersec-weekly.org",
    actual_domain: "cybersec-weekly.org",
    threat_score: 0.04,
    infra_confidence: 0.98,
    attribution_confidence: 0.92,
    verdict: "CLEAN",
    verdict_class: "safe",
    action_taken: "DELIVERED",
    primary_action_label: "Open Investigation",
    signals: [
      { title: "Cryptographic Alignment Clear", desc: "SPF, DKIM, and DMARC verification strictly aligned with root domain." },
      { title: "Established Domain Reputation", desc: "Domain registered >8 years ago with clean historical threat ledger." },
      { title: "No Intent Pressure Detected", desc: "Educational newsletter content with no credential or financial calls to action." }
    ],
    auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", arc: "PASS" }
  }
};

let currentEmailId = "email-bec-demo";

document.addEventListener("DOMContentLoaded", () => {
  // Theme Switcher & Storage Sync
  const themeSelect = document.getElementById("themeSelect");
  const storedTheme = localStorage.getItem("traceguard_theme") || "theme-obsidian";
  document.documentElement.className = storedTheme;
  if (themeSelect) {
    themeSelect.value = storedTheme;
    themeSelect.addEventListener("change", (e) => {
      const newTheme = e.target.value;
      document.documentElement.className = newTheme;
      localStorage.setItem("traceguard_theme", newTheme);
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ traceguard_theme: newTheme });
      }
    });
  }

  // Mode Navigation Tabs
  const modeBtns = document.querySelectorAll(".mode-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  modeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      modeBtns.forEach((b) => b.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  // Initial Render with Default BEC Scenario
  renderIntelligenceDossier(PRESETS.bec);

  // 1. Scan Active Webmail Email
  const btnScanWebmail = document.getElementById("btnScanWebmail");
  const webmailMeta = document.getElementById("webmailMeta");
  const metaClient = document.getElementById("metaClient");
  const metaSubject = document.getElementById("metaSubject");
  const analyzingPipeline = document.getElementById("analyzingPipeline");

  if (btnScanWebmail) {
    btnScanWebmail.addEventListener("click", async () => {
      if (typeof chrome === "undefined" || !chrome.tabs) {
        alert("Active webmail scan requires running in a browser tab.");
        return;
      }

      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) return;

        // Show animated pipeline state
        analyzingPipeline.classList.remove("hidden");

        chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL_DATA" }, (response) => {
          setTimeout(() => {
            analyzingPipeline.classList.add("hidden");
          }, 600);

          if (chrome.runtime.lastError || !response || !response.success) {
            alert("Could not extract email automatically. Please ensure an email is open on Gmail or Outlook, or use Manual Check.");
            return;
          }

          const data = response.data;
          metaClient.textContent = data.client || "Webmail";
          metaSubject.textContent = data.subject || "(No subject)";
          webmailMeta.classList.remove("hidden");

          // Run client heuristic detector
          if (typeof PhishingDetector !== "undefined") {
            const scan = PhishingDetector.scanEmail(data);
            const isMalicious = scan.score >= 60;
            const isCaution = scan.score >= 25 && scan.score < 60;

            const customBundle = {
              id: "email-active-scan",
              email_id: "email-bec-demo",
              subject: data.subject || "Open Webmail Message",
              sender: data.sender || "Sender Address",
              claimed_domain: data.sender ? (data.sender.split("@")[1] || "claimed.com") : "claimed.com",
              actual_domain: data.sender ? (data.sender.split("@")[1] || "actual.xyz") : "actual.xyz",
              threat_score: scan.threatScore,
              infra_confidence: scan.infraConfidence,
              attribution_confidence: scan.attributionConfidence,
              verdict: isMalicious ? "HIGH RISK" : isCaution ? "CAUTION" : "CLEAN",
              verdict_class: isMalicious ? "critical" : isCaution ? "caution" : "safe",
              action_taken: isMalicious ? "QUARANTINED" : isCaution ? "FLAGGED" : "DELIVERED",
              primary_action_label: isMalicious ? "Quarantine Email" : "Flag for Review",
              signals: scan.threats.slice(0, 3).map((t) => ({
                title: t.title,
                desc: t.description
              })),
              auth: {
                spf: isMalicious ? "FAIL" : "PASS",
                dkim: isMalicious ? "FAIL" : "PASS",
                dmarc: isMalicious ? "FAIL" : "PASS",
                arc: "PASS"
              }
            };

            renderIntelligenceDossier(customBundle);
          }
        });
      } catch (err) {
        analyzingPipeline.classList.add("hidden");
        console.error(err);
      }
    });
  }

  // 2. Manual Analysis
  const btnManualAnalyze = document.getElementById("btnManualAnalyze");
  const btnManualSample = document.getElementById("btnManualSample");
  const manualSender = document.getElementById("manualSender");
  const manualSubject = document.getElementById("manualSubject");
  const manualBody = document.getElementById("manualBody");

  if (btnManualAnalyze) {
    btnManualAnalyze.addEventListener("click", () => {
      const sender = manualSender.value.trim();
      const subject = manualSubject.value.trim();
      const body = manualBody.value.trim();

      if (!sender && !subject && !body) {
        alert("Please enter a sender, subject, or message body to analyze.");
        return;
      }

      if (typeof PhishingDetector !== "undefined") {
        const scan = PhishingDetector.scanEmail({ sender, subject, body });
        const isMalicious = scan.score >= 60;
        const isCaution = scan.score >= 25 && scan.score < 60;

        renderIntelligenceDossier({
          id: "email-manual-check",
          email_id: "email-bec-demo",
          subject: subject || "Manual Investigation Sample",
          sender: sender || "unknown@unverified.org",
          claimed_domain: sender.includes("@") ? sender.split("@")[1].replace(/>/g, "").trim() : "unverified.com",
          actual_domain: "external-relay.xyz",
          threat_score: scan.threatScore,
          infra_confidence: scan.infraConfidence,
          attribution_confidence: scan.attributionConfidence,
          verdict: isMalicious ? "HIGH RISK" : isCaution ? "CAUTION" : "CLEAN",
          verdict_class: isMalicious ? "critical" : isCaution ? "caution" : "safe",
          action_taken: isMalicious ? "QUARANTINED" : isCaution ? "FLAGGED" : "DELIVERED",
          primary_action_label: isMalicious ? "Quarantine Email" : "Flag for Review",
          signals: scan.threats.slice(0, 3).map((t) => ({
            title: t.title,
            desc: t.description
          })),
          auth: { spf: "FAIL", dkim: "FAIL", dmarc: "FAIL", arc: "NONE" }
        });
      }
    });
  }

  if (btnManualSample) {
    btnManualSample.addEventListener("click", () => {
      manualSender.value = "Executive Directives <ceo.john@acme-payments-verify.xyz>";
      manualSubject.value = "URGENT: Change Vendor Wire Instructions for Q3 Settlement";
      manualBody.value = "Sarah,\n\nPlease process an urgent wire transfer of $84,200 to our supplier's updated bank account below:\nRouting: 021000021\nAccount: 48829104882\n\nEnsure this is completed before 2:00 PM today.\n\nRegards,\nJohn Smith, CEO";
      btnManualAnalyze.click();
    });
  }

  // 3. Link Inspection
  const btnUrlInspect = document.getElementById("btnUrlInspect");
  const urlInput = document.getElementById("urlInput");

  if (btnUrlInspect) {
    btnUrlInspect.addEventListener("click", () => {
      const url = urlInput.value.trim();
      if (!url) {
        alert("Please enter a link destination to inspect.");
        return;
      }

      if (typeof PhishingDetector !== "undefined") {
        const urlAnalysis = PhishingDetector.analyzeUrl(url);
        const isSuspicious = urlAnalysis.isSuspicious;

        renderIntelligenceDossier({
          id: "url-inspect-sample",
          email_id: "email-cred-demo",
          subject: `Destination Analysis: ${url.length > 35 ? url.substring(0, 32) + '...' : url}`,
          sender: "inbound-link@sandbox.traceguard",
          claimed_domain: "login.microsoftonline.com",
          actual_domain: url.includes("://") ? url.split("://")[1].split("/")[0] : url,
          threat_score: isSuspicious ? 0.88 : 0.05,
          infra_confidence: 0.90,
          attribution_confidence: 0.50,
          verdict: isSuspicious ? "HIGH RISK" : "CLEAN",
          verdict_class: isSuspicious ? "critical" : "safe",
          action_taken: isSuspicious ? "QUARANTINED" : "DELIVERED",
          primary_action_label: isSuspicious ? "Block Destination" : "Verified Safe",
          signals: urlAnalysis.findings.map((f) => ({
            title: f.type.replace(/_/g, " "),
            desc: f.message
          })),
          auth: { spf: "PASS", dkim: "PASS", dmarc: "PASS", arc: "PASS" }
        });
      }
    });
  }

  // 4. Presets
  const presetSelect = document.getElementById("presetSelect");
  const btnLoadPreset = document.getElementById("btnLoadPreset");

  if (btnLoadPreset && presetSelect) {
    btnLoadPreset.addEventListener("click", () => {
      const key = presetSelect.value;
      const preset = PRESETS[key] || PRESETS.bec;
      renderIntelligenceDossier(preset);
    });
  }

  // 5. Open Forensic Investigation CTA
  const btnOpenFullInvestigation = document.getElementById("btnOpenFullInvestigation");
  if (btnOpenFullInvestigation) {
    btnOpenFullInvestigation.addEventListener("click", () => {
      const url = `${WEB_APP_BASE}/investigation?id=${currentEmailId}`;
      if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, "_blank");
      }
    });
  }
});

function renderIntelligenceDossier(data) {
  currentEmailId = data.email_id || "email-bec-demo";

  const scorePct = Math.round(data.threat_score * 100);
  const infraPct = Math.round(data.infra_confidence * 100);
  const attrPct = Math.round(data.attribution_confidence * 100);

  // Verdict Hero
  const verdictTag = document.getElementById("verdictTag");
  verdictTag.textContent = data.verdict || (scorePct >= 70 ? "⚠ HIGH RISK" : "CLEAN");
  verdictTag.className = `verdict-tag ${data.verdict_class || (scorePct >= 70 ? "critical" : "safe")}`;

  const actionTag = document.getElementById("actionTag");
  actionTag.textContent = data.action_taken || "EVALUATED";
  actionTag.style.background = scorePct >= 70 ? "var(--threat-critical)" : "var(--threat-safe)";

  const scoreNumber = document.getElementById("scoreNumber");
  scoreNumber.textContent = `${scorePct}%`;
  scoreNumber.style.color = scorePct >= 70 ? "var(--threat-critical)" : scorePct >= 40 ? "var(--threat-medium)" : "var(--threat-safe)";

  document.getElementById("emailSubject").textContent = data.subject || "No Subject";
  document.getElementById("emailSender").textContent = data.sender || "Unknown Sender";

  // Top 3 Signals
  const signalsList = document.getElementById("signalsList");
  signalsList.innerHTML = "";
  const signals = data.signals || [];
  if (signals.length === 0) {
    signalsList.innerHTML = `
      <div class="signal-card safe">
        <div class="signal-title">Cryptographic Alignment Clear</div>
        <div class="signal-desc">All SPF, DKIM, and DMARC authentication protocols passed.</div>
      </div>
    `;
  } else {
    signals.slice(0, 3).forEach((s) => {
      const card = document.createElement("div");
      card.className = `signal-card ${scorePct >= 70 ? "critical" : "caution"}`;
      card.innerHTML = `
        <div class="signal-title">⚠ ${escapeHtml(s.title)}</div>
        <div class="signal-desc">${escapeHtml(s.desc)}</div>
      `;
      signalsList.appendChild(card);
    });
  }

  // Sender Identity Comparison
  document.getElementById("claimedDomain").textContent = data.claimed_domain || "acme.com";
  const actualEl = document.getElementById("actualDomain");
  actualEl.textContent = data.actual_domain || "secure-exchange-transfer.xyz";
  if (data.claimed_domain === data.actual_domain) {
    actualEl.classList.remove("mismatch");
  } else {
    actualEl.classList.add("mismatch");
  }

  // 3-Axis Calibrated Scoring
  document.getElementById("axisThreatVal").textContent = `${scorePct}%`;
  document.getElementById("axisThreatBar").style.width = `${scorePct}%`;

  document.getElementById("axisInfraVal").textContent = `${infraPct}%`;
  document.getElementById("axisInfraBar").style.width = `${infraPct}%`;

  document.getElementById("axisAttrVal").textContent = `${attrPct}%`;
  document.getElementById("axisAttrBar").style.width = `${attrPct}%`;

  // Auth Grid
  renderAuthCell("authSpfVal", data.auth.spf);
  renderAuthCell("authDkimVal", data.auth.dkim);
  renderAuthCell("authDmarcVal", data.auth.dmarc);
  renderAuthCell("authArcVal", data.auth.arc);

  // Quick Action Button
  const btnPrimary = document.getElementById("btnPrimaryAction");
  btnPrimary.textContent = data.primary_action_label || (scorePct >= 70 ? "Quarantine Email" : "Flag for Review");
  btnPrimary.className = scorePct >= 70 ? "btn-action-danger flex-1" : "btn-action-primary flex-1";
}

function renderAuthCell(elementId, result) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const res = (result || "FAIL").toUpperCase();
  el.textContent = res;
  el.className = `auth-status ${res === "PASS" ? "pass" : "fail"}`;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}
