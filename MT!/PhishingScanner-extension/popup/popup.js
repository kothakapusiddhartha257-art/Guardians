/**
 * Phishing Shield - Popup UI Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  const btnScanActive = document.getElementById("btn-scan-active");
  const activeMeta = document.getElementById("active-meta");
  const metaClient = document.getElementById("meta-client");
  const metaSender = document.getElementById("meta-sender");
  const metaSubject = document.getElementById("meta-subject");

  const manualSender = document.getElementById("manual-sender");
  const manualSubject = document.getElementById("manual-subject");
  const manualBody = document.getElementById("manual-body");
  const btnManualScan = document.getElementById("btn-manual-scan");
  const btnManualSample = document.getElementById("btn-manual-sample");

  const urlInput = document.getElementById("url-input");
  const btnUrlScan = document.getElementById("btn-url-scan");

  const resultsContainer = document.getElementById("results-container");
  const dialFill = document.getElementById("dial-fill");
  const scoreNumber = document.getElementById("score-number");
  const verdictBadge = document.getElementById("verdict-badge");
  const verdictSummary = document.getElementById("verdict-summary");
  const threatCount = document.getElementById("threat-count");
  const threatUrlCount = document.getElementById("threat-url-count");
  const threatList = document.getElementById("threat-list");

  // Tab switching
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetTab = document.getElementById(btn.dataset.tab);
      if (targetTab) targetTab.classList.add("active");
    });
  });

  // Check storage for any recent background scan result
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["lastScan"], (res) => {
      if (res && res.lastScan && res.lastScan.result) {
        displayResults(res.lastScan.result);
      }
    });
  }

  // 1. Scan Active Email
  btnScanActive.addEventListener("click", async () => {
    btnScanActive.disabled = true;
    btnScanActive.querySelector(".btn-text").innerText = "Extracting email...";

    try {
      if (typeof chrome === "undefined" || !chrome.tabs) {
        throw new Error("Chrome Tabs API not available.");
      }

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) throw new Error("No active tab found.");

      chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL_DATA" }, (response) => {
        btnScanActive.disabled = false;
        btnScanActive.querySelector(".btn-text").innerText = "Scan Open Email";

        if (chrome.runtime.lastError || !response || !response.success) {
          // Fallback if not on supported webmail
          alert("Could not extract email automatically from this tab. Please ensure you have an open email in Gmail or Outlook, or use the 'Manual Check' tab.");
          return;
        }

        const data = response.data;
        // Update meta preview
        metaClient.innerText = data.client || "Webmail";
        metaSender.innerText = data.sender || "(Not detected)";
        metaSubject.innerText = data.subject || "(No subject)";
        activeMeta.classList.remove("hidden");

        // Run detection
        const analysis = PhishingDetector.scanEmail(data);
        displayResults(analysis);
      });
    } catch (err) {
      btnScanActive.disabled = false;
      btnScanActive.querySelector(".btn-text").innerText = "Scan Open Email";
      alert("Error: " + err.message);
    }
  });

  // 2. Manual Scan
  btnManualScan.addEventListener("click", () => {
    const sender = manualSender.value.trim();
    const subject = manualSubject.value.trim();
    const body = manualBody.value.trim();

    if (!sender && !subject && !body) {
      alert("Please enter at least a sender, subject, or email body to analyze.");
      return;
    }

    const analysis = PhishingDetector.scanEmail({ sender, subject, body });
    displayResults(analysis);
  });

  // Load sample phishing email
  btnManualSample.addEventListener("click", () => {
    manualSender.value = "PayPal Security <alert-support@paypaI-verify.xyz>";
    manualSubject.value = "URGENT: Your PayPal Account Has Been Suspended (Action Required)";
    manualBody.value = "Dear Customer,\n\nWe detected unauthorized access to your account. Your account has been temporarily restricted.\n\nTo restore your account and verify your identity within 24 hours, click below:\nhttp://bit.ly/paypal-secure-login-update\n\nIf you do not update billing info, your account will be permanently terminated.\n\nThank you,\nPayPal Security Team";
    
    // Auto-analyze sample
    const analysis = PhishingDetector.scanEmail({
      sender: manualSender.value,
      subject: manualSubject.value,
      body: manualBody.value
    });
    displayResults(analysis);
  });

  // 3. URL Scan
  btnUrlScan.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) {
      alert("Please enter a URL to inspect.");
      return;
    }

    const urlAnalysis = PhishingDetector.analyzeUrl(url);
    const analysis = {
      score: urlAnalysis.isSuspicious ? Math.max(50, urlAnalysis.weight) : 0,
      riskLevel: urlAnalysis.isSuspicious ? (urlAnalysis.weight >= 40 ? "DANGER" : "CAUTION") : "SAFE",
      riskColor: urlAnalysis.isSuspicious ? (urlAnalysis.weight >= 40 ? "#ef4444" : "#f59e0b") : "#10b981",
      summaryText: urlAnalysis.isSuspicious
        ? "Suspicious traits identified in URL structure."
        : "No suspicious patterns identified in this URL.",
      threats: urlAnalysis.findings.map(f => ({
        category: "URL Structure",
        severity: f.severity,
        title: f.type.replace(/_/g, " "),
        description: f.message
      })),
      urlCount: 1,
      maliciousUrlCount: urlAnalysis.isSuspicious ? 1 : 0
    };

    displayResults(analysis);
  });

  // Display results in UI
  function displayResults(analysis) {
    resultsContainer.classList.remove("hidden");

    const score = analysis.score;
    scoreNumber.innerText = `${score}%`;

    // Update SVG stroke-dashoffset (Circumference of r=42 is 263.89)
    const circumference = 264;
    const offset = circumference - (score / 100) * circumference;
    dialFill.style.strokeDashoffset = offset;
    dialFill.style.stroke = analysis.riskColor;

    // Verdict Badge
    verdictBadge.className = "verdict-badge";
    if (analysis.riskLevel === "SAFE") {
      verdictBadge.classList.add("safe");
      verdictBadge.innerText = "✓ LOW RISK / SAFE";
    } else if (analysis.riskLevel === "CAUTION") {
      verdictBadge.classList.add("caution");
      verdictBadge.innerText = "⚠ SUSPICIOUS";
    } else {
      verdictBadge.classList.add("danger");
      verdictBadge.innerText = "⛔ PHISHING DETECTED";
    }

    verdictSummary.innerText = analysis.summaryText;
    threatCount.innerText = analysis.threats.length;
    threatUrlCount.innerText = `${analysis.urlCount} link(s) checked`;

    // Render threat items
    threatList.innerHTML = "";
    if (analysis.threats.length === 0) {
      threatList.innerHTML = `
        <div class="clean-message">
          🛡️ No threat indicators found. Sender, links, and content appear legitimate.
        </div>
      `;
    } else {
      analysis.threats.forEach(t => {
        const item = document.createElement("div");
        item.className = `threat-item ${t.severity.toLowerCase()}`;
        item.innerHTML = `
          <div class="threat-header">
            <span class="threat-category">${escapeHtml(t.category)}: ${escapeHtml(t.title)}</span>
            <span class="threat-severity ${t.severity.toLowerCase()}">${t.severity}</span>
          </div>
          <p class="threat-desc">${escapeHtml(t.description)}</p>
        `;
        threatList.appendChild(item);
      });
    }

    // Smooth scroll down to results
    resultsContainer.scrollIntoView({ behavior: "smooth" });
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
});
