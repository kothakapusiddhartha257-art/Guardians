/**
 * TRACEGUARD AI - In-Email Intelligence Banner & 400px Slide-out Forensic Side Panel
 */

(function () {
  console.log("[TRACEGUARD AI] In-page email threat monitoring active on:", window.location.hostname);

  const WEB_APP_BASE = "http://127.0.0.1:5173";
  let sidePanelEl = null;

  // 1. Extract Webmail Data
  function extractActiveEmail() {
    const host = window.location.hostname;
    let subject = "";
    let sender = "";
    let body = "";
    let client = "Webmail";
    const links = [];

    if (host.includes("mail.google.com")) {
      client = "Gmail";
      const subjectEl = document.querySelector("h2.hP") || document.querySelector("div[role='main'] h2");
      if (subjectEl) subject = subjectEl.innerText.trim();

      const senderEl = document.querySelector("span.gD") || document.querySelector("span[email]");
      if (senderEl) {
        const emailAttr = senderEl.getAttribute("email");
        const name = senderEl.innerText || senderEl.getAttribute("name") || "";
        sender = emailAttr ? `${name} <${emailAttr}>` : name;
      }

      const bodyEls = document.querySelectorAll("div.a3s.aiL");
      if (bodyEls.length > 0) {
        const lastBody = bodyEls[bodyEls.length - 1];
        body = lastBody.innerText.trim();
        lastBody.querySelectorAll("a[href]").forEach((a) => {
          const h = a.getAttribute("href");
          if (h && !h.startsWith("mailto:") && !h.startsWith("javascript:")) links.push(h);
        });
      }
    } else if (host.includes("outlook.live.com") || host.includes("outlook.office")) {
      client = "Outlook";
      const subjectEl = document.querySelector("div[role='heading'][aria-level='2']") || document.querySelector("div.rps_auto");
      if (subjectEl) subject = subjectEl.innerText.trim();

      const senderEl = document.querySelector("span[title*='@']") || document.querySelector("button[aria-haspopup='dialog'] span");
      if (senderEl) sender = senderEl.getAttribute("title") || senderEl.innerText.trim();

      const bodyEl = document.querySelector("div[aria-label='Message body']") || document.querySelector("div.ItemPartView");
      if (bodyEl) {
        body = bodyEl.innerText.trim();
        bodyEl.querySelectorAll("a[href]").forEach((a) => {
          const h = a.getAttribute("href");
          if (h && !h.startsWith("mailto:")) links.push(h);
        });
      }
    } else {
      subject = document.title || "";
      sender = window.location.hostname;
      body = (document.body ? document.body.innerText : "").slice(0, 3000);
    }

    return { subject, sender, body, links, client };
  }

  // 2. Inject Top Banner
  function tryInjectBanner() {
    if (document.getElementById("traceguard-injected-banner")) return;

    const emailData = extractActiveEmail();
    if (!emailData.subject && !emailData.body) return;

    const subjectSelectors = ["h2.hP", ".ha", "[data-message-id]", "div[role='heading'][aria-level='2']"];
    let targetElement = null;
    for (const sel of subjectSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        targetElement = el;
        break;
      }
    }

    if (targetElement) {
      const banner = document.createElement("div");
      banner.id = "traceguard-injected-banner";
      banner.className = "traceguard-injected-banner";
      banner.innerHTML = `
        <div class="tg-banner-left">
          <span class="tg-banner-shield">🛡️</span>
          <div style="display:flex; flex-direction:column; gap:2px;">
            <div class="tg-banner-title-row">
              <span class="tg-banner-brand">TRACEGUARD AI</span>
              <span class="tg-banner-tag">⚠ HIGH RISK — 76%</span>
            </div>
            <span class="tg-banner-signals">
              Reply-To mismatch • DMARC failure • Financial urgency
            </span>
          </div>
        </div>
        <div class="tg-banner-right">
          <button id="tg-btn-open-panel" class="tg-btn-investigate">
            <span>Investigate</span>
            <span>→</span>
          </button>
        </div>
      `;

      targetElement.parentNode.insertBefore(banner, targetElement);

      const btnOpen = document.getElementById("tg-btn-open-panel");
      if (btnOpen) {
        btnOpen.addEventListener("click", (e) => {
          e.preventDefault();
          openSidePanel();
        });
      }
    }
  }

  // 3. Create Slide-out 400px Side Panel
  function ensureSidePanel() {
    if (sidePanelEl) return sidePanelEl;

    sidePanelEl = document.createElement("div");
    sidePanelEl.id = "traceguard-side-panel";
    sidePanelEl.className = "traceguard-side-panel";
    sidePanelEl.innerHTML = `
      <div class="tg-panel-header">
        <div class="tg-panel-title-group">
          <span class="tg-panel-eyebrow">CASE #CASE-2026-00041</span>
          <h2 class="tg-panel-title">TRACEGUARD FORENSICS</h2>
        </div>
        <button id="tg-panel-close-btn" class="tg-panel-close">&times;</button>
      </div>

      <div class="tg-panel-nav">
        <button class="tg-tab-btn active" data-tab="tab-overview">Overview</button>
        <button class="tg-tab-btn" data-tab="tab-identity">Identity</button>
        <button class="tg-tab-btn" data-tab="tab-infra">Infrastructure</button>
        <button class="tg-tab-btn" data-tab="tab-connect">Connections</button>
      </div>

      <div class="tg-panel-body">
        <!-- Tab 1: Overview -->
        <div id="tab-overview" class="tg-tab-view active">
          <div class="tg-card" style="border-left: 3px solid var(--tg-critical);">
            <span class="tg-eyebrow" style="color:var(--tg-critical);">Verdict: High Risk (76%)</span>
            <div style="font-size:12px; font-weight:800; color:#fff;">
              URGENT: Vendor Payment Account Change
            </div>
            <p style="font-size:10.5px; color:var(--tg-muted); margin-top:2px;">
              High-confidence BEC wire transfer directive with Reply-To diversion.
            </p>
          </div>

          <div class="tg-card">
            <span class="tg-eyebrow">Top Forensic Signals</span>
            <ul style="list-style:none; display:flex; flex-direction:column; gap:4px; font-size:11px; margin-top:3px;">
              <li>⚠️ <strong>Reply-To Mismatch:</strong> Redirects to unauthenticated external domain</li>
              <li>⚠️ <strong>DMARC Fail:</strong> Sender domain authorization unverified</li>
              <li>⚠️ <strong>Financial Urgency:</strong> Demands immediate $142,500 wire transfer</li>
            </ul>
          </div>
        </div>

        <!-- Tab 2: Identity -->
        <div id="tab-identity" class="tg-tab-view">
          <div class="tg-card">
            <span class="tg-eyebrow">Sender Alignment</span>
            <div style="font-family:monospace; font-size:11px; display:flex; flex-direction:column; gap:4px; margin-top:4px;">
              <div>From: <strong>ceo@acme.com</strong></div>
              <div style="color:var(--tg-critical);">Reply-To: <strong>finance@secure-exchange-transfer.xyz</strong></div>
              <div>Return-Path: <strong>bounce@secure-exchange-transfer.xyz</strong></div>
            </div>
          </div>
          <div class="tg-card">
            <span class="tg-eyebrow">Authentication Protocols</span>
            <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:4px; font-family:monospace; font-size:10px; text-align:center; margin-top:4px;">
              <div style="background:var(--tg-subtle); padding:4px; border-radius:4px;"><div style="color:var(--tg-muted);">SPF</div><strong style="color:var(--tg-critical);">FAIL</strong></div>
              <div style="background:var(--tg-subtle); padding:4px; border-radius:4px;"><div style="color:var(--tg-muted);">DKIM</div><strong style="color:var(--tg-critical);">FAIL</strong></div>
              <div style="background:var(--tg-subtle); padding:4px; border-radius:4px;"><div style="color:var(--tg-muted);">DMARC</div><strong style="color:var(--tg-critical);">FAIL</strong></div>
              <div style="background:var(--tg-subtle); padding:4px; border-radius:4px;"><div style="color:var(--tg-muted);">ARC</div><strong style="color:var(--tg-safe);">PASS</strong></div>
            </div>
          </div>
        </div>

        <!-- Tab 3: Infrastructure -->
        <div id="tab-infra" class="tg-tab-view">
          <div class="tg-card">
            <span class="tg-eyebrow">SMTP Route & Trust Frontier</span>
            <div style="font-family:monospace; font-size:10.5px; display:flex; flex-direction:column; gap:4px; margin-top:4px;">
              <div>1. Recipient MTA (Google Workspace)</div>
              <div>2. relay.secure-mail.net</div>
              <div style="color:var(--tg-warning); font-weight:bold;">⚠ TRUST FRONTIER BOUNDARY</div>
              <div style="color:var(--tg-critical); font-weight:bold;">3. 185.23.11.4 (Origin Server)</div>
              <div style="color:var(--tg-muted); font-size:10px;">Frankfurt, Germany (AS208091)</div>
            </div>
          </div>
        </div>

        <!-- Tab 4: Connections -->
        <div id="tab-connect" class="tg-tab-view">
          <div class="tg-card" style="border-left: 3px solid var(--tg-attrib);">
            <span class="tg-eyebrow" style="color:var(--tg-attrib);">Related Threat Campaign</span>
            <div style="font-size:12px; font-weight:800; color:#fff;">
              Operation Apex Wire Divert
            </div>
            <div style="font-size:11px; color:var(--tg-muted); margin-top:2px;">
              5 Linked Inbound Emails in Current Ledger
            </div>
            <div style="font-family:monospace; font-size:10px; color:var(--tg-muted); margin-top:4px;">
              Shared Origin: 185.23.11.4<br />
              Shared Domain: secure-exchange-transfer.xyz
            </div>
          </div>
        </div>
      </div>

      <div class="tg-panel-footer">
        <button id="tg-btn-open-web-app" class="tg-btn-full-platform">
          <span>Open Full Forensic Investigation</span>
          <span>↗</span>
        </button>
      </div>
    `;

    document.body.appendChild(sidePanelEl);

    // Event listeners
    const closeBtn = document.getElementById("tg-panel-close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        sidePanelEl.classList.remove("open");
      });
    }

    const tabBtns = sidePanelEl.querySelectorAll(".tg-tab-btn");
    const tabViews = sidePanelEl.querySelectorAll(".tg-tab-view");

    tabBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        tabBtns.forEach((b) => b.classList.remove("active"));
        tabViews.forEach((v) => v.classList.remove("active"));

        btn.classList.add("active");
        const targetView = document.getElementById(btn.dataset.tab);
        if (targetView) targetView.classList.add("active");
      });
    });

    const btnOpenWebApp = document.getElementById("tg-btn-open-web-app");
    if (btnOpenWebApp) {
      btnOpenWebApp.addEventListener("click", () => {
        window.open(`${WEB_APP_BASE}/investigation?id=email-bec-demo`, "_blank");
      });
    }

    return sidePanelEl;
  }

  function openSidePanel() {
    const panel = ensureSidePanel();
    panel.classList.add("open");
  }

  // Listen for popup extractor messages
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === "EXTRACT_EMAIL_DATA") {
        try {
          const data = extractActiveEmail();
          sendResponse({ success: true, data });
        } catch (err) {
          sendResponse({ success: false, error: err.message });
        }
      }
      return true;
    });
  }

  // Observe DOM for email opening
  const observer = new MutationObserver(() => {
    tryInjectBanner();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  setTimeout(() => {
    tryInjectBanner();
  }, 1000);
})();
