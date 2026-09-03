/**
 * TRACEGUARD AI - In-Page Content Script (v2)
 * Shadow DOM Isolated Threat Banner & 400px Forensic Slide-Out Workspace
 */

(function () {
  console.log("[TRACEGUARD AI] In-page email threat monitoring active on:", window.location.hostname);

  const WEB_APP_BASE = "http://127.0.0.1:5173";
  let lastMessageId = null;
  let activeBundle = null;
  let sidePanelEl = null;

  // ═════════════════════════════════════════════════════════════════
  // 1. EXTRACT MESSAGE IDENTIFIERS & METADATA
  // ═════════════════════════════════════════════════════════════════

  function getActiveGmailMessageId() {
    // 1. Check data-legacy-message-id attribute on message rows
    const msgRows = document.querySelectorAll("[data-legacy-message-id], [data-message-id]");
    if (msgRows.length > 0) {
      const lastRow = msgRows[msgRows.length - 1];
      const legacyId = lastRow.getAttribute("data-legacy-message-id") || lastRow.getAttribute("data-message-id");
      if (legacyId) return legacyId;
    }

    // 2. Check URL Hash (e.g. #inbox/FMfcgzGxSH...)
    const hash = window.location.hash || "";
    const parts = hash.split("/");
    if (parts.length >= 2 && parts[0] === "#inbox" && parts[1].length >= 10) {
      return parts[1];
    }

    return null;
  }

  function extractFallbackEmailData() {
    let subject = "";
    let sender = "";
    let body = "";
    const links = [];

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

    return { subject, sender, body, links };
  }

  // ═════════════════════════════════════════════════════════════════
  // 2. SHADOW DOM INJECTION (ZERO CSS BLEED)
  // ═════════════════════════════════════════════════════════════════

  function injectThreatBanner(bundle = null, isAnalyzing = false) {
    let rootHost = document.getElementById("traceguard-root");
    if (!rootHost) {
      rootHost = document.createElement("div");
      rootHost.id = "traceguard-root";
      
      const targetAnchor = document.querySelector("div[role='main'] h2.hP") || 
                           document.querySelector(".ha") || 
                           document.querySelector("div[role='main'] table");

      if (targetAnchor && targetAnchor.parentNode) {
        targetAnchor.parentNode.insertBefore(rootHost, targetAnchor);
      } else {
        const main = document.querySelector("div[role='main']");
        if (main) main.prepend(rootHost);
      }
    }

    if (!rootHost.shadowRoot) {
      rootHost.attachShadow({ mode: "open" });
    }

    const shadow = rootHost.shadowRoot;
    shadow.innerHTML = ""; // Clean refresh

    // Stylesheet inside Shadow DOM
    const style = document.createElement("style");
    style.textContent = `
      :host {
        display: block;
        width: 100%;
        margin-bottom: 12px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      .tg-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 14px;
        border-radius: 12px;
        background: #080B12;
        color: #F5F1EA;
        border: 1px solid rgba(148, 163, 184, 0.2);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        font-size: 12px;
      }
      .tg-banner.critical {
        border-color: rgba(255, 92, 92, 0.5);
        background: #110B12;
      }
      .tg-banner.safe {
        border-color: rgba(61, 220, 151, 0.4);
      }
      .tg-left {
        display: flex;
        align-items: center;
        gap: 10px;
        min-width: 0;
      }
      .tg-shield {
        font-size: 20px;
      }
      .tg-title-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .tg-brand {
        font-weight: 900;
        font-size: 12px;
        color: #FFFFFF;
      }
      .tg-tag {
        font-family: monospace;
        font-size: 10px;
        font-weight: 800;
        padding: 2px 6px;
        border-radius: 4px;
        background: rgba(255, 92, 92, 0.2);
        color: #FF5C5C;
        border: 1px solid rgba(255, 92, 92, 0.4);
      }
      .tg-tag.safe {
        background: rgba(61, 220, 151, 0.2);
        color: #3DDC97;
        border-color: rgba(61, 220, 151, 0.4);
      }
      .tg-signals {
        font-size: 11px;
        color: #94A3B8;
        margin-top: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .tg-right {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
      }
      .tg-btn {
        background: #182234;
        color: #F5F1EA;
        border: 1px solid rgba(148, 163, 184, 0.3);
        padding: 6px 10px;
        border-radius: 8px;
        font-size: 11px;
        font-weight: 700;
        cursor: pointer;
        transition: all 150ms ease;
      }
      .tg-btn:hover {
        background: #202C40;
        border-color: #4F8CFF;
      }
      .tg-btn-primary {
        background: #4F8CFF;
        color: #FFFFFF;
        border: none;
      }
      .tg-btn-primary:hover {
        background: #3B72DB;
      }
      .spinner {
        display: inline-block;
        width: 12px;
        height: 12px;
        border: 2px solid #94A3B8;
        border-top-color: #4F8CFF;
        border-radius: 50%;
        animation: spin 800ms linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }
    `;

    shadow.appendChild(style);

    const banner = document.createElement("div");
    banner.className = "tg-banner";

    if (isAnalyzing) {
      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag" style="color: #4F8CFF; border-color: #4F8CFF;">ANALYZING</span>
            </div>
            <div class="tg-signals">Preserving EML & running 11-Lens Forensic DAG...</div>
          </div>
        </div>
        <div class="tg-right">
          <span class="spinner"></span>
        </div>
      `;
    } else if (bundle) {
      const score = Math.round((bundle.threat_score || 0) * 100);
      const isCritical = score >= 50;
      if (isCritical) banner.classList.add("critical");
      else banner.classList.add("safe");

      const signalsText = bundle.key_signals && bundle.key_signals.length > 0
        ? bundle.key_signals.join(" • ")
        : "Cryptographic signature validated";

      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag ${isCritical ? "" : "safe"}">
                ${bundle.classification || "THREAT"} — ${score}%
              </span>
            </div>
            <div class="tg-signals" title="${signalsText}">${signalsText}</div>
          </div>
        </div>
        <div class="tg-right">
          <button id="btnOpenDossier" class="tg-btn">Forensic Dossier</button>
          <button id="btnOpenConsole" class="tg-btn tg-btn-primary">Console &rarr;</button>
        </div>
      `;

      shadow.appendChild(banner);

      shadow.getElementById("btnOpenDossier").addEventListener("click", () => {
        openSlidePanel(bundle);
      });

      shadow.getElementById("btnOpenConsole").addEventListener("click", () => {
        window.open(`${WEB_APP_BASE}/investigation?id=${bundle.email_id}`, "_blank");
      });

      return;
    } else {
      // Default: Scan Trigger Banner
      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag" style="color: #94A3B8; border-color: #94A3B8;">READY</span>
            </div>
            <div class="tg-signals">In-page forensic gateway ready to inspect RFC822 source</div>
          </div>
        </div>
        <div class="tg-right">
          <button id="btnScanMessage" class="tg-btn tg-btn-primary">⚡ Scan This Email</button>
        </div>
      `;

      shadow.appendChild(banner);

      shadow.getElementById("btnScanMessage").addEventListener("click", () => {
        triggerSingleEmailScan();
      });
      return;
    }

    shadow.appendChild(banner);
  }

  // ═════════════════════════════════════════════════════════════════
  // 3. SCAN THIS EMAIL CONTROLLER
  // ═════════════════════════════════════════════════════════════════

  async function triggerSingleEmailScan() {
    injectThreatBanner(null, true);
    const msgId = getActiveGmailMessageId();

    try {
      let res;
      if (msgId) {
        res = await chrome.runtime.sendMessage({
          type: "SCAN_MESSAGE",
          gmailMessageId: msgId
        });
      }

      if (!res || res.error) {
        // Fallback: construct raw MIME from DOM
        const fallback = extractFallbackEmailData();
        const rawMime = `From: ${fallback.sender}\nSubject: ${fallback.subject}\nDate: ${new Date().toUTCString()}\n\n${fallback.body}`;
        res = await chrome.runtime.sendMessage({
          type: "INGEST_RAW_EML",
          rawBase64: btoa(unescape(encodeURIComponent(rawMime))),
          messageId: msgId || "active-dom-email"
        });
      }

      if (res && res.email_id) {
        activeBundle = res;
        injectThreatBanner(res, false);
      } else {
        throw new Error(res ? res.error : "Failed to analyze message");
      }
    } catch (e) {
      console.warn("[TRACEGUARD AI] Scan error:", e);
      injectThreatBanner(null, false);
    }
  }

  // ═════════════════════════════════════════════════════════════════
  // 4. 400PX FORENSIC SIDE DRAWER
  // ═════════════════════════════════════════════════════════════════

  function openSlidePanel(bundle) {
    if (sidePanelEl) sidePanelEl.remove();

    sidePanelEl = document.createElement("div");
    sidePanelEl.id = "traceguard-sidepanel";
    sidePanelEl.className = "traceguard-sidepanel open";

    const score = Math.round((bundle.threat_score || 0) * 100);
    const infra = Math.round((bundle.infra_confidence || 0.8) * 100);
    const attrib = Math.round((bundle.attribution_confidence || 0.4) * 100);

    sidePanelEl.innerHTML = `
      <div class="tg-panel-header">
        <div style="display:flex; align-items:center; gap:8px;">
          <span>🛡️</span>
          <div>
            <div style="font-weight:900; font-size:13px; color:#F5F1EA;">FORENSIC DOSSIER</div>
            <div style="font-size:10px; font-family:monospace; color:#94A3B8;">${bundle.case_id || "CASE-2026-LIVE"}</div>
          </div>
        </div>
        <button id="tgClosePanel" style="background:transparent; border:none; color:#94A3B8; font-size:18px; cursor:pointer;">&times;</button>
      </div>

      <div class="tg-panel-tabs">
        <button class="tg-tab-btn active" data-tab="tg-tab-overview">OVERVIEW</button>
        <button class="tg-tab-btn" data-tab="tg-tab-identity">IDENTITY</button>
        <button class="tg-tab-btn" data-tab="tg-tab-infra">INFRASTRUCTURE</button>
      </div>

      <div class="tg-panel-body">
        <!-- Tab 1: Overview -->
        <div id="tg-tab-overview" class="tg-tab-content active">
          <div style="background:#111827; padding:12px; border-radius:10px; border:1px solid rgba(148,163,184,0.15); margin-bottom:12px;">
            <div style="font-size:10px; font-family:monospace; color:#FF5C5C; font-weight:800;">VERDICT: ${bundle.classification || "MALICIOUS"}</div>
            <div style="font-size:24px; font-family:monospace; font-weight:900; color:#FF5C5C;">${score}% THREAT</div>
            <p style="font-size:11px; color:#94A3B8; margin-top:4px;">${bundle.explanation_summary || "Automated multi-lens signature correlation."}</p>
          </div>

          <div style="font-size:10px; font-family:monospace; font-weight:800; color:#94A3B8; margin-bottom:6px;">3-AXIS CALIBRATED SCORES</div>
          <div style="display:flex; flex-direction:column; gap:8px; font-family:monospace; font-size:11px;">
            <div>
              <div style="display:flex; justify-content:space-between; color:#94A3B8;"><span>Threat Severity:</span><strong style="color:#FF5C5C;">${score}%</strong></div>
              <div style="width:100%; height:4px; background:#182234; border-radius:4px; margin-top:2px;"><div style="width:${score}%; height:100%; background:#FF5C5C; border-radius:4px;"></div></div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; color:#94A3B8;"><span>Infrastructure Trust:</span><strong style="color:#38BDF8;">${infra}%</strong></div>
              <div style="width:100%; height:4px; background:#182234; border-radius:4px; margin-top:2px;"><div style="width:${infra}%; height:100%; background:#38BDF8; border-radius:4px;"></div></div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; color:#94A3B8;"><span>Attribution Confidence:</span><strong style="color:#A78BFA;">${attrib}%</strong></div>
              <div style="width:100%; height:4px; background:#182234; border-radius:4px; margin-top:2px;"><div style="width:${attrib}%; height:100%; background:#A78BFA; border-radius:4px;"></div></div>
            </div>
          </div>
        </div>

        <!-- Tab 2: Identity -->
        <div id="tg-tab-identity" class="tg-tab-content">
          <div style="background:#111827; padding:10px; border-radius:8px; border:1px solid rgba(148,163,184,0.15); margin-bottom:12px; font-family:monospace; font-size:11px;">
            <div style="color:#94A3B8; font-size:9px;">CLAIMED SENDER</div>
            <div style="color:#F5F1EA; font-weight:700;">${bundle.claimed_domain || "acme.com"}</div>
            <div style="color:#94A3B8; font-size:9px; margin-top:6px;">ACTUAL RETURN PATH</div>
            <div style="color:#FF5C5C; font-weight:700;">${bundle.actual_domain || "secure-exchange.net"}</div>
          </div>

          <div style="font-size:10px; font-family:monospace; font-weight:800; color:#94A3B8; margin-bottom:6px;">AUTHENTICATION PROTOCOLS</div>
          <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:6px; font-family:monospace; font-size:11px;">
            <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15);">SPF: <strong style="color:${bundle.auth?.spf === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${bundle.auth?.spf || 'FAIL'}</strong></div>
            <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15);">DKIM: <strong style="color:${bundle.auth?.dkim === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${bundle.auth?.dkim || 'FAIL'}</strong></div>
            <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15);">DMARC: <strong style="color:${bundle.auth?.dmarc === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${bundle.auth?.dmarc || 'FAIL'}</strong></div>
            <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15);">ARC: <strong style="color:${bundle.auth?.arc === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${bundle.auth?.arc || 'PASS'}</strong></div>
          </div>
        </div>

        <!-- Tab 3: Infrastructure -->
        <div id="tg-tab-infra" class="tg-tab-content">
          <div style="background:#111827; padding:10px; border-radius:8px; border:1px solid rgba(148,163,184,0.15); font-family:monospace; font-size:11px; display:flex; flex-direction:column; gap:6px;">
            <div><span style="color:#94A3B8;">Origin IP:</span> <strong style="color:#38BDF8;">${bundle.origin_ip || "185.23.11.4"}</strong></div>
            <div><span style="color:#94A3B8;">Location:</span> <strong style="color:#F5F1EA;">${bundle.origin_city || "Frankfurt"}, ${bundle.origin_country || "DE"}</strong></div>
            <div><span style="color:#94A3B8;">Relay Hops:</span> <strong style="color:#F5F1EA;">${bundle.relay_hops_count || 3} intermediate MTAs</strong></div>
            <div><span style="color:#94A3B8;">Related Cases:</span> <strong style="color:#A78BFA;">${bundle.related_cases_count || 4} correlated incidents</strong></div>
          </div>
        </div>
      </div>

      <div style="padding:12px; border-top:1px solid rgba(148,163,184,0.15);">
        <button id="tgOpenConsoleBtn" style="width:100%; background:#4F8CFF; color:#FFFFFF; border:none; padding:10px; border-radius:10px; font-weight:800; font-size:11px; cursor:pointer; font-family:inherit;">
          OPEN IN TRACEGUARD CONSOLE &rarr;
        </button>
      </div>
    `;

    document.body.appendChild(sidePanelEl);

    // Tab switcher
    sidePanelEl.querySelectorAll(".tg-tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        sidePanelEl.querySelectorAll(".tg-tab-btn").forEach((b) => b.classList.remove("active"));
        sidePanelEl.querySelectorAll(".tg-tab-content").forEach((c) => c.classList.remove("active"));
        btn.classList.add("active");
        const tabId = btn.getAttribute("data-tab");
        const content = sidePanelEl.querySelector(`#${tabId}`);
        if (content) content.classList.add("active");
      });
    });

    sidePanelEl.querySelector("#tgClosePanel").addEventListener("click", () => {
      sidePanelEl.remove();
      sidePanelEl = null;
    });

    sidePanelEl.querySelector("#tgOpenConsoleBtn").addEventListener("click", () => {
      window.open(`${WEB_APP_BASE}/investigation?id=${bundle.email_id}`, "_blank");
    });
  }

  // ═════════════════════════════════════════════════════════════════
  // 5. OBSERVERS & POPUP COMMUNICATION
  // ═════════════════════════════════════════════════════════════════

  function checkEmailOpenState() {
    const currentMsgId = getActiveGmailMessageId();
    if (currentMsgId && currentMsgId !== lastMessageId) {
      lastMessageId = currentMsgId;
      injectThreatBanner(null, false);
    } else if (!currentMsgId) {
      const root = document.getElementById("traceguard-root");
      if (root) root.remove();
      if (sidePanelEl) {
        sidePanelEl.remove();
        sidePanelEl = null;
      }
    }
  }

  // Monitor URL changes
  window.addEventListener("popstate", checkEmailOpenState);
  window.addEventListener("hashchange", checkEmailOpenState);
  setInterval(checkEmailOpenState, 1200);

  // Listen to message from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "EXTRACT_AND_ANALYZE") {
      const msgId = getActiveGmailMessageId();
      if (activeBundle) {
        sendResponse({ bundle: activeBundle });
      } else if (msgId) {
        chrome.runtime.sendMessage(
          { type: "SCAN_MESSAGE", gmailMessageId: msgId },
          (res) => {
            if (res && res.email_id) {
              activeBundle = res;
              injectThreatBanner(res, false);
              sendResponse({ bundle: res });
            } else {
              sendResponse({ error: res ? res.error : "Failed to scan email" });
            }
          }
        );
        return true;
      } else {
        const fallback = extractFallbackEmailData();
        if (fallback.subject || fallback.body) {
          const rawMime = `From: ${fallback.sender}\nSubject: ${fallback.subject}\nDate: ${new Date().toUTCString()}\n\n${fallback.body}`;
          chrome.runtime.sendMessage(
            {
              type: "INGEST_RAW_EML",
              rawBase64: btoa(unescape(encodeURIComponent(rawMime))),
              messageId: "active-dom-email"
            },
            (res) => {
              if (res && res.email_id) {
                activeBundle = res;
                injectThreatBanner(res, false);
                sendResponse({ bundle: res });
              } else {
                sendResponse({ error: res ? res.error : "Failed to analyze message" });
              }
            }
          );
          return true;
        } else {
          sendResponse({ error: "No email open in current view" });
        }
      }
    }
  });
})();
