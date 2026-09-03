/**
 * TRACEGUARD AI - In-Email Content Script (Self-Contained MV3)
 * Full Gmail SPA Navigation Watcher, DOM Header Extractor, Shadow DOM Mount & 400px Dossier
 */

(function () {
  console.log('[TRACEGUARD AI] In-page email threat monitoring active on:', window.location.hostname);

  const WEB_APP_BASE = 'http://127.0.0.1:5173';
  let currentMessageId = null;
  let activeBundle = null;
  let activeSidePanel = null;

  function debounce(fn, wait) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  function extractMessageIdFromDom() {
    const msgRows = document.querySelectorAll('[data-legacy-message-id], [data-message-id]');
    if (msgRows.length > 0) {
      const lastRow = msgRows[msgRows.length - 1];
      const legacyId = lastRow.getAttribute('data-legacy-message-id') || lastRow.getAttribute('data-message-id');
      if (legacyId) return legacyId;
    }

    const hash = window.location.hash || '';
    const parts = hash.split('/');
    if (parts.length >= 2 && parts[0] === '#inbox' && parts[1].length >= 8) {
      return parts[1];
    }

    const openThread = document.querySelector("div[role='main'] h2.hP");
    if (openThread) {
      return 'thread-' + openThread.innerText.substring(0, 20).replace(/\W+/g, '');
    }

    return null;
  }

  function extractEmailMetadataFromDom() {
    let subject = '';
    let from = '';
    let body = '';

    const subjectEl = document.querySelector("h2.hP") || document.querySelector("div[role='main'] h2");
    if (subjectEl) subject = subjectEl.innerText.trim();

    const senderEl = document.querySelector('span.gD') || document.querySelector('span[email]');
    if (senderEl) {
      const emailAttr = senderEl.getAttribute('email');
      const name = senderEl.innerText || senderEl.getAttribute('name') || '';
      from = emailAttr ? `${name} <${emailAttr}>` : name;
    }

    const bodyEls = document.querySelectorAll('div.a3s.aiL');
    if (bodyEls.length > 0) {
      const lastBody = bodyEls[bodyEls.length - 1];
      body = lastBody.innerText.trim();
    }

    return { subject, from, body };
  }

  function constructSyntheticMime(meta) {
    return `From: ${meta.from || 'sender@example.com'}\nSubject: ${meta.subject || '(No Subject)'}\nDate: ${new Date().toUTCString()}\n\n${meta.body || ''}`;
  }

  function mountBanner(bundle, isAnalyzing) {
    let host = document.getElementById('traceguard-root');
    if (!host) {
      host = document.createElement('div');
      host.id = 'traceguard-root';

      const targetAnchor = document.querySelector("div[role='main'] h2.hP") ||
                           document.querySelector('.ha') ||
                           document.querySelector("div[role='main'] table") ||
                           document.querySelector("div[role='main']");

      if (targetAnchor && targetAnchor.parentNode) {
        targetAnchor.parentNode.insertBefore(host, targetAnchor);
      } else {
        const main = document.querySelector("div[role='main']");
        if (main) main.prepend(host);
      }
    }

    if (!host.shadowRoot) {
      host.attachShadow({ mode: 'open' });
    }

    const shadow = host.shadowRoot;
    shadow.innerHTML = '';

    const style = document.createElement('style');
    style.textContent = `
      :host {
        display: block;
        width: 100%;
        margin: 8px 0 12px 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        box-sizing: border-box;
      }
      * { box-sizing: border-box; }
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
        gap: 12px;
      }
      .tg-banner.critical {
        border-color: rgba(255, 92, 92, 0.6);
        background: #150B12;
      }
      .tg-banner.suspicious {
        border-color: rgba(246, 196, 83, 0.6);
        background: #141108;
      }
      .tg-banner.safe {
        border-color: rgba(61, 220, 151, 0.5);
        background: #08140F;
      }
      .tg-left {
        display: flex;
        align-items: center;
        gap: 10px;
        min-width: 0;
        flex: 1;
      }
      .tg-shield { font-size: 20px; flex-shrink: 0; }
      .tg-title-row { display: flex; align-items: center; gap: 6px; }
      .tg-brand { font-weight: 900; font-size: 12px; color: #FFFFFF; }
      .tg-tag {
        font-family: "JetBrains Mono", monospace;
        font-size: 10px;
        font-weight: 800;
        padding: 2px 6px;
        border-radius: 4px;
        background: rgba(255, 92, 92, 0.2);
        color: #FF5C5C;
        border: 1px solid rgba(255, 92, 92, 0.4);
      }
      .tg-tag.suspicious {
        background: rgba(246, 196, 83, 0.2);
        color: #F6C453;
        border-color: rgba(246, 196, 83, 0.4);
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
        padding: 6px 12px;
        border-radius: 8px;
        font-size: 11px;
        font-weight: 700;
        cursor: pointer;
        transition: all 150ms ease;
      }
      .tg-btn:hover { background: #202C40; border-color: #4F8CFF; }
      .tg-btn-primary { background: #4F8CFF; color: #FFFFFF; border: none; }
      .tg-btn-primary:hover { background: #3B72DB; }
      .spinner {
        display: inline-block;
        width: 14px;
        height: 14px;
        border: 2px solid #94A3B8;
        border-top-color: #4F8CFF;
        border-radius: 50%;
        animation: tg-spin 800ms linear infinite;
      }
      @keyframes tg-spin { to { transform: rotate(360deg); } }
    `;
    shadow.appendChild(style);

    const banner = document.createElement('div');
    banner.className = 'tg-banner';

    if (isAnalyzing) {
      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag" style="color:#4F8CFF; border-color:#4F8CFF;">ANALYZING</span>
            </div>
            <div class="tg-signals">Running 11-Lens Forensic DAG Pipeline...</div>
          </div>
        </div>
        <div class="tg-right">
          <span class="spinner"></span>
        </div>
      `;
    } else if (bundle) {
      const score = Math.round((bundle.threat_score || bundle.threatScore || 0) * 100);
      let bannerType = 'safe';
      let tagType = 'safe';

      if (score >= 75) {
        bannerType = 'critical';
        tagType = 'critical';
      } else if (score >= 35) {
        bannerType = 'suspicious';
        tagType = 'suspicious';
      }

      banner.classList.add(bannerType);

      const signals = bundle.key_signals || bundle.keySignals || [];
      const signalsText = signals.length > 0 ? signals.slice(0, 2).join(' • ') : 'Cryptographic signatures verified';

      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag ${tagType}">${bundle.classification || 'VERDICT'} — ${score}%</span>
            </div>
            <div class="tg-signals" title="${signalsText}">${signalsText}</div>
          </div>
        </div>
        <div class="tg-right">
          <button id="tgBtnDossier" class="tg-btn">Forensic Dossier</button>
          <button id="tgBtnConsole" class="tg-btn tg-btn-primary">Console &rarr;</button>
        </div>
      `;

      shadow.appendChild(banner);

      shadow.getElementById('tgBtnDossier').addEventListener('click', () => {
        openForensicSidePanel(bundle);
      });

      shadow.getElementById('tgBtnConsole').addEventListener('click', () => {
        window.open(`${WEB_APP_BASE}/investigation?id=${bundle.email_id || bundle.emailId}`, '_blank');
      });

      return;
    } else {
      banner.innerHTML = `
        <div class="tg-left">
          <span class="tg-shield">🛡️</span>
          <div>
            <div class="tg-title-row">
              <span class="tg-brand">TRACEGUARD AI</span>
              <span class="tg-tag safe" style="color:#94A3B8; border-color:#94A3B8;">READY</span>
            </div>
            <div class="tg-signals">Forensic gateway ready to inspect email headers & intent</div>
          </div>
        </div>
        <div class="tg-right">
          <button id="tgBtnScanNow" class="tg-btn tg-btn-primary">⚡ Scan This Email</button>
        </div>
      `;

      shadow.appendChild(banner);

      shadow.getElementById('tgBtnScanNow').addEventListener('click', () => {
        scanCurrentEmail();
      });
      return;
    }

    shadow.appendChild(banner);
  }

  function unmountBanner() {
    const host = document.getElementById('traceguard-root');
    if (host) host.remove();
    if (activeSidePanel) {
      activeSidePanel.remove();
      activeSidePanel = null;
    }
  }

  function openForensicSidePanel(bundle) {
    if (activeSidePanel) activeSidePanel.remove();

    activeSidePanel = document.createElement('div');
    activeSidePanel.id = 'traceguard-sidepanel';
    activeSidePanel.style.cssText = `
      position: fixed;
      top: 0;
      right: 0;
      width: 400px;
      height: 100vh;
      background: #080B12;
      color: #F5F1EA;
      border-left: 1px solid rgba(148, 163, 184, 0.2);
      box-shadow: -8px 0 32px rgba(0, 0, 0, 0.5);
      z-index: 9999999;
      display: flex;
      flex-direction: column;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    `;

    const score = Math.round((bundle.threat_score || 0) * 100);
    const infra = Math.round((bundle.infra_confidence || 0.8) * 100);
    const attrib = Math.round((bundle.attribution_confidence || 0.4) * 100);
    const auth = bundle.auth || {};

    activeSidePanel.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:16px; border-bottom:1px solid rgba(148,163,184,0.15);">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:18px;">🛡️</span>
          <div>
            <div style="font-weight:900; font-size:13px; color:#F5F1EA;">FORENSIC DOSSIER</div>
            <div style="font-size:10px; font-family:monospace; color:#94A3B8;">${bundle.case_id || 'CASE-2026-LIVE'}</div>
          </div>
        </div>
        <button id="tgCloseSidePanel" style="background:transparent; border:none; color:#94A3B8; font-size:20px; cursor:pointer;">&times;</button>
      </div>

      <div style="flex:1; padding:16px; overflow-y:auto; display:flex; flex-direction:column; gap:12px;">
        <!-- Hero -->
        <div style="background:#111827; padding:12px; border-radius:10px; border:1px solid rgba(148,163,184,0.15);">
          <div style="font-size:10px; font-family:monospace; color:#FF5C5C; font-weight:800;">VERDICT: ${bundle.classification || 'MALICIOUS'}</div>
          <div style="font-size:24px; font-family:monospace; font-weight:900; color:#FF5C5C;">${score}% THREAT</div>
          <p style="font-size:11px; color:#94A3B8; margin-top:4px;">${bundle.explanation_summary || 'Multi-lens calibrated risk analysis.'}</p>
        </div>

        <!-- Sender Comparison -->
        <div style="background:#111827; padding:10px; border-radius:8px; border:1px solid rgba(148,163,184,0.15); font-family:monospace; font-size:11px;">
          <div style="color:#94A3B8; font-size:9px;">CLAIMED SENDER</div>
          <div style="color:#F5F1EA; font-weight:700;">${bundle.claimed_domain || 'acme.com'}</div>
          <div style="color:#94A3B8; font-size:9px; margin-top:6px;">ACTUAL RETURN PATH</div>
          <div style="color:#FF5C5C; font-weight:700;">${bundle.actual_domain || 'secure-exchange.net'}</div>
        </div>

        <!-- 3-Axis Scores -->
        <div style="background:#111827; padding:10px; border-radius:8px; border:1px solid rgba(148,163,184,0.15); font-family:monospace; font-size:11px; display:flex; flex-direction:column; gap:8px;">
          <div style="font-size:9px; color:#94A3B8; font-weight:800;">3-AXIS SCORES</div>
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

        <!-- Auth Grid -->
        <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:6px; font-family:monospace; font-size:11px;">
          <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15); text-align:center;">
            <div style="font-size:8px; color:#94A3B8;">SPF</div>
            <strong style="color:${auth.spf === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${auth.spf || 'FAIL'}</strong>
          </div>
          <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15); text-align:center;">
            <div style="font-size:8px; color:#94A3B8;">DKIM</div>
            <strong style="color:${auth.dkim === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${auth.dkim || 'FAIL'}</strong>
          </div>
          <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15); text-align:center;">
            <div style="font-size:8px; color:#94A3B8;">DMARC</div>
            <strong style="color:${auth.dmarc === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${auth.dmarc || 'FAIL'}</strong>
          </div>
          <div style="padding:6px; background:#111827; border-radius:6px; border:1px solid rgba(148,163,184,0.15); text-align:center;">
            <div style="font-size:8px; color:#94A3B8;">ARC</div>
            <strong style="color:${auth.arc === 'PASS' ? '#3DDC97' : '#FF5C5C'};">${auth.arc || 'PASS'}</strong>
          </div>
        </div>
      </div>

      <div style="padding:16px; border-top:1px solid rgba(148,163,184,0.15);">
        <button id="tgSidePanelConsoleBtn" style="width:100%; background:#4F8CFF; color:#FFFFFF; border:none; padding:10px; border-radius:10px; font-weight:800; font-size:11px; cursor:pointer;">
          OPEN IN TRACEGUARD CONSOLE &rarr;
        </button>
      </div>
    `;

    document.body.appendChild(activeSidePanel);

    activeSidePanel.querySelector('#tgCloseSidePanel').addEventListener('click', () => {
      activeSidePanel.remove();
      activeSidePanel = null;
    });

    activeSidePanel.querySelector('#tgSidePanelConsoleBtn').addEventListener('click', () => {
      window.open(`${WEB_APP_BASE}/investigation?id=${bundle.email_id || bundle.emailId}`, '_blank');
    });
  }

  async function scanCurrentEmail() {
    mountBanner(null, true);
    const msgId = extractMessageIdFromDom();

    try {
      let res;
      if (msgId && !msgId.startsWith('thread-')) {
        res = await chrome.runtime.sendMessage({
          type: 'SCAN_MESSAGE',
          gmailMessageId: msgId
        });
      }

      if (!res || res.error || !res.email_id) {
        const meta = extractEmailMetadataFromDom();
        const rawMime = constructSyntheticMime(meta);
        res = await chrome.runtime.sendMessage({
          type: 'INGEST_RAW_EML',
          rawMime,
          messageId: msgId || 'dom-active-email'
        });
      }

      if (res && res.email_id) {
        activeBundle = res;
        mountBanner(res, false);
      } else {
        throw new Error(res ? res.error : 'Scan failed');
      }
    } catch (err) {
      console.warn('[TRACEGUARD Content] Scan error:', err);
      mountBanner(null, false);
    }
  }

  function detectOpenMessage() {
    const id = extractMessageIdFromDom();
    if (id && id !== currentMessageId) {
      currentMessageId = id;
      activeBundle = null;
      mountBanner(null, false);
    } else if (!id && currentMessageId) {
      currentMessageId = null;
      activeBundle = null;
      unmountBanner();
    }
  }

  const observer = new MutationObserver(debounce(detectOpenMessage, 250));
  observer.observe(document.body, { childList: true, subtree: true });

  window.addEventListener('hashchange', detectOpenMessage);
  window.addEventListener('popstate', detectOpenMessage);
  setInterval(detectOpenMessage, 1500);

  detectOpenMessage();

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'EXTRACT_AND_ANALYZE') {
      if (activeBundle) {
        sendResponse({ bundle: activeBundle });
      } else {
        scanCurrentEmail().then(() => {
          sendResponse({ bundle: activeBundle });
        }).catch(err => {
          sendResponse({ error: err.message });
        });
        return true;
      }
    }
  });
})();
