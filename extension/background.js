/**
 * TRACEGUARD AI - Service Worker (Manifest V3)
 * Full Ingestion Client, Gmail OAuth & Forensic Stream Engine
 */

const BACKEND_URL = "http://127.0.0.1:8000";
const GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

// ═══════════════════════════════════════════════════════════════════
// 1. OAUTH & TOKEN LIFECYCLE (MV3)
// ═══════════════════════════════════════════════════════════════════

async function getAccessToken(forceRefresh = false) {
  if (!forceRefresh) {
    // Check volatile session storage first (cleared on browser restart)
    const session = await chrome.storage.session.get(["access_token", "expires_at"]);
    if (session.access_token && session.expires_at && Date.now() < session.expires_at - 60000) {
      return session.access_token;
    }
  }

  // Attempt silent refresh via backend
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/oauth/gmail/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    if (res.ok) {
      const data = await res.json();
      const expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
      await chrome.storage.session.set({
        access_token: data.access_token,
        expires_at: expiresAt
      });
      await chrome.storage.local.set({ connected: true });
      return data.access_token;
    }
  } catch (e) {
    console.warn("[TRACEGUARD SW] Backend token refresh attempt failed:", e);
  }

  return null;
}

async function connectGmailAuth() {
  try {
    // 1. Get Google OAuth URL from TRACEGUARD backend
    const redirectUri = chrome.identity.getRedirectURL("oauth2");
    const authUrlRes = await fetch(
      `${BACKEND_URL}/api/v1/oauth/gmail/auth-url?redirect_uri=${encodeURIComponent(redirectUri)}`
    );
    
    if (!authUrlRes.ok) {
      throw new Error(`Failed to initialize Google OAuth URL: ${authUrlRes.statusText}`);
    }
    
    const { auth_url } = await authUrlRes.json();

    // 2. Launch Chrome Web Auth Flow
    const responseUrl = await new Promise((resolve, reject) => {
      chrome.identity.launchWebAuthFlow(
        {
          url: auth_url,
          interactive: true
        },
        (redirectUrl) => {
          if (chrome.runtime.lastError || !redirectUrl) {
            reject(new Error(chrome.runtime.lastError ? chrome.runtime.lastError.message : "OAuth flow cancelled"));
          } else {
            resolve(redirectUrl);
          }
        }
      );
    });

    // 3. Extract authorization code from callback URL
    const urlObj = new URL(responseUrl);
    const code = urlObj.searchParams.get("code");
    const error = urlObj.searchParams.get("error");

    if (error) {
      throw new Error(`Google OAuth error: ${error}`);
    }
    if (!code) {
      throw new Error("No authorization code received in callback URL.");
    }

    // 4. Exchange code for access token via backend
    const exchangeRes = await fetch(`${BACKEND_URL}/api/v1/oauth/gmail/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: code,
        redirect_uri: redirectUri
      })
    });

    if (!exchangeRes.ok) {
      const errData = await exchangeRes.json().catch(() => ({}));
      throw new Error(errData.detail || "Failed to exchange authorization code with backend.");
    }

    const tokenData = await exchangeRes.json();
    const expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;

    // 5. Store session and local display state
    await chrome.storage.session.set({
      access_token: tokenData.access_token,
      expires_at: expiresAt
    });

    const userEmail = tokenData.user_email || "connected.user@gmail.com";
    await chrome.storage.local.set({
      connected: true,
      user_email: userEmail,
      connected_at: new Date().toISOString()
    });

    return {
      status: "connected",
      user_email: userEmail
    };
  } catch (err) {
    console.error("[TRACEGUARD SW] connectGmailAuth error:", err);
    throw err;
  }
}

async function disconnectGmailAuth() {
  await chrome.storage.session.remove(["access_token", "expires_at"]);
  await chrome.storage.local.set({
    connected: false,
    user_email: null
  });
  return { status: "disconnected" };
}

// ═══════════════════════════════════════════════════════════════════
// 2. GMAIL RAW DATA EXTRACTION & INGESTION
// ═══════════════════════════════════════════════════════════════════

async function fetchRawGmailMessage(messageId, token) {
  const url = `${GMAIL_API_BASE}/messages/${messageId}?format=raw`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  if (res.status === 401) {
    // Attempt single refresh
    const newToken = await getAccessToken(true);
    if (newToken) {
      return fetchRawGmailMessage(messageId, newToken);
    }
    throw new Error("UNAUTHORIZED");
  }

  if (!res.ok) {
    throw new Error(`Gmail API error ${res.status}: ${res.statusText}`);
  }

  const data = await res.json();
  return data.raw; // Base64URL RFC822 source
}

async function ingestMessageToTraceguard(rawBase64Url, gmailMessageId) {
  // Convert standard base64url to standard base64
  let base64 = rawBase64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }

  const res = await fetch(`${BACKEND_URL}/api/v1/emails/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      raw_eml_base64: base64,
      gmail_message_id: gmailMessageId
    })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `TRACEGUARD Ingestion failed with status ${res.status}`);
  }

  const bundle = await res.json();
  
  // Record to Recent Scans in local storage (last 50)
  await recordRecentScan({
    messageId: gmailMessageId || bundle.email_id,
    emailId: bundle.email_id,
    caseId: bundle.case_id,
    subject: bundle.subject,
    sender: bundle.from_address,
    verdict: bundle.classification,
    threatScore: bundle.threat_score,
    infraConfidence: bundle.infra_confidence,
    attributionConfidence: bundle.attribution_confidence,
    keySignals: bundle.key_signals,
    auth: bundle.auth,
    claimedDomain: bundle.claimed_domain,
    actualDomain: bundle.actual_domain,
    scannedAt: new Date().toISOString()
  });

  return bundle;
}

async function recordRecentScan(scanRecord) {
  try {
    const { recent_scans = [] } = await chrome.storage.local.get("recent_scans");
    const filtered = recent_scans.filter((s) => s.messageId !== scanRecord.messageId && s.emailId !== scanRecord.emailId);
    const updated = [scanRecord, ...filtered].slice(0, 50);
    await chrome.storage.local.set({ recent_scans: updated });
  } catch (e) {
    console.error("[TRACEGUARD SW] Failed to save recent scan record:", e);
  }
}

// ═══════════════════════════════════════════════════════════════════
// 3. INBOX BATCH SCANNER (WITH REAL-TIME PROGRESS STREAMING)
// ═══════════════════════════════════════════════════════════════════

async function scanInboxMessages(options = {}, port = null) {
  const count = options.count || 20;
  const query = options.query || "in:inbox";

  const token = await getAccessToken();
  if (!token) {
    throw new Error("NOT_AUTHENTICATED");
  }

  // 1. List messages
  const listUrl = `${GMAIL_API_BASE}/messages?maxResults=${count}&q=${encodeURIComponent(query)}`;
  const listRes = await fetch(listUrl, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!listRes.ok) {
    if (listRes.status === 401) throw new Error("UNAUTHORIZED");
    throw new Error(`Failed to list messages: ${listRes.statusText}`);
  }

  const listData = await listRes.json();
  const messages = listData.messages || [];

  if (messages.length === 0) {
    return { results: [], summary: { total: 0, critical: 0, suspicious: 0, safe: 0 } };
  }

  const total = messages.length;
  const results = [];
  const failures = [];

  const notifyProgress = (done, currentSubject, stage, partialResult = null) => {
    const payload = {
      type: "SCAN_PROGRESS",
      done,
      total,
      currentSubject,
      stage,
      partialResult
    };
    if (port) {
      try {
        port.postMessage(payload);
      } catch (e) {
        // Port disconnected
      }
    }
  };

  for (let i = 0; i < messages.length; i++) {
    const msgMeta = messages[i];
    const msgId = msgMeta.id;

    try {
      notifyProgress(i, `Message ID: ${msgId}`, "Extracting raw RFC822 MIME from Gmail API");
      const rawBase64Url = await fetchRawGmailMessage(msgId, token);

      notifyProgress(i, `Message ID: ${msgId}`, "Running 11-Lens Forensic DAG Pipeline");
      const bundle = await ingestMessageToTraceguard(rawBase64Url, msgId);

      results.push(bundle);
      notifyProgress(i + 1, bundle.subject, "Analysis Complete", bundle);
    } catch (err) {
      console.warn(`[TRACEGUARD SW] Error processing message ${msgId}:`, err);
      failures.push({ messageId: msgId, error: err.message });
      notifyProgress(i + 1, `Failed: ${msgId}`, "Failed", null);
    }
  }

  const summary = {
    total: results.length,
    critical: results.filter((r) => r.threat_score >= 0.75).length,
    suspicious: results.filter((r) => r.threat_score >= 0.35 && r.threat_score < 0.75).length,
    safe: results.filter((r) => r.threat_score < 0.35).length,
    failedCount: failures.length
  };

  return { results, summary, failures };
}

// ═══════════════════════════════════════════════════════════════════
// 4. MESSAGE ROUTER & PORT HANDLERS
// ═══════════════════════════════════════════════════════════════════

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "traceguard-inbox-scan") {
    port.onMessage.addListener(async (msg) => {
      if (msg.type === "START_INBOX_SCAN") {
        try {
          const outcome = await scanInboxMessages(msg.options, port);
          port.postMessage({ type: "SCAN_COMPLETE", ...outcome });
        } catch (err) {
          port.postMessage({
            type: "SCAN_ERROR",
            error: err.message || "Failed to scan inbox."
          });
        }
      }
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handleAsync = async () => {
    try {
      switch (message.type) {
        case "AUTH_STATUS": {
          const local = await chrome.storage.local.get(["connected", "user_email"]);
          const token = await getAccessToken();
          return {
            connected: !!token && !!local.connected,
            user_email: local.user_email || null
          };
        }

        case "AUTH_CONNECT": {
          return await connectGmailAuth();
        }

        case "AUTH_DISCONNECT": {
          return await disconnectGmailAuth();
        }

        case "SCAN_MESSAGE": {
          const token = await getAccessToken();
          if (!token) throw new Error("NOT_AUTHENTICATED");
          const rawBase64Url = await fetchRawGmailMessage(message.gmailMessageId, token);
          return await ingestMessageToTraceguard(rawBase64Url, message.gmailMessageId);
        }

        case "INGEST_RAW_EML": {
          return await ingestMessageToTraceguard(message.rawBase64, message.messageId);
        }

        case "GET_RECENT_SCANS": {
          const { recent_scans = [] } = await chrome.storage.local.get("recent_scans");
          return { recent_scans };
        }

        default:
          return { error: `Unknown message type: ${message.type}` };
      }
    } catch (err) {
      console.error(`[TRACEGUARD SW] Handler error for ${message.type}:`, err);
      return { error: err.message || "Internal extension error" };
    }
  };

  handleAsync().then(sendResponse);
  return true; // Keep message channel open for async response
});

// Initialization
chrome.runtime.onInstalled.addListener(() => {
  console.log("[TRACEGUARD AI] V2 MV3 Extension Service Worker installed and ready.");
});
