/**
 * TRACEGUARD AI - Extension Popup View Controller (v2 Modular)
 */

import { WEB_APP_BASE, VIEW_STATES, ENDPOINTS } from '../shared/constants.js';
import { MESSAGE_TYPES } from '../shared/messages.js';

// DOM Elements
const themeSelect = document.getElementById('themeSelect');
const statusIndicator = document.getElementById('statusIndicator');
const statusText = document.getElementById('statusText');

// Views
const viewDisconnected = document.getElementById('viewDisconnected');
const viewConnected = document.getElementById('viewConnected');
const viewScanning = document.getElementById('viewScanning');
const viewResults = document.getElementById('viewResults');
const viewBatchSummary = document.getElementById('viewBatchSummary');

// Disconnected Controls
const btnConnectGmail = document.getElementById('btnConnectGmail');

// Connected Controls
const userEmailLabel = document.getElementById('userEmailLabel');
const btnDisconnect = document.getElementById('btnDisconnect');
const scanQuerySelect = document.getElementById('scanQuerySelect');
const scanCountSelect = document.getElementById('scanCountSelect');
const btnStartInboxScan = document.getElementById('btnStartInboxScan');
const btnScanCurrentEmail = document.getElementById('btnScanCurrentEmail');
const recentScansList = document.getElementById('recentScansList');
const recentCountBadge = document.getElementById('recentCountBadge');

// Scanning Controls
const scanProgressCount = document.getElementById('scanProgressCount');
const progressBar = document.getElementById('progressBar');
const activeScanSubject = document.getElementById('activeScanSubject');
const activeScanStage = document.getElementById('activeScanStage');

// Results Controls
const btnBackToDashboard = document.getElementById('btnBackToDashboard');
const verdictTag = document.getElementById('verdictTag');
const actionTag = document.getElementById('actionTag');
const scoreNumber = document.getElementById('scoreNumber');
const emailSubject = document.getElementById('emailSubject');
const emailSender = document.getElementById('emailSender');
const signalsList = document.getElementById('signalsList');
const claimedDomain = document.getElementById('claimedDomain');
const actualDomain = document.getElementById('actualDomain');
const axisThreatVal = document.getElementById('axisThreatVal');
const axisThreatBar = document.getElementById('axisThreatBar');
const axisInfraVal = document.getElementById('axisInfraVal');
const axisInfraBar = document.getElementById('axisInfraBar');
const axisAttrVal = document.getElementById('axisAttrVal');
const axisAttrBar = document.getElementById('axisAttrBar');
const authSpfVal = document.getElementById('authSpfVal');
const authDkimVal = document.getElementById('authDkimVal');
const authDmarcVal = document.getElementById('authDmarcVal');
const authArcVal = document.getElementById('authArcVal');
const btnOpenFullInvestigation = document.getElementById('btnOpenFullInvestigation');

// Batch Controls
const batchCriticalCount = document.getElementById('batchCriticalCount');
const batchSuspiciousCount = document.getElementById('batchSuspiciousCount');
const batchSafeCount = document.getElementById('batchSafeCount');
const batchResultsList = document.getElementById('batchResultsList');
const btnBatchDone = document.getElementById('btnBatchDone');

// Error Toast
const errorToast = document.getElementById('errorToast');
const errorMessage = document.getElementById('errorMessage');
const btnDismissError = document.getElementById('btnDismissError');

let currentActiveEmailId = null;
let currentActiveView = VIEW_STATES.DISCONNECTED;

document.addEventListener('DOMContentLoaded', async () => {
  await initTheme();
  await checkAuthStatus();
  await loadRecentScans();
  setupEventListeners();
});

async function initTheme() {
  const { traceguard_theme = 'obsidian' } = await chrome.storage.local.get('traceguard_theme');
  document.documentElement.setAttribute('data-theme', traceguard_theme);
  themeSelect.value = traceguard_theme;

  themeSelect.addEventListener('change', (e) => {
    const val = e.target.value;
    document.documentElement.setAttribute('data-theme', val);
    chrome.storage.local.set({ traceguard_theme: val });
  });
}

function showView(viewState) {
  currentActiveView = viewState;
  const views = [viewDisconnected, viewConnected, viewScanning, viewResults, viewBatchSummary];
  views.forEach((v) => { if (v) v.classList.add('hidden'); });

  if (viewState === VIEW_STATES.DISCONNECTED) viewDisconnected.classList.remove('hidden');
  else if (viewState === VIEW_STATES.CONNECTED_IDLE) viewConnected.classList.remove('hidden');
  else if (viewState === VIEW_STATES.SCANNING) viewScanning.classList.remove('hidden');
  else if (viewState === VIEW_STATES.RESULTS) viewResults.classList.remove('hidden');
  else if (viewState === VIEW_STATES.BATCH_SUMMARY) viewBatchSummary.classList.remove('hidden');
}

function showError(msg) {
  errorMessage.innerText = msg;
  errorToast.classList.remove('hidden');
  setTimeout(() => {
    errorToast.classList.add('hidden');
  }, 6000);
}

async function checkAuthStatus() {
  try {
    const res = await chrome.runtime.sendMessage({ type: MESSAGE_TYPES.AUTH_STATUS });
    if (res && res.connected) {
      userEmailLabel.innerText = res.user_email || 'Google Authorized';
      statusText.innerText = 'Connected';
      showView(VIEW_STATES.CONNECTED_IDLE);
    } else {
      statusText.innerText = 'Offline';
      showView(VIEW_STATES.DISCONNECTED);
    }
  } catch (e) {
    showView(VIEW_STATES.DISCONNECTED);
  }
}

async function handleConnect() {
  btnConnectGmail.disabled = true;
  btnConnectGmail.innerText = 'Connecting Google OAuth...';
  try {
    const res = await chrome.runtime.sendMessage({ type: MESSAGE_TYPES.AUTH_CONNECT });
    if (res && res.status === 'connected') {
      userEmailLabel.innerText = res.user_email;
      statusText.innerText = 'Connected';
      showView(VIEW_STATES.CONNECTED_IDLE);
      await loadRecentScans();
    } else if (res && res.error) {
      showError(res.error);
      showView(VIEW_STATES.DISCONNECTED);
    }
  } catch (e) {
    showError(e.message || 'Failed to complete Google OAuth.');
    showView(VIEW_STATES.DISCONNECTED);
  } finally {
    btnConnectGmail.disabled = false;
    btnConnectGmail.innerHTML = `<span>Authorize with Google OAuth</span><span class="arrow-icon">&rarr;</span>`;
  }
}

async function handleDisconnect() {
  await chrome.runtime.sendMessage({ type: MESSAGE_TYPES.AUTH_DISCONNECT });
  statusText.innerText = 'Offline';
  showView(VIEW_STATES.DISCONNECTED);
}

function startInboxScan() {
  const query = scanQuerySelect.value;
  const count = parseInt(scanCountSelect.value, 10) || 20;

  showView(VIEW_STATES.SCANNING);
  progressBar.style.width = '5%';
  scanProgressCount.innerText = 'Connecting to Gmail API...';
  activeScanSubject.innerText = 'Listing recent inbox messages';
  activeScanStage.innerText = 'Authenticating RFC822 Stream';

  const port = chrome.runtime.connect({ name: 'scan-inbox' });

  port.postMessage({
    type: MESSAGE_TYPES.SCAN_INBOX,
    count,
    query
  });

  port.onMessage.addListener((msg) => {
    if (msg.type === MESSAGE_TYPES.SCAN_PROGRESS) {
      const pct = Math.max(5, Math.round((msg.done / msg.total) * 100));
      progressBar.style.width = `${pct}%`;
      scanProgressCount.innerText = `Analyzing ${msg.done + 1} of ${msg.total} Messages...`;
      activeScanSubject.innerText = msg.currentSubject || 'Processing MIME structure...';
      activeScanStage.innerText = msg.stage || 'Forensic Pipeline DAG';
    } else if (msg.type === MESSAGE_TYPES.SCAN_COMPLETE) {
      renderBatchSummary(msg);
      loadRecentScans();
    } else if (msg.type === MESSAGE_TYPES.SCAN_ERROR) {
      showError(msg.error || 'Inbox scan encountered an error.');
      showView(VIEW_STATES.CONNECTED_IDLE);
    }
  });

  port.onDisconnect.addListener(() => {
    if (currentActiveView === VIEW_STATES.SCANNING) {
      showView(VIEW_STATES.CONNECTED_IDLE);
    }
  });
}

function renderBatchSummary(data) {
  const { results = [], summary = { critical: 0, suspicious: 0, safe: 0 } } = data;
  batchCriticalCount.innerText = summary.critical || 0;
  batchSuspiciousCount.innerText = summary.suspicious || 0;
  batchSafeCount.innerText = summary.safe || 0;

  batchResultsList.innerHTML = '';
  if (results.length === 0) {
    batchResultsList.innerHTML = `<div class="empty-state">No matching emails found for this query.</div>`;
  } else {
    results.forEach((item) => {
      const el = document.createElement('div');
      el.className = 'recent-item';
      const score = Math.round((item.threat_score || 0) * 100);
      let badgeClass = 'safe';
      if (item.threat_score >= 0.75) badgeClass = 'critical';
      else if (item.threat_score >= 0.35) badgeClass = 'suspicious';

      el.innerHTML = `
        <div class="recent-meta">
          <div class="recent-subj truncate">${item.subject || '(No Subject)'}</div>
          <div class="recent-sender truncate">${item.from_address || item.claimed_domain || 'Unknown'}</div>
        </div>
        <span class="score-badge-mini ${badgeClass}">${score}%</span>
      `;

      el.addEventListener('click', () => {
        renderEmailDetail(item);
      });

      batchResultsList.appendChild(el);
    });
  }

  showView(VIEW_STATES.BATCH_SUMMARY);
}

async function handleScanCurrentEmail() {
  btnScanCurrentEmail.disabled = true;
  btnScanCurrentEmail.innerText = 'Inspecting Active Tab...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('No active browser tab detected.');

    chrome.tabs.sendMessage(tab.id, { action: MESSAGE_TYPES.EXTRACT_AND_ANALYZE }, async (response) => {
      if (chrome.runtime.lastError || !response) {
        showError('Please open an email inside Gmail to inspect.');
        btnScanCurrentEmail.disabled = false;
        btnScanCurrentEmail.innerHTML = `<span>Scan Open Webmail Tab</span><span class="arrow-icon">&rarr;</span>`;
        return;
      }

      if (response.bundle) {
        renderEmailDetail(response.bundle);
      } else if (response.error) {
        showError(response.error);
      }
      btnScanCurrentEmail.disabled = false;
      btnScanCurrentEmail.innerHTML = `<span>Scan Open Webmail Tab</span><span class="arrow-icon">&rarr;</span>`;
    });
  } catch (e) {
    showError(e.message || 'Failed to inspect active tab.');
    btnScanCurrentEmail.disabled = false;
    btnScanCurrentEmail.innerHTML = `<span>Scan Open Webmail Tab</span><span class="arrow-icon">&rarr;</span>`;
  }
}

function renderEmailDetail(item) {
  currentActiveEmailId = item.email_id || item.emailId;

  const score = Math.round((item.threat_score || item.threatScore || 0) * 100);
  const infra = Math.round((item.infra_confidence || item.infraConfidence || 0.8) * 100);
  const attrib = Math.round((item.attribution_confidence || item.attributionConfidence || 0.4) * 100);

  scoreNumber.innerText = `${score}%`;
  emailSubject.innerText = item.subject || '(No Subject)';
  emailSender.innerText = item.from_address || item.sender || 'Unknown Sender';

  if (score >= 75) {
    verdictTag.innerText = item.classification || 'MALICIOUS';
    verdictTag.style.color = 'var(--threat-critical)';
    actionTag.innerText = 'QUARANTINED';
    scoreNumber.style.color = 'var(--threat-critical)';
  } else if (score >= 35) {
    verdictTag.innerText = item.classification || 'SUSPICIOUS';
    verdictTag.style.color = 'var(--threat-warning)';
    actionTag.innerText = 'FLAGGED';
    scoreNumber.style.color = 'var(--threat-warning)';
  } else {
    verdictTag.innerText = 'BENIGN / SAFE';
    verdictTag.style.color = 'var(--threat-safe)';
    actionTag.innerText = 'DELIVERED';
    scoreNumber.style.color = 'var(--threat-safe)';
  }

  signalsList.innerHTML = '';
  const signals = item.key_signals || item.keySignals || [
    'Anomalous sending infrastructure',
    'Cryptographic verification check',
    'Late fusion intent classification'
  ];
  signals.slice(0, 3).forEach((sig) => {
    const row = document.createElement('div');
    row.className = 'signal-row';
    row.innerHTML = `<span class="signal-bullet">&bull;</span><span>${sig}</span>`;
    signalsList.appendChild(row);
  });

  claimedDomain.innerText = item.claimed_domain || item.claimedDomain || (item.from_address ? item.from_address.split('@')[1] : 'sender.com');
  actualDomain.innerText = item.actual_domain || item.actualDomain || item.claimed_domain || 'relay.net';
  if (claimedDomain.innerText !== actualDomain.innerText) {
    actualDomain.classList.add('mismatch');
  } else {
    actualDomain.classList.remove('mismatch');
  }

  axisThreatVal.innerText = `${score}%`;
  axisThreatBar.style.width = `${score}%`;
  axisInfraVal.innerText = `${infra}%`;
  axisInfraBar.style.width = `${infra}%`;
  axisAttrVal.innerText = `${attrib}%`;
  axisAttrBar.style.width = `${attrib}%`;

  const auth = item.auth || {};
  authSpfVal.innerText = auth.spf || 'FAIL';
  authSpfVal.className = `auth-status ${auth.spf === 'PASS' ? 'pass' : 'fail'}`;

  authDkimVal.innerText = auth.dkim || 'FAIL';
  authDkimVal.className = `auth-status ${auth.dkim === 'PASS' ? 'pass' : 'fail'}`;

  authDmarcVal.innerText = auth.dmarc || 'FAIL';
  authDmarcVal.className = `auth-status ${auth.dmarc === 'PASS' ? 'pass' : 'fail'}`;

  authArcVal.innerText = auth.arc || 'PASS';
  authArcVal.className = `auth-status ${auth.arc === 'PASS' ? 'pass' : 'fail'}`;

  showView(VIEW_STATES.RESULTS);
}

async function loadRecentScans() {
  try {
    const res = await chrome.runtime.sendMessage({ type: MESSAGE_TYPES.GET_RECENT_SCANS });
    const scans = res ? res.recent_scans || [] : [];
    recentCountBadge.innerText = scans.length;

    recentScansList.innerHTML = '';
    if (scans.length === 0) {
      recentScansList.innerHTML = `<div class="empty-state">No recent scans. Run an inbox scan to begin.</div>`;
      return;
    }

    scans.forEach((s) => {
      const el = document.createElement('div');
      el.className = 'recent-item';
      const score = Math.round((s.threatScore || s.threat_score || 0) * 100);
      let badgeClass = 'safe';
      if (score >= 75) badgeClass = 'critical';
      else if (score >= 35) badgeClass = 'suspicious';

      el.innerHTML = `
        <div class="recent-meta">
          <div class="recent-subj truncate">${s.subject || '(No Subject)'}</div>
          <div class="recent-sender truncate">${s.sender || s.from_address || 'Unknown'}</div>
        </div>
        <span class="score-badge-mini ${badgeClass}">${score}%</span>
      `;

      el.addEventListener('click', () => {
        renderEmailDetail(s);
      });

      recentScansList.appendChild(el);
    });
  } catch (e) {
    console.error('Failed to load recent scans:', e);
  }
}

function setupEventListeners() {
  btnConnectGmail.addEventListener('click', handleConnect);
  btnDisconnect.addEventListener('click', handleDisconnect);
  btnStartInboxScan.addEventListener('click', startInboxScan);
  btnScanCurrentEmail.addEventListener('click', handleScanCurrentEmail);
  btnBatchDone.addEventListener('click', () => showView(VIEW_STATES.CONNECTED_IDLE));
  btnBackToDashboard.addEventListener('click', () => showView(VIEW_STATES.CONNECTED_IDLE));

  btnDismissError.addEventListener('click', () => {
    errorToast.classList.add('hidden');
  });

  btnOpenFullInvestigation.addEventListener('click', () => {
    if (currentActiveEmailId) {
      chrome.tabs.create({ url: `${WEB_APP_BASE}/investigation?id=${currentActiveEmailId}` });
    } else {
      chrome.tabs.create({ url: `${WEB_APP_BASE}/investigation` });
    }
  });
}
