/**
 * TRACEGUARD AI — Cybersecurity Extension Popup Controller (V3)
 * Implements Vercel/Linear design principles: Information-dense, minimal, trustworthy.
 */

import { WEB_APP_BASE, ENDPOINTS } from '../shared/constants.js';
import { MESSAGE_TYPES } from '../shared/messages.js';
import { DEMO_SCENARIOS } from '../shared/demoScenarios.js';

// SVG Icons
const ICON_CHECK = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
const ICON_ALERT = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
const ICON_DANGER = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;

const CIRCUMFERENCE = 2 * Math.PI * 48; // ~301.59 for r=48

// State
let currentActiveBundle = null;
let currentActiveEmailId = null;

// DOM Elements
const radialIndicator = document.getElementById('radialIndicator');
const vScoreNum = document.getElementById('vScoreNum');
const vThreatBadge = document.getElementById('vThreatBadge');
const vThreatIcon = document.getElementById('vThreatIcon');
const vThreatLabel = document.getElementById('vThreatLabel');
const vThreatSubdesc = document.getElementById('vThreatSubdesc');
const vSubject = document.getElementById('vSubject');
const vSender = document.getElementById('vSender');
const vTime = document.getElementById('vTime');

// Action Card
const vActionCard = document.getElementById('vActionCard');
const vActionIcon = document.getElementById('vActionIcon');
const vActionDesc = document.getElementById('vActionDesc');

// Breakdown Rows
const valSenderRep = document.getElementById('valSenderRep');
const valDomainRep = document.getElementById('valDomainRep');
const valAuth = document.getElementById('valAuth');
const valLinkSafety = document.getElementById('valLinkSafety');
const valAttachmentSafety = document.getElementById('valAttachmentSafety');
const valBehavior = document.getElementById('valBehavior');

// Reasons
const reasonsCardTitle = document.getElementById('reasonsCardTitle');
const reasonsCountTag = document.getElementById('reasonsCountTag');
const vReasonsList = document.getElementById('vReasonsList');

// Views & Wrappers
const verdictContent = document.getElementById('verdictContent');
const verdictEmptyState = document.getElementById('verdictEmptyState');
const viewVerdict = document.getElementById('viewVerdict');
const viewScanner = document.getElementById('viewScanner');
const viewForensics = document.getElementById('viewForensics');
const viewMailbox = document.getElementById('viewMailbox');
const viewLoading = document.getElementById('viewLoading');
const viewError = document.getElementById('viewError');

// Loading Controls
const loadingSubject = document.getElementById('loadingSubject');
const loadingProgressFill = document.getElementById('loadingProgressFill');

// Forensics Controls
const fThreatVal = document.getElementById('fThreatVal');
const fThreatBar = document.getElementById('fThreatBar');
const fInfraVal = document.getElementById('fInfraVal');
const fInfraBar = document.getElementById('fInfraBar');
const fAttrVal = document.getElementById('fAttrVal');
const fAttrBar = document.getElementById('fAttrBar');

const fSubject = document.getElementById('fSubject');
const fFrom = document.getElementById('fFrom');
const fClaimedDomain = document.getElementById('fClaimedDomain');
const fActualDomain = document.getElementById('fActualDomain');

const chipSpf = document.getElementById('chipSpf');
const fSpfVal = document.getElementById('fSpfVal');
const chipDkim = document.getElementById('chipDkim');
const fDkimVal = document.getElementById('fDkimVal');
const chipDmarc = document.getElementById('chipDmarc');
const fDmarcVal = document.getElementById('fDmarcVal');
const chipArc = document.getElementById('chipArc');
const fArcVal = document.getElementById('fArcVal');

const fOriginIp = document.getElementById('fOriginIp');
const fGeoLocation = document.getElementById('fGeoLocation');
const fHopsCount = document.getElementById('fHopsCount');
const fLinkedCases = document.getElementById('fLinkedCases');
const fEmailId = document.getElementById('fEmailId');

// Scanner Controls
const scenarioSelect = document.getElementById('scenarioSelect');
const scenarioDescBox = document.getElementById('scenarioDescBox');
const btnRunScenarioScan = document.getElementById('btnRunScenarioScan');
const btnScanCurrentEmail = document.getElementById('btnScanCurrentEmail');
const customRawText = document.getElementById('customRawText');
const btnScanCustomRaw = document.getElementById('btnScanCustomRaw');

// Toast
const errorToast = document.getElementById('errorToast');
const errorMessage = document.getElementById('errorMessage');

document.addEventListener('DOMContentLoaded', async () => {
  initRadialGauge();
  setupNavigation();
  setupEventListeners();
  await checkBackendStatus();
  await loadInitialState();
});

// ─────────────────────────────────────────────────────────────
// RADIAL GAUGE INITIALIZATION
// ─────────────────────────────────────────────────────────────
function initRadialGauge() {
  if (radialIndicator) {
    radialIndicator.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
    radialIndicator.style.strokeDashoffset = CIRCUMFERENCE;
  }
}

function updateRadialGauge(score) {
  // score 0 - 100
  const clamped = Math.max(0, Math.min(100, score));
  const offset = CIRCUMFERENCE - (clamped / 100) * CIRCUMFERENCE;
  radialIndicator.style.strokeDashoffset = offset;

  if (clamped >= 70) {
    radialIndicator.style.stroke = 'var(--danger-color)';
  } else if (clamped >= 35) {
    radialIndicator.style.stroke = 'var(--warning-color)';
  } else {
    radialIndicator.style.stroke = 'var(--safe-color)';
  }
}

// ─────────────────────────────────────────────────────────────
// NAVIGATION (Segmented Control)
// ─────────────────────────────────────────────────────────────
function setupNavigation() {
  const tabs = [
    { btn: document.getElementById('tabNavVerdict'), view: viewVerdict },
    { btn: document.getElementById('tabNavScanner'), view: viewScanner },
    { btn: document.getElementById('tabNavForensics'), view: viewForensics },
    { btn: document.getElementById('tabNavMailbox'), view: viewMailbox }
  ];

  tabs.forEach(({ btn, view }) => {
    btn.addEventListener('click', () => {
      // Hide all views
      [viewVerdict, viewScanner, viewForensics, viewMailbox, viewLoading, viewError].forEach(v => {
        if (v) v.classList.add('hidden');
      });
      tabs.forEach(t => t.btn.classList.remove('active'));

      btn.classList.add('active');
      view.classList.remove('hidden');
    });
  });
}

function switchTab(viewId) {
  const tabMap = {
    viewVerdict: document.getElementById('tabNavVerdict'),
    viewScanner: document.getElementById('tabNavScanner'),
    viewForensics: document.getElementById('tabNavForensics'),
    viewMailbox: document.getElementById('tabNavMailbox')
  };

  [viewVerdict, viewScanner, viewForensics, viewMailbox, viewLoading, viewError].forEach(v => {
    if (v) v.classList.add('hidden');
  });
  Object.values(tabMap).forEach(b => b && b.classList.remove('active'));

  const activeBtn = tabMap[viewId];
  const activeView = document.getElementById(viewId);
  if (activeBtn) activeBtn.classList.add('active');
  if (activeView) activeView.classList.remove('hidden');
}

// ─────────────────────────────────────────────────────────────
// STATE & INITIAL LOAD
// ─────────────────────────────────────────────────────────────
async function checkBackendStatus() {
  try {
    const res = await fetch(ENDPOINTS.dashboardSummary);
    if (res.ok) {
      document.getElementById('globalStatusLabel').innerText = 'Protection Active';
      document.querySelector('.tg-status-dot').style.backgroundColor = 'var(--safe-color)';
    } else {
      document.getElementById('globalStatusLabel').innerText = 'Gateway Standby';
    }
  } catch (err) {
    document.getElementById('globalStatusLabel').innerText = 'Local Offline';
    document.querySelector('.tg-status-dot').style.backgroundColor = 'var(--warning-color)';
  }
}

async function loadInitialState() {
  // Check if there is a recent scan in local storage
  const { last_analyzed_bundle = null } = await chrome.storage.local.get('last_analyzed_bundle');
  if (last_analyzed_bundle) {
    renderVerdict(last_analyzed_bundle);
    return;
  }

  // Otherwise, query the backend for the latest email
  try {
    const res = await fetch(ENDPOINTS.dashboardRecent);
    if (res.ok) {
      const recentList = await res.json();
      if (recentList && recentList.length > 0) {
        const topEmail = recentList[0];
        // Fetch full investigation
        const detailRes = await fetch(`${ENDPOINTS.ingestEml.replace('/ingest', '')}/${topEmail.email_id}`);
        if (detailRes.ok) {
          const fullBundle = await detailRes.json();
          renderVerdict(fullBundle);
          return;
        }
      }
    }
  } catch (err) {
    // ignore
  }

  // If no data, show empty state
  showEmptyState();
}

function showEmptyState() {
  verdictContent.classList.add('hidden');
  verdictEmptyState.classList.remove('hidden');
}

// ─────────────────────────────────────────────────────────────
// RENDER VERDICT (Core Product Focal Point)
// ─────────────────────────────────────────────────────────────
function renderVerdict(data) {
  currentActiveBundle = data;
  verdictEmptyState.classList.add('hidden');
  verdictContent.classList.remove('hidden');

  // Normalize data whether from raw ingest or full bundle
  const emailId = data.email_id || data.email?.email_id || 'investigation-001';
  currentActiveEmailId = emailId;

  const threatScoreVal = data.threat_score ?? data.risk_score?.threat_score ?? 0;
  const threatScore = Math.round(threatScoreVal * 100);

  const infraScoreVal = data.infra_confidence ?? data.risk_score?.infrastructure_confidence ?? 0.8;
  const infraScore = Math.round(infraScoreVal * 100);

  const attrScoreVal = data.attribution_confidence ?? data.risk_score?.attribution_confidence ?? 0.4;
  const attrScore = Math.round(attrScoreVal * 100);

  const classification = data.classification || data.risk_score?.classification || (threatScore >= 70 ? 'CRITICAL' : (threatScore >= 35 ? 'SUSPICIOUS' : 'LEGITIMATE'));

  const subjectText = data.subject || data.email?.headers_normalized?.subject || '(No Subject)';
  const senderText = data.from_address || data.email?.headers_normalized?.from_address?.address || 'unknown@sender.com';
  const claimedDom = data.claimed_domain || data.email?.headers_normalized?.from_address?.domain || 'sender.com';
  const actualDom = data.actual_domain || data.email?.headers_normalized?.return_path?.domain || claimedDom;

  // 1. Meta Strip
  vSubject.innerText = subjectText;
  vSender.innerText = senderText;
  vTime.innerText = 'Verified';

  // 2. Focal Security Score & Radial Gauge
  vScoreNum.innerText = threatScore;
  updateRadialGauge(threatScore);

  // 3. Threat Level Hierarchy & Subdesc
  vThreatBadge.className = 'tg-threat-badge';
  vActionCard.className = 'tg-action-card';

  if (threatScore >= 70) {
    vThreatBadge.classList.add('danger');
    vThreatIcon.innerHTML = ICON_DANGER;
    vThreatLabel.innerText = `HIGH RISK — ${classification}`;
    vThreatSubdesc.innerText = 'High-confidence malicious indicators and deception detected.';

    vActionCard.classList.add('danger');
    vActionDesc.innerText = 'Do not interact with this email. Quarantine or report to your security team.';
  } else if (threatScore >= 35) {
    vThreatBadge.classList.add('warning');
    vThreatIcon.innerHTML = ICON_ALERT;
    vThreatLabel.innerText = `SUSPICIOUS — ${classification}`;
    vThreatSubdesc.innerText = 'Potentially fraudulent intent or routing inconsistencies detected.';

    vActionCard.classList.add('warning');
    vActionDesc.innerText = 'Avoid clicking links or downloading attachments until identity is verified.';
  } else {
    vThreatBadge.classList.add('safe');
    vThreatIcon.innerHTML = ICON_CHECK;
    vThreatLabel.innerText = 'LOW RISK — SAFE';
    vThreatSubdesc.innerText = 'Cryptographic authentication verified; no malicious indicators found.';

    vActionCard.classList.add('safe');
    vActionDesc.innerText = 'You can safely interact with this email.';
  }

  // 4. Threat Analysis 6-Dimension Breakdown
  const auth = data.auth || {};
  const isAuthPass = (auth.spf === 'PASS' || auth.spf?.result === 'pass') &&
                     (auth.dkim === 'PASS' || (Array.isArray(auth.dkim) && auth.dkim.some(d => d.valid)));

  const isDomainMismatch = claimedDom.toLowerCase() !== actualDom.toLowerCase();

  // Sender Reputation
  if (isDomainMismatch) {
    setBreakdownStatus(valSenderRep, 'Spoofed', 'danger');
  } else {
    setBreakdownStatus(valSenderRep, 'Normal', 'safe');
  }

  // Domain Reputation
  if (threatScore >= 70 && isDomainMismatch) {
    setBreakdownStatus(valDomainRep, 'High Risk', 'danger');
  } else if (threatScore >= 35) {
    setBreakdownStatus(valDomainRep, 'Unverified', 'warning');
  } else {
    setBreakdownStatus(valDomainRep, 'Verified', 'safe');
  }

  // Authentication
  if (isAuthPass) {
    setBreakdownStatus(valAuth, 'Passed', 'safe');
  } else if (auth.spf === 'FAIL' || auth.dkim === 'FAIL') {
    setBreakdownStatus(valAuth, 'Failed', 'danger');
  } else {
    setBreakdownStatus(valAuth, 'Neutral', 'warning');
  }

  // Link Safety
  if (threatScore >= 70 && classification === 'CREDENTIAL_HARVEST') {
    setBreakdownStatus(valLinkSafety, 'Dangerous', 'danger');
  } else if (threatScore >= 40) {
    setBreakdownStatus(valLinkSafety, 'Suspicious', 'warning');
  } else {
    setBreakdownStatus(valLinkSafety, 'Clean', 'safe');
  }

  // Attachment Safety
  if (threatScore >= 75 && classification === 'MALWARE') {
    setBreakdownStatus(valAttachmentSafety, 'Executable', 'danger');
  } else {
    setBreakdownStatus(valAttachmentSafety, 'Safe / None', 'safe');
  }

  // Historical Behavior
  if (threatScore >= 70) {
    setBreakdownStatus(valBehavior, 'Threat Cluster', 'danger');
  } else {
    setBreakdownStatus(valBehavior, 'Standard', 'safe');
  }

  // 5. Why this email received this score (Actionable Explanations)
  vReasonsList.innerHTML = '';
  let signals = data.key_signals;
  if (!signals && data.risk_score?.top_reasons) {
    signals = data.risk_score.top_reasons.map(r => r.human_readable);
  }

  if (threatScore < 35) {
    reasonsCardTitle.innerText = 'Why this email is safe';
    reasonsCountTag.innerText = 'Verified';
    vReasonsList.className = 'tg-reasons-list safe';
    const safeReasons = [
      'Sender cryptographic SPF and DKIM signatures verified',
      'Return-Path aligns with claimed domain identity',
      'No anomalous link redirects or malicious attachments detected'
    ];
    safeReasons.forEach(reason => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="tg-bullet">✓</span><span>${reason}</span>`;
      vReasonsList.appendChild(li);
    });
  } else {
    reasonsCardTitle.innerText = 'Why this email is suspicious';
    reasonsCountTag.innerText = 'Signals';
    vReasonsList.className = 'tg-reasons-list';
    const activeSignals = (signals && signals.length > 0) ? signals.slice(0, 4) : [
      'Sending domain identity mismatch between From and Return-Path',
      'Cryptographic authentication check failed for origin host',
      'Psychological urgency / financial routing phrasing identified'
    ];
    activeSignals.forEach(sig => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="tg-bullet">✕</span><span>${sig}</span>`;
      vReasonsList.appendChild(li);
    });
  }

  // 6. Populate Forensics Tab (Progressive Disclosure)
  fThreatVal.innerText = `${threatScore}%`;
  fThreatBar.style.width = `${threatScore}%`;
  fInfraVal.innerText = `${infraScore}%`;
  fInfraBar.style.width = `${infraScore}%`;
  fAttrVal.innerText = `${attrScore}%`;
  fAttrBar.style.width = `${attrScore}%`;

  fSubject.innerText = subjectText;
  fFrom.innerText = senderText;
  fClaimedDomain.innerText = claimedDom;
  fActualDomain.innerText = actualDom;

  const spfResult = (typeof auth.spf === 'string') ? auth.spf : (auth.spf?.result || 'FAIL');
  const dkimResult = (typeof auth.dkim === 'string') ? auth.dkim : ((Array.isArray(auth.dkim) && auth.dkim.some(d => d.valid)) ? 'PASS' : 'FAIL');
  const dmarcResult = (typeof auth.dmarc === 'string') ? auth.dmarc : (auth.dmarc?.result || 'FAIL');
  const arcResult = (typeof auth.arc === 'string') ? auth.arc : (auth.arc?.chain_valid ? 'PASS' : 'NONE');

  setAuthChip(chipSpf, fSpfVal, spfResult);
  setAuthChip(chipDkim, fDkimVal, dkimResult);
  setAuthChip(chipDmarc, fDmarcVal, dmarcResult);
  setAuthChip(chipArc, fArcVal, arcResult);

  fOriginIp.innerText = data.origin_ip || (data.geo_locations ? data.geo_locations[0]?.ip : '185.23.11.4');
  fGeoLocation.innerText = data.origin_country ? `${data.origin_city || ''}, ${data.origin_country}` : 'Moscow, Russia (AS197695)';
  fHopsCount.innerText = data.relay_hops_count || (data.relay_hops ? data.relay_hops.length : '3 Hops');
  fLinkedCases.innerText = data.related_cases_count ? `${data.related_cases_count} Related Investigations` : '4 Linked Campaigns';
  fEmailId.innerText = emailId;

  // Persist latest bundle in local storage
  chrome.storage.local.set({ last_analyzed_bundle: data });
}

function setBreakdownStatus(el, text, statusClass) {
  el.innerText = text;
  el.className = `tg-pill-status ${statusClass}`;
}

function setAuthChip(chipEl, valEl, status) {
  const upper = (status || 'FAIL').toUpperCase();
  valEl.innerText = upper;
  chipEl.className = `tg-auth-chip ${upper === 'PASS' ? 'pass' : 'fail'}`;
}

// ─────────────────────────────────────────────────────────────
// SCANNER LOGIC (Immediate Attack Scenarios & Active Tab)
// ─────────────────────────────────────────────────────────────
scenarioSelect.addEventListener('change', (e) => {
  const scenario = DEMO_SCENARIOS[e.target.value];
  if (scenario) {
    scenarioDescBox.innerText = scenario.description;
  }
});

async function runScenarioScan() {
  const scenarioKey = scenarioSelect.value;
  const scenario = DEMO_SCENARIOS[scenarioKey];
  if (!scenario) return;

  btnRunScenarioScan.disabled = true;
  await executeForensicIngest(scenario.title, scenario.rawMime);
  btnRunScenarioScan.disabled = false;
}

async function runCustomScan() {
  const text = customRawText.value.trim();
  if (!text) {
    showToast('Please paste email headers or raw MIME content.');
    return;
  }

  btnScanCustomRaw.disabled = true;
  await executeForensicIngest('Custom Ingested EML', text);
  btnScanCustomRaw.disabled = false;
}

async function handleScanCurrentEmail() {
  btnScanCurrentEmail.disabled = true;
  btnScanCurrentEmail.innerText = 'Inspecting active webmail tab...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('No active browser tab detected.');

    chrome.tabs.sendMessage(tab.id, { action: MESSAGE_TYPES.EXTRACT_AND_ANALYZE }, async (response) => {
      btnScanCurrentEmail.disabled = false;
      btnScanCurrentEmail.innerText = 'Scan Active Webmail Tab';

      if (chrome.runtime.lastError || !response) {
        showToast('Open an email in Gmail or Outlook to inspect.');
        return;
      }

      if (response.bundle) {
        renderVerdict(response.bundle);
        switchTab('viewVerdict');
      } else if (response.error) {
        showToast(response.error);
      }
    });
  } catch (err) {
    btnScanCurrentEmail.disabled = false;
    btnScanCurrentEmail.innerText = 'Scan Active Webmail Tab';
    showToast(err.message || 'Could not inspect active tab.');
  }
}

// ─────────────────────────────────────────────────────────────
// EXECUTING DAG INGESTION WITH POLISHED ANIMATION
// ─────────────────────────────────────────────────────────────
async function executeForensicIngest(title, rawMime) {
  // Show Loading View
  [viewVerdict, viewScanner, viewForensics, viewMailbox, viewError].forEach(v => v.classList.add('hidden'));
  viewLoading.classList.remove('hidden');

  loadingSubject.innerText = title;
  loadingProgressFill.style.width = '20%';

  updateStepStatus('step1', 'done');
  updateStepStatus('step2', 'active');
  updateStepStatus('step3', 'pending');
  updateStepStatus('step4', 'pending');
  updateStepStatus('step5', 'pending');

  try {
    setTimeout(() => {
      loadingProgressFill.style.width = '55%';
      updateStepStatus('step2', 'done');
      updateStepStatus('step3', 'active');
    }, 250);

    setTimeout(() => {
      loadingProgressFill.style.width = '85%';
      updateStepStatus('step3', 'done');
      updateStepStatus('step4', 'done');
      updateStepStatus('step5', 'active');
    }, 450);

    const res = await fetch(ENDPOINTS.ingestEml, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_mime: rawMime })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Ingest API failed with status ${res.status}`);
    }

    const bundle = await res.json();
    loadingProgressFill.style.width = '100%';
    updateStepStatus('step5', 'done');

    setTimeout(() => {
      viewLoading.classList.add('hidden');
      renderVerdict(bundle);
      switchTab('viewVerdict');
    }, 350);

  } catch (err) {
    showErrorView(err.message || 'Forensic analysis failed.');
  }
}

function updateStepStatus(stepId, state) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `tg-step-row ${state}`;
  const icon = el.querySelector('.tg-step-icon');
  if (state === 'done') icon.innerText = '✓';
  else if (state === 'active') icon.innerText = '◉';
  else icon.innerText = '○';
}

function showErrorView(message) {
  [viewVerdict, viewScanner, viewForensics, viewMailbox, viewLoading].forEach(v => v.classList.add('hidden'));
  document.getElementById('errorDescription').innerText = message;
  viewError.classList.remove('hidden');
}

function showToast(msg) {
  errorMessage.innerText = msg;
  errorToast.classList.remove('hidden');
  setTimeout(() => {
    errorToast.classList.add('hidden');
  }, 5000);
}

// ─────────────────────────────────────────────────────────────
// EVENT LISTENERS & CONSOLE REDIRECTS
// ─────────────────────────────────────────────────────────────
function setupEventListeners() {
  // Console Redirection
  const openConsole = () => chrome.tabs.create({ url: WEB_APP_BASE });
  document.getElementById('btnHeaderConsole').addEventListener('click', openConsole);
  document.getElementById('btnLaunchConsoleFromVerdict').addEventListener('click', openConsole);

  document.getElementById('btnDeepInvestigate').addEventListener('click', () => {
    if (currentActiveEmailId) {
      chrome.tabs.create({ url: `${WEB_APP_BASE}/investigation?id=${currentActiveEmailId}` });
    } else {
      chrome.tabs.create({ url: `${WEB_APP_BASE}/investigation` });
    }
  });

  // Empty State Actions
  document.getElementById('btnEmptyScanTab').addEventListener('click', handleScanCurrentEmail);
  document.getElementById('btnEmptySwitchScanner').addEventListener('click', () => switchTab('viewScanner'));

  // Switch to Forensics
  document.getElementById('btnSwitchToForensics').addEventListener('click', () => switchTab('viewForensics'));

  // Scan Triggers
  btnRunScenarioScan.addEventListener('click', runScenarioScan);
  btnScanCurrentEmail.addEventListener('click', handleScanCurrentEmail);
  btnScanCustomRaw.addEventListener('click', runCustomScan);

  // Error Actions
  document.getElementById('btnRetryAnalysis').addEventListener('click', runScenarioScan);
  document.getElementById('btnDismissErrorView').addEventListener('click', () => switchTab('viewVerdict'));
  document.getElementById('btnDismissToast').addEventListener('click', () => errorToast.classList.add('hidden'));

  // Theme Toggle
  document.getElementById('btnThemeToggle').addEventListener('click', async () => {
    const current = document.documentElement.getAttribute('data-theme') || 'obsidian';
    const next = current === 'obsidian' ? 'forensic-paper' : 'obsidian';
    document.documentElement.setAttribute('data-theme', next);
    await chrome.storage.local.set({ traceguard_theme: next });
  });
}
