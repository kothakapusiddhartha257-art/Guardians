/**
 * TRACEGUARD AI - Storage Manager
 * Enforces session vs local storage separation and rolling 50-scan history.
 */

import { MAX_HISTORY_ENTRIES } from '../shared/constants.js';

export async function getSessionTokens() {
  return await chrome.storage.session.get([
    'google_access_token',
    'traceguard_session_token',
    'expires_at'
  ]);
}

export async function setSessionTokens({ googleAccessToken, traceguardToken, expiresIn = 3600 }) {
  const expiresAt = Date.now() + (expiresIn * 1000);
  await chrome.storage.session.set({
    google_access_token: googleAccessToken,
    traceguard_session_token: traceguardToken,
    expires_at: expiresAt
  });
}

export async function clearSessionTokens() {
  await chrome.storage.session.remove([
    'google_access_token',
    'traceguard_session_token',
    'expires_at'
  ]);
}

export async function getLocalAuthState() {
  return await chrome.storage.local.get(['connected', 'user_email', 'connected_at']);
}

export async function setLocalAuthState({ connected, userEmail }) {
  await chrome.storage.local.set({
    connected: !!connected,
    user_email: userEmail || null,
    connected_at: connected ? new Date().toISOString() : null
  });
}

export async function getRecentScans() {
  const { recent_scans = [] } = await chrome.storage.local.get('recent_scans');
  return recent_scans;
}

export async function saveRecentScan(record) {
  const scans = await getRecentScans();
  const idToMatch = record.email_id || record.emailId || record.messageId;
  const filtered = scans.filter(s => (s.email_id || s.emailId || s.messageId) !== idToMatch);
  const updated = [record, ...filtered].slice(0, MAX_HISTORY_ENTRIES);
  await chrome.storage.local.set({ recent_scans: updated });
  return updated;
}
