/**
 * TRACEGUARD AI - Shared Constants & Configurations
 */

export const GMAIL_SCOPE_METADATA = 'https://www.googleapis.com/auth/gmail.metadata';
export const GMAIL_SCOPE_READONLY = 'https://www.googleapis.com/auth/gmail.readonly';
export const GMAIL_SCOPE_USERINFO = 'https://www.googleapis.com/auth/userinfo.email';

export const BACKEND_BASE = 'http://127.0.0.1:8000/api/v1';
export const WEB_APP_BASE = 'http://127.0.0.1:5173';

export const ENDPOINTS = {
  oauthExchange: `${BACKEND_BASE}/oauth/gmail/exchange`,
  oauthRefresh: `${BACKEND_BASE}/oauth/gmail/refresh`,
  oauthStatus: `${BACKEND_BASE}/oauth/gmail/status`,
  oauthAuthUrl: `${BACKEND_BASE}/oauth/gmail/auth-url`,
  ingestEml: `${BACKEND_BASE}/emails/ingest`,
  ingestEmlAlias: `${BACKEND_BASE}/ingest/eml`,
  investigationRoute: (id) => `${WEB_APP_BASE}/investigation?id=${id}`,
  monitoringRoute: `${WEB_APP_BASE}/monitoring`,
};

export const DEFAULT_SCAN_COUNT = 20;
export const MAX_CONCURRENT_GMAIL_FETCH = 5;
export const POLL_BACKOFF_MS = [1000, 2000, 4000, 8000, 10000];
export const JOB_TIMEOUT_MS = 90000;
export const MAX_HISTORY_ENTRIES = 50;

export const VIEW_STATES = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED_IDLE: 'connected',
  SCANNING: 'scanning',
  RESULTS: 'results',
  BATCH_SUMMARY: 'batchSummary',
  ERROR: 'error'
};
