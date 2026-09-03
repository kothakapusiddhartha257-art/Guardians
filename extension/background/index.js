/**
 * TRACEGUARD AI - Service Worker Entry & Message Router (MV3)
 */

import { MESSAGE_TYPES } from '../shared/messages.js';
import { connectGmail, clearAuth, getAuthStatus } from './auth.js';
import { runInboxScan, scanSingleMessage } from './scanOrchestrator.js';
import { ingestEml } from './ingestClient.js';
import { getRecentScans, saveRecentScan } from './storage.js';

// Port-based long-lived connections for real-time progress streaming
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'scan-inbox' || port.name === 'traceguard-inbox-scan') {
    port.onMessage.addListener(async (msg) => {
      if (msg.type === MESSAGE_TYPES.SCAN_INBOX || msg.type === 'START_INBOX_SCAN') {
        try {
          await runInboxScan(
            {
              count: msg.count || (msg.options && msg.options.count) || 20,
              query: msg.query || (msg.options && msg.options.query) || 'in:inbox'
            },
            port
          );
        } catch (err) {
          port.postMessage({
            type: MESSAGE_TYPES.SCAN_ERROR,
            error: err.message || 'Inbox scan failed.'
          });
        }
      }
    });
  }
});

// Single message request/response router
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const router = async () => {
    try {
      switch (message.type) {
        case MESSAGE_TYPES.AUTH_STATUS:
          return await getAuthStatus();

        case MESSAGE_TYPES.AUTH_CONNECT:
          return await connectGmail();

        case MESSAGE_TYPES.AUTH_DISCONNECT:
          return await clearAuth();

        case MESSAGE_TYPES.SCAN_MESSAGE:
          return await scanSingleMessage(message.gmailMessageId);

        case MESSAGE_TYPES.INGEST_RAW_EML:
          return await ingestEml({
            rawEmlBase64: message.rawBase64,
            rawMime: message.rawMime,
            gmailMessageId: message.messageId || ''
          });

        case MESSAGE_TYPES.GET_RECENT_SCANS: {
          const recent = await getRecentScans();
          return { recent_scans: recent };
        }

        case MESSAGE_TYPES.SAVE_RECENT_SCAN: {
          const updated = await saveRecentScan(message.record);
          return { status: 'success', recent_scans: updated };
        }

        default:
          return { error: `Unrecognized message type: ${message.type}` };
      }
    } catch (err) {
      console.error(`[TRACEGUARD Router] Error handling ${message.type}:`, err);
      return { error: err.message || 'Internal background worker error' };
    }
  };

  router().then(sendResponse);
  return true; // Keep channel open for async response
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[TRACEGUARD AI] MV3 Service Worker ready and operational.');
});
