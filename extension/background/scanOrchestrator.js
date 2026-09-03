/**
 * TRACEGUARD AI - Scan Orchestrator
 * Coordinates batch inbox scans, streaming progress, and individual message inspection.
 */

import { listMessages, getRawMessage } from './gmailClient.js';
import { ingestEml } from './ingestClient.js';
import { decodeRawToText } from '../shared/eml.js';
import { MAX_CONCURRENT_GMAIL_FETCH } from '../shared/constants.js';

export async function runInboxScan({ count = 20, query = 'in:inbox' }, port = null) {
  const ids = await listMessages({ query, maxResults: count });
  const results = [];
  const failures = [];
  let done = 0;

  if (ids.length === 0) {
    const emptySummary = { total: 0, critical: 0, suspicious: 0, safe: 0, failedCount: 0 };
    if (port) port.postMessage({ type: 'SCAN_COMPLETE', results: [], summary: emptySummary });
    return { results: [], summary: emptySummary };
  }

  const chunks = [];
  for (let i = 0; i < ids.length; i += MAX_CONCURRENT_GMAIL_FETCH) {
    chunks.push(ids.slice(i, i + MAX_CONCURRENT_GMAIL_FETCH));
  }

  for (const chunk of chunks) {
    await Promise.all(
      chunk.map(async (id) => {
        try {
          if (port) {
            port.postMessage({
              type: 'SCAN_PROGRESS',
              done,
              total: ids.length,
              currentSubject: `Fetching RFC822 Source (${id})`,
              stage: 'Gmail API Extraction'
            });
          }

          const raw = await getRawMessage(id);

          if (port) {
            port.postMessage({
              type: 'SCAN_PROGRESS',
              done,
              total: ids.length,
              currentSubject: raw.snippet || `Message: ${id}`,
              stage: 'Running 11-Lens Forensic DAG Pipeline'
            });
          }

          const bundle = await ingestEml({
            rawEmlBase64: raw.rawBase64Url,
            gmailMessageId: id
          });

          results.push(bundle);

          if (port) {
            port.postMessage({
              type: 'SCAN_RESULT',
              result: bundle
            });
          }
        } catch (err) {
          console.warn(`[TRACEGUARD Orchestrator] Error on message ${id}:`, err);
          failures.push({ messageId: id, error: err.message });
          if (port) {
            port.postMessage({
              type: 'SCAN_ERROR',
              messageId: id,
              error: err.message
            });
          }
        } finally {
          done += 1;
          if (port) {
            port.postMessage({
              type: 'SCAN_PROGRESS',
              done,
              total: ids.length,
              currentSubject: `Completed ${done} of ${ids.length}`,
              stage: 'Analysis Complete'
            });
          }
        }
      })
    );
  }

  const summary = {
    total: results.length,
    critical: results.filter(r => (r.threat_score || 0) >= 0.75).length,
    suspicious: results.filter(r => (r.threat_score || 0) >= 0.35 && (r.threat_score || 0) < 0.75).length,
    safe: results.filter(r => (r.threat_score || 0) < 0.35).length,
    failedCount: failures.length
  };

  if (port) {
    port.postMessage({
      type: 'SCAN_COMPLETE',
      results,
      summary,
      failures
    });
  }

  return { results, summary, failures };
}

export async function scanSingleMessage(gmailMessageId) {
  const raw = await getRawMessage(gmailMessageId);
  return await ingestEml({
    rawEmlBase64: raw.rawBase64Url,
    gmailMessageId
  });
}
