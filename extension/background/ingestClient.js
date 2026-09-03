/**
 * TRACEGUARD AI - Ingestion Client
 * Forwards RFC822 EML bytes to TRACEGUARD 11-Lens Forensic DAG Engine.
 */

import { ENDPOINTS } from '../shared/constants.js';
import { saveRecentScan } from './storage.js';

export async function ingestEml({ rawEmlBase64, rawMime, gmailMessageId, caseId = null }) {
  let payload = {};

  if (rawEmlBase64) {
    // Standardize Base64
    let cleanB64 = rawEmlBase64.replace(/-/g, '+').replace(/_/g, '/');
    while (cleanB64.length % 4) {
      cleanB64 += '=';
    }
    payload.raw_eml_base64 = cleanB64;
  } else if (rawMime) {
    payload.raw_mime = rawMime;
  } else {
    throw new Error('Must provide either raw_eml_base64 or raw_mime payload');
  }

  payload.gmail_message_id = gmailMessageId || '';
  if (caseId) payload.case_id = caseId;

  const res = await fetch(ENDPOINTS.ingestEml, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `TRACEGUARD Ingestion failed with status ${res.status}`);
  }

  const bundle = await res.json();

  // Save to Rolling Recent Scans History (50 items)
  await saveRecentScan({
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
