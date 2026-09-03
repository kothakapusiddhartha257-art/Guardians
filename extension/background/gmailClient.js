/**
 * TRACEGUARD AI - Gmail API Client
 * Lists and extracts raw RFC822 MIME bytes from Gmail REST endpoints with concurrency capping.
 */

import { MAX_CONCURRENT_GMAIL_FETCH } from '../shared/constants.js';
import { getValidGoogleToken } from './auth.js';

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';

export async function listMessages({ query = 'in:inbox', maxResults = 20 }) {
  const token = await getValidGoogleToken();
  if (!token) throw new Error('NOT_AUTHENTICATED');

  const url = `${GMAIL_BASE}/messages?maxResults=${maxResults}&q=${encodeURIComponent(query)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (res.status === 401) {
    const freshToken = await getValidGoogleToken(true);
    if (freshToken) return listMessages({ query, maxResults });
    throw new Error('UNAUTHORIZED');
  }

  if (!res.ok) {
    throw new Error(`Gmail API list failed (${res.status}): ${res.statusText}`);
  }

  const data = await res.json();
  return (data.messages || []).map(m => m.id);
}

export async function getRawMessage(messageId) {
  const token = await getValidGoogleToken();
  if (!token) throw new Error('NOT_AUTHENTICATED');

  const url = `${GMAIL_BASE}/messages/${messageId}?format=raw`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  });

  if (res.status === 401) {
    const freshToken = await getValidGoogleToken(true);
    if (freshToken) return getRawMessage(messageId);
    throw new Error('UNAUTHORIZED');
  }

  if (!res.ok) {
    throw new Error(`Gmail API get raw failed (${res.status}) for ${messageId}`);
  }

  const data = await res.json();
  return {
    id: messageId,
    rawBase64Url: data.raw,
    threadId: data.threadId,
    snippet: data.snippet
  };
}

export async function batchGetRaw(messageIds) {
  const results = [];
  const chunks = [];
  
  for (let i = 0; i < messageIds.length; i += MAX_CONCURRENT_GMAIL_FETCH) {
    chunks.push(messageIds.slice(i, i + MAX_CONCURRENT_GMAIL_FETCH));
  }

  for (const chunk of chunks) {
    const chunkResults = await Promise.all(
      chunk.map(id => getRawMessage(id).catch(err => {
        console.warn(`[TRACEGUARD GmailClient] Failed getting raw for ${id}:`, err);
        return null;
      }))
    );
    results.push(...chunkResults.filter(Boolean));
  }

  return results;
}
