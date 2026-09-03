/**
 * TRACEGUARD AI - OAuth Lifecycle Engine
 * Handles Google OAuth flow, backend code-exchange, and token auto-refresh.
 */

import { ENDPOINTS, GMAIL_SCOPE_READONLY, GMAIL_SCOPE_USERINFO } from '../shared/constants.js';
import {
  getSessionTokens,
  setSessionTokens,
  clearSessionTokens,
  getLocalAuthState,
  setLocalAuthState
} from './storage.js';

export async function getValidGoogleToken(forceRefresh = false) {
  if (!forceRefresh) {
    const session = await getSessionTokens();
    if (session.google_access_token && session.expires_at && Date.now() < session.expires_at - 60000) {
      return session.google_access_token;
    }
  }

  // Attempt backend refresh
  try {
    const res = await fetch(ENDPOINTS.oauthRefresh, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    if (res.ok) {
      const data = await res.json();
      await setSessionTokens({
        googleAccessToken: data.access_token,
        traceguardToken: data.session_token || 'tg_session_active',
        expiresIn: data.expires_in || 3600
      });
      await setLocalAuthState({ connected: true, userEmail: data.user_email });
      return data.access_token;
    }
  } catch (err) {
    console.warn('[TRACEGUARD Auth] Silent token refresh failed:', err);
  }

  return null;
}

export async function connectGmail() {
  try {
    const redirectUri = chrome.identity.getRedirectURL('oauth2');
    const authUrlRes = await fetch(`${ENDPOINTS.oauthAuthUrl}?redirect_uri=${encodeURIComponent(redirectUri)}`);
    
    if (!authUrlRes.ok) {
      throw new Error(`Failed to initialize Google OAuth URL: ${authUrlRes.statusText}`);
    }

    const { auth_url } = await authUrlRes.json();

    const responseUrl = await new Promise((resolve, reject) => {
      chrome.identity.launchWebAuthFlow(
        { url: auth_url, interactive: true },
        (redirectUrl) => {
          if (chrome.runtime.lastError || !redirectUrl) {
            reject(new Error(chrome.runtime.lastError ? chrome.runtime.lastError.message : 'User cancelled OAuth flow'));
          } else {
            resolve(redirectUrl);
          }
        }
      );
    });

    const parsed = new URL(responseUrl);
    const code = parsed.searchParams.get('code');
    const error = parsed.searchParams.get('error');

    if (error) throw new Error(`Google OAuth error: ${error}`);
    if (!code) throw new Error('No authorization code returned from Google OAuth flow.');

    // Exchange with TRACEGUARD backend
    const exchangeRes = await fetch(ENDPOINTS.oauthExchange, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, redirect_uri: redirectUri })
    });

    if (!exchangeRes.ok) {
      const err = await exchangeRes.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to exchange authorization code with TRACEGUARD backend.');
    }

    const tokenData = await exchangeRes.json();
    const userEmail = tokenData.user_email || 'connected.user@gmail.com';

    await setSessionTokens({
      googleAccessToken: tokenData.access_token,
      traceguardToken: tokenData.session_token || 'tg_session_active',
      expiresIn: tokenData.expires_in || 3600
    });

    await setLocalAuthState({ connected: true, userEmail });

    return { status: 'connected', user_email: userEmail };
  } catch (err) {
    console.error('[TRACEGUARD Auth] Connect error:', err);
    throw err;
  }
}

export async function clearAuth() {
  await clearSessionTokens();
  await setLocalAuthState({ connected: false, userEmail: null });
  return { status: 'disconnected' };
}

export async function getAuthStatus() {
  const local = await getLocalAuthState();
  const token = await getValidGoogleToken();
  return {
    connected: !!token && !!local.connected,
    user_email: local.user_email || null
  };
}
