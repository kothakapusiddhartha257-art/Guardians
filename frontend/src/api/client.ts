import {
  MOCK_DASHBOARD_SUMMARY,
  MOCK_DASHBOARD_TREND,
  MOCK_RECENT_THREATS,
  MOCK_INVESTIGATION_BUNDLE,
  MOCK_CASES,
  MOCK_CAMPAIGNS
} from './mockData';

const BASE_URL = '/api/v1';

// Set to true only when you explicitly want demo/offline fallback behavior.
// Real integration should keep this false so failures are visible.
const DEMO_FALLBACK_ENABLED = false;

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('access_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Accept': 'application/json',
        ...getAuthHeaders(),
        ...options?.headers
      }
    });

    if (res.status === 401) {
      // Token invalid/expired — clear it so AuthContext can react on next check
      localStorage.removeItem('access_token');
      throw new Error('API Error 401: Unauthorized');
    }

    if (!res.ok) {
      const errorText = await res.text().catch(() => '');
      throw new Error(`API Error ${res.status}: ${errorText || res.statusText}`);
    }

    return await res.json();
  } catch (err) {
    if (DEMO_FALLBACK_ENABLED) {
      console.warn(`[API Client Notice] Using demo fallback for ${endpoint}:`, err);
      return getFallbackData<T>(endpoint);
    }
    // Re-throw so callers/UI can show real error states instead of masking failures.
    throw err;
  }
}

function getFallbackData<T>(endpoint: string): T {
  if (endpoint.includes('/dashboard/summary')) return MOCK_DASHBOARD_SUMMARY as unknown as T;
  if (endpoint.includes('/dashboard/trend')) return MOCK_DASHBOARD_TREND as unknown as T;
  if (endpoint.includes('/dashboard/recent')) return MOCK_RECENT_THREATS as unknown as T;
  if (endpoint.includes('/dashboard/monthly-breakdown')) {
    return { total: 59, by_category: { 'Phishing': 28, 'Malware': 14, 'BEC': 12, 'Clean': 5 } } as unknown as T;
  }
  if (endpoint.includes('/cases')) return MOCK_CASES as unknown as T;
  if (endpoint.includes('/campaigns')) return MOCK_CAMPAIGNS as unknown as T;
  if (endpoint.includes('/emails/live')) return MOCK_RECENT_THREATS as unknown as T;
  if (endpoint.includes('/emails')) return MOCK_INVESTIGATION_BUNDLE as unknown as T;
  if (endpoint.includes('/mailboxes')) return [] as unknown as T;
  return {} as unknown as T;
}

export const api = {
  // ---- Auth ----
  login: (username: string, password: string) =>
    fetchApi<{ access_token: string; token_type: string; username: string; role: string }>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    }),

  getCurrentUser: () => fetchApi<any>('/auth/me'),

  getSession: () => fetchApi<any>('/auth/session'),

  logout: () => fetchApi<any>('/auth/logout', { method: 'POST' }),

  // ---- Dashboard ----
  getDashboardSummary: () => fetchApi<any>('/dashboard/summary'),
  getDashboardTrend: () => fetchApi<any[]>('/dashboard/trend'),
  getRecentThreats: () => fetchApi<any[]>('/dashboard/recent'),

  // ---- Cases ----
  getCases: (status?: string, severity?: string, q?: string) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (q) params.append('q', q);
    return fetchApi<any[]>(`/cases?${params.toString()}`);
  },

  getCaseDetail: (caseId: string) => fetchApi<any>(`/cases/${caseId}`),

  updateCase: (caseId: string, data: any) =>
    fetchApi<any>(`/cases/${caseId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }),

  // ---- Emails / Investigation ----
  getEmailInvestigation: (emailId: string) => fetchApi<any>(`/emails/${emailId}`),
  getEmailSubgraph: (emailId: string) => fetchApi<any>(`/emails/${emailId}/graph`),

  uploadEmail: async (file?: File, rawContent?: string, caseId?: string) => {
    const formData = new FormData();
    if (file) formData.append('file', file);
    if (rawContent) formData.append('raw_content', rawContent);
    if (caseId) formData.append('case_id', caseId);

    const res = await fetch(`${BASE_URL}/emails`, {
      method: 'POST',
      headers: { ...getAuthHeaders() },
      body: formData
    });

    if (!res.ok) {
      const errorText = await res.text().catch(() => '');
      throw new Error(`Upload failed (${res.status}): ${errorText || res.statusText}`);
    }

    return await res.json();
  },

  // ---- Mailboxes ----
  getMailboxes: () => fetchApi<any[]>('/mailboxes'),

  // ---- Campaigns ----
  getCampaigns: () => fetchApi<any[]>('/campaigns')
};

// ---- WebSocket helpers ----

export function openLiveFeedSocket(
  onMessage: (data: any) => void,
  onError?: (e: Event) => void
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${protocol}://${window.location.host}/ws/live-feed`);
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {
      // ignore malformed frame
    }
  };
  if (onError) ws.onerror = onError;
  return ws;
}

export function openEmailStatusSocket(
  emailId: string,
  onMessage: (data: any) => void,
  onError?: (e: Event) => void
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${protocol}://${window.location.host}/ws/emails/${emailId}`);
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {
      // ignore malformed frame
    }
  };
  if (onError) ws.onerror = onError;
  return ws;
}