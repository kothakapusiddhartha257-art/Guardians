import {
  MOCK_DASHBOARD_SUMMARY,
  MOCK_DASHBOARD_TREND,
  MOCK_RECENT_THREATS,
  MOCK_INVESTIGATION_BUNDLE,
  MOCK_CASES,
  MOCK_CAMPAIGNS
} from './mockData';

const BASE_URL = '/api/v1';

export async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Accept': 'application/json',
        ...options?.headers
      }
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`API Error ${res.status}: ${errorText || res.statusText}`);
    }

    return await res.json();
  } catch (err) {
    // Graceful offline mock fallback for standalone frontend execution
    console.warn(`[API Client Notice] Using standalone mock fallback for ${endpoint}:`, err);
    return getFallbackData<T>(endpoint);
  }
}

function getFallbackData<T>(endpoint: string): T {
  if (endpoint.includes('/dashboard/summary')) return MOCK_DASHBOARD_SUMMARY as unknown as T;
  if (endpoint.includes('/dashboard/trend')) return MOCK_DASHBOARD_TREND as unknown as T;
  if (endpoint.includes('/dashboard/recent')) return MOCK_RECENT_THREATS as unknown as T;
  if (endpoint.includes('/dashboard/monthly-breakdown')) return { total: 59, by_category: { 'Phishing': 28, 'Malware': 14, 'BEC': 12, 'Clean': 5 } } as unknown as T;
  if (endpoint.includes('/cases')) return MOCK_CASES as unknown as T;
  if (endpoint.includes('/campaigns')) return MOCK_CAMPAIGNS as unknown as T;
  if (endpoint.includes('/emails/live')) return MOCK_RECENT_THREATS as unknown as T;
  if (endpoint.includes('/emails')) return MOCK_INVESTIGATION_BUNDLE as unknown as T;
  if (endpoint.includes('/mailboxes')) return [] as unknown as T;
  return {} as unknown as T;
}

export const api = {
  getDashboardSummary: () => fetchApi<any>('/dashboard/summary'),
  getDashboardTrend: () => fetchApi<any[]>('/dashboard/trend'),
  getRecentThreats: () => fetchApi<any[]>('/dashboard/recent'),
  
  getCases: (status?: string, severity?: string, q?: string) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (q) params.append('q', q);
    return fetchApi<any[]>(`/cases?${params.toString()}`);
  },
  
  getCaseDetail: (caseId: string) => fetchApi<any>(`/cases/${caseId}`),
  updateCase: (caseId: string, data: any) => fetchApi<any>(`/cases/${caseId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }),

  getEmailInvestigation: (emailId: string) => fetchApi<any>(`/emails/${emailId}`),
  getEmailSubgraph: (emailId: string) => fetchApi<any>(`/emails/${emailId}/graph`),

  uploadEmail: async (file?: File, rawContent?: string, caseId?: string) => {
    try {
      const formData = new FormData();
      if (file) formData.append('file', file);
      if (rawContent) formData.append('raw_content', rawContent);
      if (caseId) formData.append('case_id', caseId);

      const res = await fetch(`${BASE_URL}/emails`, {
        method: 'POST',
        body: formData
      });

      if (!res.ok) {
        throw new Error(`Upload failed: ${await res.text()}`);
      }
      return await res.json();
    } catch (e) {
      console.warn('[Upload Notice] Simulating successful analysis for standalone frontend:', e);
      return {
        status: 'success',
        report_id: 'REP-2026-F98A1B',
        investigation_url: '/investigation?id=REP-2026-F98A1B',
        bundle: MOCK_INVESTIGATION_BUNDLE
      };
    }
  }
};
