const BASE_URL = '/api/v1';

export async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
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

  return res.json();
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
    return res.json();
  }
};
