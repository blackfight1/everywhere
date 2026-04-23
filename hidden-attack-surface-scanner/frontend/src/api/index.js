const BASE = '';

async function request(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(`${BASE}${path}`, { ...options, headers });
    if (!res.ok) {
        const raw = await res.text();
        let msg = `Request failed: ${res.status}`;
        try {
            const parsed = JSON.parse(raw);
            msg = parsed.error || msg;
        } catch { /* ignore */ }
        throw new Error(msg);
    }

    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
}

export const api = {
    // Stats
    getStats: () => request('/api/stats'),

    // Scans
    listScans: () => request('/api/scans'),
    getScan: (id) => request(`/api/scan/${id}`),
    createScan: (data) => request('/api/scan', { method: 'POST', body: JSON.stringify(data) }),
    stopScan: (id) => request(`/api/scan/${id}/stop`, { method: 'POST' }),
    deleteScan: (id) => request(`/api/scan/${id}`, { method: 'DELETE' }),
    getScanResults: (id) => request(`/api/scan/${id}/results`),

    // Payloads
    listPayloads: () => request('/api/payloads'),
    updatePayloads: (data) => request('/api/payloads', { method: 'PUT', body: JSON.stringify(data) }),
    updatePayload: (id, data) => request(`/api/payloads/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    importPayloads: (file) => {
        const body = new FormData();
        body.append('file', file);
        return request('/api/payloads/import', { method: 'POST', body });
    },
    exportPayloads: () => window.open('/api/payloads/export', '_blank', 'noopener'),

    // Pingbacks
    listPingbacks: (params = {}) => {
        const qs = new URLSearchParams();
        Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, v); });
        const q = qs.toString();
        return request(`/api/pingbacks${q ? '?' + q : ''}`);
    },
    getPingback: (id) => request(`/api/pingbacks/${id}`),

    // Settings
    getSettings: () => request('/api/settings'),
    updateSettings: (data) => request('/api/settings', { method: 'PUT', body: JSON.stringify(data) }),
    testNotification: (data) => request('/api/settings/notification/test', { method: 'POST', body: JSON.stringify(data) }),
};
