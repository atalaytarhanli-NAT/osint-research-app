window.app = (function () {
  async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    const res = await fetch(path, { credentials: 'include', headers, ...opts });
    if (res.status === 204) return null;
    let data;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
      const err = new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
      err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  }

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
    window.location.href = '/login';
  }

  return { api, logout };
})();
