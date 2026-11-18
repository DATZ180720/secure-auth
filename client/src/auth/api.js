/**
 * API client.
 * - The access token lives only in memory (never localStorage), so an XSS
 *   bug can't read it from storage.
 * - The refresh token is an httpOnly cookie the browser sends automatically.
 * - On a 401 the client refreshes once and retries; concurrent requests
 *   share a single refresh call.
 */
let accessToken = null;
let refreshPromise = null;
let onSessionExpired = () => {};

export const setAccessToken = (token) => {
  accessToken = token;
};
export const setSessionExpiredHandler = (fn) => {
  onSessionExpired = fn;
};

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message ?? body?.details?.[0]?.message ?? body?.error ?? 'Request failed');
    this.status = status;
    this.body = body;
  }
}

async function raw(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'X-Requested-With': 'XMLHttpRequest' };
  if (body) headers['Content-Type'] = 'application/json';
  if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const res = await fetch(`/api/auth${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

export function refreshSession() {
  refreshPromise ??= raw('/refresh', { method: 'POST', auth: false })
    .then((data) => {
      setAccessToken(data.accessToken);
      return data;
    })
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
}

async function authed(path, options) {
  try {
    return await raw(path, options);
  } catch (err) {
    if (err.status !== 401) throw err;
    try {
      await refreshSession();
    } catch {
      setAccessToken(null);
      onSessionExpired();
      throw err;
    }
    return raw(path, options);
  }
}

export const api = {
  register: (data) => raw('/register', { method: 'POST', body: data, auth: false }),
  login: (data) => raw('/login', { method: 'POST', body: data, auth: false }),
  logout: () => raw('/logout', { method: 'POST', auth: false }),
  logoutAll: () => authed('/logout-all', { method: 'POST' }),
  me: () => authed('/me'),
  sessions: () => authed('/sessions'),
  changePassword: (data) => authed('/change-password', { method: 'POST', body: data }),
};
