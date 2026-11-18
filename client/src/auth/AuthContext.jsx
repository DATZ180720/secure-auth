import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, refreshSession, setAccessToken, setSessionExpiredHandler } from './api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  const startSession = useCallback((data) => {
    setAccessToken(data.accessToken);
    setUser(data.user);
  }, []);

  // On page load, try to restore the session from the refresh cookie.
  useEffect(() => {
    setSessionExpiredHandler(() => setUser(null));
    refreshSession()
      .then((data) => setUser(data.user))
      .catch(() => setUser(null))
      .finally(() => setReady(true));
  }, []);

  const value = useMemo(
    () => ({
      user,
      ready,
      login: async (credentials) => startSession(await api.login(credentials)),
      register: async (data) => startSession(await api.register(data)),
      changePassword: async (data) => startSession(await api.changePassword(data)),
      logout: async (everywhere = false) => {
        try {
          await (everywhere ? api.logoutAll() : api.logout());
        } finally {
          setAccessToken(null);
          setUser(null);
        }
      },
    }),
    [user, ready, startSession],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
