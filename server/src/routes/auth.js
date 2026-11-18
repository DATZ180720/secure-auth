import { Router } from 'express';
import { validate, registerSchema, loginSchema, changePasswordSchema } from '../validation.js';
import { requireAuth, requireCsrfHeader } from '../middleware.js';
import { toPublicUser } from '../services/users.js';

export const REFRESH_COOKIE = 'refresh_token';

export function authRouter({ users, tokens, config, limiters }) {
  const router = Router();
  const auth = requireAuth({ users, tokens });

  const cookieOptions = {
    httpOnly: true, // not readable from JavaScript → safe from XSS token theft
    secure: config.isProduction, // HTTPS only in production
    sameSite: 'strict',
    path: '/api/auth', // only sent to the auth endpoints
    maxAge: config.REFRESH_TOKEN_TTL_DAYS * 86_400_000,
  };

  const startSession = (res, user, req) => {
    const refresh = tokens.issueRefreshToken(user.id, { userAgent: req.get('user-agent')?.slice(0, 200) });
    res.cookie(REFRESH_COOKIE, refresh, cookieOptions);
    return { accessToken: tokens.signAccessToken(user), expiresIn: config.ACCESS_TOKEN_TTL_SECONDS, user: toPublicUser(user) };
  };

  router.post('/register', limiters.auth, validate(registerSchema), async (req, res) => {
    const user = await users.create(req.body);
    if (!user) return res.status(409).json({ error: 'email_in_use' });
    users.audit(user.id, 'register', req.ip);
    res.status(201).json(startSession(res, user, req));
  });

  router.post('/login', limiters.auth, validate(loginSchema), async (req, res) => {
    const { user, error } = await users.authenticate(req.body.email, req.body.password);
    if (error) {
      users.audit(user?.id, `login_failed:${error}`, req.ip);
      // Same message for "no such user" and "wrong password" (no enumeration).
      if (error === 'locked') {
        return res.status(423).json({ error: 'account_locked', message: `Too many failed attempts. Try again in ${config.LOCKOUT_MINUTES} minutes.` });
      }
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
    }
    users.audit(user.id, 'login', req.ip);
    res.json(startSession(res, user, req));
  });

  router.post('/refresh', requireCsrfHeader, (req, res) => {
    const result = tokens.rotate(req.cookies[REFRESH_COOKIE], req.get('user-agent')?.slice(0, 200));
    if (!result.ok) {
      if (result.reason === 'reuse_detected') users.audit(result.userId, 'refresh_token_reuse', req.ip);
      res.clearCookie(REFRESH_COOKIE, { ...cookieOptions, maxAge: undefined });
      return res.status(401).json({ error: 'invalid_refresh_token' });
    }
    const user = users.findById(result.userId);
    res.cookie(REFRESH_COOKIE, result.token, cookieOptions);
    res.json({ accessToken: tokens.signAccessToken(user), expiresIn: config.ACCESS_TOKEN_TTL_SECONDS, user: toPublicUser(user) });
  });

  router.post('/logout', requireCsrfHeader, (req, res) => {
    tokens.revoke(req.cookies[REFRESH_COOKIE]);
    res.clearCookie(REFRESH_COOKIE, { ...cookieOptions, maxAge: undefined });
    res.status(204).end();
  });

  router.post('/logout-all', auth, (req, res) => {
    tokens.revokeAllForUser(req.user.id);
    users.audit(req.user.id, 'logout_all', req.ip);
    res.clearCookie(REFRESH_COOKIE, { ...cookieOptions, maxAge: undefined });
    res.status(204).end();
  });

  router.get('/me', auth, (req, res) => res.json({ user: toPublicUser(req.user) }));

  router.get('/sessions', auth, (req, res) => res.json({ sessions: tokens.activeSessions(req.user.id) }));

  router.post('/change-password', auth, validate(changePasswordSchema), async (req, res) => {
    const ok = await users.changePassword(req.user, req.body.currentPassword, req.body.newPassword);
    if (!ok) return res.status(400).json({ error: 'invalid_current_password' });
    tokens.revokeAllForUser(req.user.id); // sign out every other device
    users.audit(req.user.id, 'password_changed', req.ip);
    res.json(startSession(res, users.findById(req.user.id), req));
  });

  return router;
}
