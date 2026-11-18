import rateLimit from 'express-rate-limit';

/** Requires a valid "Authorization: Bearer <access token>" header. */
export const requireAuth = ({ tokens, users }) => (req, res, next) => {
  const header = req.get('authorization') ?? '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const payload = tokens.verifyAccessToken(token);
    const user = users.findById(Number(payload.sub));
    // token_version changes on password change → old tokens stop working.
    if (!user || user.token_version !== payload.ver) return res.status(401).json({ error: 'unauthorized' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
};

/**
 * CSRF defence for cookie-authenticated endpoints (refresh/logout).
 * Besides SameSite=Strict cookies, we require a custom header: browsers
 * don't let cross-site forms set custom headers, and CORS blocks it for
 * other origins.
 */
export const requireCsrfHeader = (req, res, next) => {
  if (req.get('x-requested-with') !== 'XMLHttpRequest') return res.status(403).json({ error: 'csrf_check_failed' });
  next();
};

export const createLimiters = (config) => {
  const enabled = config.NODE_ENV !== 'test';
  const make = (windowMs, limit) =>
    rateLimit({
      windowMs,
      limit,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      skip: () => !enabled,
      message: { error: 'too_many_requests' },
    });
  return {
    auth: make(15 * 60_000, 20), // login/register: 20 per 15 min per IP
    api: make(60_000, 120),
  };
};

// eslint-disable-next-line no-unused-vars
export const errorHandler = (err, req, res, _next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json' });
  console.error(err);
  // Never leak stack traces or internal messages to the client.
  res.status(500).json({ error: 'internal_error' });
};
