import jwt from 'jsonwebtoken';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

const ISSUER = 'secure-auth';
const AUDIENCE = 'secure-auth-client';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export class TokenService {
  constructor(db, config) {
    this.db = db;
    this.config = config;
  }

  // ---- Access tokens: short-lived JWT, kept in memory by the client ----

  signAccessToken(user) {
    return jwt.sign({ ver: user.token_version }, this.config.JWT_ACCESS_SECRET, {
      subject: String(user.id),
      expiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    });
  }

  verifyAccessToken(token) {
    // Pinning the algorithm prevents "alg: none" / algorithm-confusion attacks.
    return jwt.verify(token, this.config.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
  }

  // ---- Refresh tokens: opaque random values, stored hashed, rotated ----

  issueRefreshToken(userId, { familyId = randomUUID(), userAgent = null } = {}) {
    const token = randomBytes(48).toString('base64url');
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, created_at, user_agent)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(userId, sha256(token), familyId, now + this.config.REFRESH_TOKEN_TTL_DAYS * 86_400_000, now, userAgent);
    return token;
  }

  /**
   * Exchanges a refresh token for a new one (rotation).
   * If a token that was already used is presented again, someone may have
   * stolen it: the whole token family is revoked and the user must log in again.
   */
  rotate(token, userAgent) {
    const row = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(sha256(token ?? ''));
    if (!row) return { ok: false, reason: 'invalid' };

    if (row.revoked_at) {
      this.revokeFamily(row.family_id);
      return { ok: false, reason: 'reuse_detected', userId: row.user_id };
    }
    if (row.expires_at < Date.now()) return { ok: false, reason: 'expired' };

    const newToken = this.issueRefreshToken(row.user_id, { familyId: row.family_id, userAgent });
    this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ?, replaced_by = ? WHERE id = ?')
      .run(Date.now(), sha256(newToken), row.id);
    return { ok: true, userId: row.user_id, token: newToken };
  }

  revoke(token) {
    this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .run(Date.now(), sha256(token ?? ''));
  }

  revokeFamily(familyId) {
    this.db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(Date.now(), familyId);
  }

  revokeAllForUser(userId) {
    this.db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(Date.now(), userId);
  }

  activeSessions(userId) {
    return this.db
      .prepare(
        `SELECT family_id AS id, MIN(created_at) AS createdAt, MAX(user_agent) AS userAgent
         FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         GROUP BY family_id ORDER BY createdAt DESC`,
      )
      .all(userId, Date.now());
  }
}
