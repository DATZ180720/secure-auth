import { hashPassword, verifyPassword, burnVerifyTime } from './passwords.js';

export class UserService {
  constructor(db, config) {
    this.db = db;
    this.config = config;
  }

  findByEmail(email) {
    return this.db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  }

  findById(id) {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  }

  async create({ email, name, password }) {
    if (this.findByEmail(email)) return null;
    const now = Date.now();
    const passwordHash = await hashPassword(password);
    const { lastInsertRowid } = this.db
      .prepare('INSERT INTO users (email, name, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .run(email, name, passwordHash, now, now);
    return this.findById(lastInsertRowid);
  }

  /**
   * Returns { user } on success or { error } with a reason that is only used
   * internally (the API always answers with the same generic message).
   */
  async authenticate(email, password) {
    const user = this.findByEmail(email);
    if (!user) {
      await burnVerifyTime(password);
      return { error: 'invalid_credentials' };
    }

    if (user.locked_until && user.locked_until > Date.now()) {
      return { error: 'locked', user };
    }

    if (!(await verifyPassword(user.password_hash, password))) {
      const failed = user.failed_logins + 1;
      const lock = failed >= this.config.MAX_FAILED_LOGINS;
      this.db
        .prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?')
        .run(lock ? 0 : failed, lock ? Date.now() + this.config.LOCKOUT_MINUTES * 60_000 : null, user.id);
      return { error: lock ? 'locked' : 'invalid_credentials', user };
    }

    this.db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(user.id);
    return { user };
  }

  async changePassword(user, currentPassword, newPassword) {
    if (!(await verifyPassword(user.password_hash, currentPassword))) return false;
    // Bumping token_version invalidates every access token already issued.
    this.db
      .prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1, updated_at = ? WHERE id = ?')
      .run(await hashPassword(newPassword), Date.now(), user.id);
    return true;
  }

  audit(userId, event, ip) {
    this.db.prepare('INSERT INTO audit_log (user_id, event, ip, created_at) VALUES (?, ?, ?, ?)').run(userId ?? null, event, ip ?? null, Date.now());
  }
}

/** Only these fields ever leave the server. */
export const toPublicUser = (u) => ({ id: u.id, email: u.email, name: u.name, createdAt: new Date(u.created_at).toISOString() });
