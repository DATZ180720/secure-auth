# Secure Auth

A full-stack authentication system (**Node.js / Express** API + **React** client) built around security best practices from OWASP and NIST SP 800-63B.

## Security features

| Area | What it does |
|------|--------------|
| **Password hashing** | Argon2id with OWASP-recommended parameters (19 MiB, 2 iterations) |
| **Password policy** | Min 10 / max 128 chars, letters + numbers, common-password blocklist (NIST-style: length over complexity rules) |
| **Access tokens** | Short-lived JWT (15 min), algorithm pinned to HS256, issuer/audience checked. Stored **only in memory** on the client |
| **Refresh tokens** | Opaque random 384-bit values in an `httpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/api/auth`. Stored **hashed** (SHA-256) in the database |
| **Token rotation** | Every refresh issues a new token and revokes the old one |
| **Reuse detection** | Replaying an already-used refresh token revokes the whole session family (stolen-token defence) |
| **Brute-force protection** | Per-IP rate limiting + per-account lockout after N failed logins |
| **User enumeration** | Same error and similar timing for "unknown email" and "wrong password" (dummy hash verification) |
| **CSRF** | SameSite=Strict cookies + required custom header on cookie-authenticated endpoints |
| **Session invalidation** | Changing the password bumps a `token_version` that kills all existing access tokens and revokes refresh tokens |
| **Headers** | Helmet (CSP, HSTS, nosniff, frame protection), `x-powered-by` removed, strict CORS origin |
| **Input** | Zod validation on every body, 10 kB body limit, parameterized SQL only |
| **Config** | Env vars validated at startup; the server won't start with a weak JWT secret |
| **Audit log** | Logins, failures, lockouts, password changes and token reuse are recorded |
| **Errors** | Generic error responses, no stack traces leaked |

## Tech stack

- **API:** Node.js 20+, Express 5, better-sqlite3, @node-rs/argon2, jsonwebtoken, Zod, Helmet, express-rate-limit
- **Client:** React 18, React Router, Vite
- **Tests:** node:test + Supertest (12 tests covering the security flows)

## Getting started

```bash
# API
cd server
npm install
cp .env.example .env      # then set a real JWT_ACCESS_SECRET
npm run dev               # http://localhost:4000

# Client (another terminal)
cd client
npm install
npm run dev               # http://localhost:5173
```

Generate a secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Run the tests:

```bash
cd server
npm test
```

## API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | – | Create account, starts a session |
| POST | `/api/auth/login` | – | Returns access token + sets refresh cookie |
| POST | `/api/auth/refresh` | cookie + `X-Requested-With` | Rotates refresh token, returns new access token |
| POST | `/api/auth/logout` | cookie + `X-Requested-With` | Revokes current session |
| POST | `/api/auth/logout-all` | Bearer | Revokes every session of the user |
| GET | `/api/auth/me` | Bearer | Current user |
| GET | `/api/auth/sessions` | Bearer | Active sessions (devices) |
| POST | `/api/auth/change-password` | Bearer | Changes password, signs out other devices |

## How the token flow works

```
Login ──► access token (memory, 15 min) + refresh cookie (httpOnly, 7 days)
          │
API call ─┤ Authorization: Bearer <access>
          │
401 ──────► POST /refresh (cookie) ──► new access + NEW refresh cookie
                                       old refresh token is revoked
Old refresh token used again? ──► whole session family revoked → user must log in
```

## Project structure

```
server/src/
├── app.js              # middleware stack (helmet, cors, limits, routes)
├── config.js           # validated env configuration
├── db.js               # SQLite schema
├── middleware.js       # requireAuth, CSRF check, rate limiters, error handler
├── validation.js       # Zod schemas + password policy
├── routes/auth.js
└── services/
    ├── passwords.js    # Argon2id hashing
    ├── tokens.js       # JWT + refresh token rotation
    └── users.js        # accounts, lockout, audit log
client/src/
├── auth/api.js         # fetch wrapper with automatic token refresh
├── auth/AuthContext.jsx
└── pages/              # Login, Register, Account
```

## Trade-offs and next steps

- `register` returns `409` for an existing email, which reveals that the account exists. A stricter flow would always answer "check your inbox" and use email verification.
- Next steps: email verification, password reset by email, TOTP two-factor authentication, PostgreSQL + Redis for rate limiting across instances.
