import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_PATH: ':memory:',
  JWT_ACCESS_SECRET: 'test-secret-that-is-long-enough-for-hs256-123',
  MAX_FAILED_LOGINS: '3',
});

const USER = { email: 'Ana@Example.com', name: 'Ana', password: 'correct-horse-42' };
const CSRF = { 'X-Requested-With': 'XMLHttpRequest' };

let app;
beforeEach(() => {
  app = createApp(config).app;
});

const register = (body = USER) => request(app).post('/api/auth/register').send(body);
const login = (email = USER.email, password = USER.password) => request(app).post('/api/auth/login').send({ email, password });
const refreshCookie = (res) => res.headers['set-cookie'].find((c) => c.startsWith('refresh_token='));
const cookieValue = (cookie) => cookie.split(';')[0];

test('config refuses short JWT secrets', () => {
  assert.throws(() => loadConfig({ JWT_ACCESS_SECRET: 'short' }), /at least 32/);
});

test('register returns an access token and a hardened refresh cookie', async () => {
  const res = await register();
  assert.equal(res.status, 201);
  assert.ok(res.body.accessToken);
  assert.equal(res.body.user.email, 'ana@example.com'); // normalised
  assert.equal(res.body.user.password_hash, undefined); // never exposed
  const cookie = refreshCookie(res);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Path=\/api\/auth/);
});

test('register rejects weak passwords and duplicate emails', async () => {
  assert.equal((await register({ ...USER, password: 'short1' })).status, 400);
  assert.equal((await register({ ...USER, password: 'password123' })).status, 400);
  assert.equal((await register({ ...USER, password: 'onlyletterspassword' })).status, 400);
  await register();
  assert.equal((await register()).status, 409);
});

test('login gives the same error for unknown email and wrong password', async () => {
  await register();
  const unknown = await login('nobody@example.com', 'whatever-123');
  const wrong = await login(USER.email, 'wrong-password-1');
  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  assert.deepEqual(unknown.body, wrong.body);
});

test('account locks after too many failed logins', async () => {
  await register();
  for (let i = 0; i < 2; i++) assert.equal((await login(USER.email, 'bad-password-1')).status, 401);
  assert.equal((await login(USER.email, 'bad-password-1')).status, 423);
  // Even the correct password is refused while locked
  assert.equal((await login()).status, 423);
});

test('protected route requires a valid bearer token', async () => {
  const { body } = await register();
  assert.equal((await request(app).get('/api/auth/me')).status, 401);
  assert.equal((await request(app).get('/api/auth/me').set('Authorization', 'Bearer not-a-jwt')).status, 401);
  const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${body.accessToken}`);
  assert.equal(me.status, 200);
  assert.equal(me.body.user.name, 'Ana');
});

test('refresh requires the CSRF header', async () => {
  const res = await register();
  const cookie = cookieValue(refreshCookie(res));
  assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', cookie)).status, 403);
});

test('refresh rotates the token, and reusing an old one revokes the session', async () => {
  const first = cookieValue(refreshCookie(await register()));

  const r1 = await request(app).post('/api/auth/refresh').set('Cookie', first).set(CSRF);
  assert.equal(r1.status, 200);
  const second = cookieValue(refreshCookie(r1));
  assert.notEqual(first, second);

  // Attacker replays the old token → detected, whole family revoked
  assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', first).set(CSRF)).status, 401);
  // ...so the legitimate newer token no longer works either
  assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', second).set(CSRF)).status, 401);
});

test('logout revokes the refresh token', async () => {
  const cookie = cookieValue(refreshCookie(await register()));
  assert.equal((await request(app).post('/api/auth/logout').set('Cookie', cookie).set(CSRF)).status, 204);
  assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', cookie).set(CSRF)).status, 401);
});

test('changing the password invalidates old access and refresh tokens', async () => {
  const reg = await register();
  const oldAccess = reg.body.accessToken;
  const oldRefresh = cookieValue(refreshCookie(reg));

  const res = await request(app)
    .post('/api/auth/change-password')
    .set('Authorization', `Bearer ${oldAccess}`)
    .send({ currentPassword: USER.password, newPassword: 'new-strong-pass-77' });
  assert.equal(res.status, 200);

  assert.equal((await request(app).get('/api/auth/me').set('Authorization', `Bearer ${oldAccess}`)).status, 401);
  assert.equal((await request(app).post('/api/auth/refresh').set('Cookie', oldRefresh).set(CSRF)).status, 401);
  assert.equal((await login(USER.email, 'new-strong-pass-77')).status, 200);
});

test('security headers are set and x-powered-by is hidden', async () => {
  const res = await request(app).get('/api/health');
  assert.equal(res.headers['x-powered-by'], undefined);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.ok(res.headers['content-security-policy']);
});

test('oversized bodies are rejected', async () => {
  const res = await request(app).post('/api/auth/login').send({ email: 'a@b.co', password: 'x'.repeat(20_000) });
  assert.equal(res.status, 413);
});
