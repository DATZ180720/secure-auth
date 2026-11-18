import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { openDatabase } from './db.js';
import { UserService } from './services/users.js';
import { TokenService } from './services/tokens.js';
import { authRouter } from './routes/auth.js';
import { createLimiters, errorHandler } from './middleware.js';

export function createApp(config) {
  const db = openDatabase(config.DATABASE_PATH);
  const users = new UserService(db, config);
  const tokens = new TokenService(db, config);
  const limiters = createLimiters(config);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // correct client IP behind one reverse proxy (rate limiting, audit)

  app.use(helmet()); // secure headers: CSP, HSTS, X-Content-Type-Options, frame protection…
  app.use(cors({ origin: config.CLIENT_ORIGIN, credentials: true })); // only our front-end, with cookies
  app.use(express.json({ limit: '10kb' })); // small bodies only
  app.use(cookieParser());
  app.use('/api', limiters.api);

  app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
  app.use('/api/auth', authRouter({ users, tokens, config, limiters }));
  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use(errorHandler);

  return { app, db };
}
