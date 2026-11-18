import { loadConfig } from './config.js';
import { createApp } from './app.js';

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(err.message);
  process.exit(1);
}

const { app, db } = createApp(config);
const server = app.listen(config.PORT, () => {
  console.log(`Auth API listening on http://localhost:${config.PORT} (${config.NODE_ENV})`);
});

const shutdown = () => {
  server.close(() => {
    db.close();
    process.exit(0);
  });
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
