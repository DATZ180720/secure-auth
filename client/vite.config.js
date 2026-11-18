import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The proxy makes the API same-origin during development, so the
// SameSite=Strict refresh cookie is sent normally.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://localhost:4000' } },
});
