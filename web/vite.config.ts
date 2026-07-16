import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server (npm run dev, for frontend development) proxies /api and
// /healthz to `bannin serve` (default 127.0.0.1:8080) so the frontend
// never needs CORS config — same-origin as far as the browser is
// concerned. For running the tool, `npm run build` emits static assets
// that `bannin serve` fronts directly on its own port (single origin,
// no proxy) — see scripts/start-web.sh.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
    },
  },
})
