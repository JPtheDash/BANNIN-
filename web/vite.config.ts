import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server proxies /api and /healthz to `bannin serve` (default
// 127.0.0.1:8080) so the frontend never needs CORS config — same-origin
// as far as the browser is concerned. Production serving (single
// origin, bannin serve fronting the built assets) is a later milestone.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
    },
  },
})
