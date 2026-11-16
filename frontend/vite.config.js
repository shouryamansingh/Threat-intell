import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The Flask dashboard. config.py defaults to 127.0.0.1:5001 (TI_DASHBOARD_PORT).
const FLASK = process.env.TI_DASHBOARD_URL || 'http://127.0.0.1:5001'

// Everything Flask still owns. Proxying rather than calling Flask directly is
// what keeps the session cookie working: the browser only ever sees one origin
// (the Vite dev server), so the HttpOnly / SameSite=Lax cookie Flask sets on
// sign-in is sent back on every /api call with no CORS relaxation anywhere.
//
// Loosening SameSite or adding permissive CORS to make a second origin work
// would weaken the real app's auth. Don't — proxy instead.
const FLASK_OWNS = [
  '/api',            // the 53 JSON endpoints this UI reads
  '/socket.io',      // live scraping progress
  '/static',         // brand logo, icon, shield
  '/login',          // still a Jinja page
  '/admin',          // still Jinja: /admin and /admin/users
  '/setup-profile',  // still Jinja
  '/healthz',
]

const proxy = Object.fromEntries(
  FLASK_OWNS.map((path) => [
    path,
    { target: FLASK, changeOrigin: false, ws: path === '/socket.io' },
  ]),
)

export default defineConfig({
  plugins: [react()],

  // Served under /app/ in production so it cannot collide with any existing
  // Flask route. The dev server matches, so dev and prod URLs stay identical.
  base: '/app/',

  server: { port: 5173, strictPort: true, proxy },

  // `npm run preview` serves the real build with the same proxy, so the
  // production bundle can be checked against a live API before deploying.
  preview: { port: 5175, strictPort: true, proxy },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
  },
})
