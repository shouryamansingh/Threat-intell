import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'

// Fonts and icons, bundled rather than fetched from fonts.googleapis.com and
// cdnjs. Those were two render-blocking round trips on every page load; see
// styles/fonts.css. Font Awesome is pinned to 6.4.0 to match the version the
// Jinja pages load, so `fas`/`fab` class names render identically.
import './styles/fonts.css'
import '@fortawesome/fontawesome-free/css/all.min.css'

// Order matters: tokens define the custom properties the other two consume.
import './styles/tokens.css'
import './styles/chrome.css'
import './styles/settings.css'

// Matches `base` in vite.config.js — the app is mounted under /app/ so it can
// never shadow an existing Flask route.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter basename="/app">
      <App />
    </BrowserRouter>
  </StrictMode>,
)
