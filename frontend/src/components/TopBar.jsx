import { useState } from 'react'
import { isDark, toggleTheme } from '../lib/theme'
import { usePublicConfig } from '../lib/publicConfig'

/**
 * Brand lockup and the light/dark switch. Mirrors <header class="app"> from
 * the Jinja pages; the toggle's two-slot markup is what the stylesheet
 * animates, so it is reproduced exactly.
 */
export default function TopBar() {
  const { brand } = usePublicConfig()
  // Seeded from the class the inline boot script already applied, so the
  // switch is never a frame out of step with the page.
  const [dark, setDark] = useState(isDark)

  return (
    <header className="app">
      <div className="inner">
        <a className="brand" href="/">
          <img src={brand.logo} alt={brand.name} />
          <div className="divider" aria-hidden="true" />
          <div>
            <div className="title">Weekly Cyber Watch</div>
            <div className="subtitle">IT Internal Audit</div>
          </div>
        </a>
        <button
          type="button"
          className="theme-toggle"
          style={{ marginLeft: 'auto' }}
          role="switch"
          aria-checked={dark}
          aria-label="Toggle light / dark theme"
          title="Toggle theme"
          onClick={() => setDark(toggleTheme())}
        >
          <span className="tt-row">
            <span className="tt-active tt-slot" aria-hidden="true">
              <i className="fas fa-moon moon" />
              <i className="fas fa-sun sun" />
            </span>
            <span className="tt-muted tt-slot" aria-hidden="true">
              <i className="fas fa-sun sun" />
              <i className="fas fa-moon moon" />
            </span>
          </span>
        </button>
      </div>
    </header>
  )
}
