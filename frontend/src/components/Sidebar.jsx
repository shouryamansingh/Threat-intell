import { NavLink } from 'react-router-dom'
import { signOut } from '../lib/api'
import { usePublicConfig } from '../lib/publicConfig'
import { usePendingCount } from '../hooks/useProfile'

/**
 * Primary navigation — the React twin of templates/_sidebar.html.
 *
 * Mid-migration, most destinations are still Jinja pages, so they are plain
 * <a> tags that leave the SPA. Only pages React actually owns use <NavLink>.
 * As each page is ported, its entry moves from `href` to `to` — that list is
 * the migration checklist.
 *
 * Two behaviours the Jinja version needed JS for are free here: the Users link
 * appears when `account.role` says so rather than being revealed by a callback
 * after load, and the pending badge follows its own hook.
 */
export default function Sidebar({ account }) {
  const { brand } = usePublicConfig()
  const pending = usePendingCount(account?.role)

  const name = account?.name || account?.email?.split('@')[0] || 'Signed in'
  const initial = ((account?.email || account?.name || '?').trim()[0] || '?').toUpperCase()

  return (
    <aside className="app-sidebar" id="app-sidebar" aria-label="Primary navigation">
      <a className="sb-logo" href="/" title={brand.name}>
        <img src={brand.icon} alt={brand.name} />
        <span className="sb-logo-text">Cyber Watch</span>
      </a>

      <nav className="sb-links">
        {/* Still Jinja. */}
        <a className="sb-link" href="/" title="Dashboard">
          <span className="sb-ico"><i className="fas fa-house" /></span>
          <span className="sb-label">Dashboard</span>
        </a>

        <a className="sb-link" href="/admin" title="Admin Settings">
          <span className="sb-ico"><i className="fas fa-user-shield" /></span>
          <span className="sb-label">Admin</span>
        </a>

        {account?.role === 'admin' && (
          <a className="sb-link" href="/admin/users" title="Users & Access">
            <span className="sb-ico"><i className="fas fa-users-gear" /></span>
            <span className="sb-label">Users &amp; Access</span>
            <span className={`sb-badge${pending > 0 ? ' show' : ''}`}>{pending}</span>
          </a>
        )}

        {/* The dashboard picks ?refresh=1 up on load — same contract as the
            non-dashboard branch of _sidebar.html. */}
        <a className="sb-link" href="/?refresh=1" title="Refresh project (wipe articles & workflow state)">
          <span className="sb-ico"><i className="fas fa-rotate-right" /></span>
          <span className="sb-label">Refresh Project</span>
        </a>

        {/* React owns this one. */}
        <NavLink
          className={({ isActive }) => `sb-link${isActive ? ' active' : ''}`}
          to="/settings"
          title="My account & password"
        >
          <span className="sb-ico"><i className="fas fa-user-gear" /></span>
          <span className="sb-label">My Account</span>
        </NavLink>
      </nav>

      <div className="sb-foot">
        {account && (
          <NavLink
            className={({ isActive }) => `sb-user${isActive ? ' active' : ''}`}
            to="/settings"
            title="My account"
          >
            {account.picture ? (
              <img className="sb-avatar" src={account.picture} alt="" referrerPolicy="no-referrer" />
            ) : (
              <span className="sb-avatar-initial">{initial}</span>
            )}
            <div className="sb-user-meta">
              <div className="name">{name}</div>
              <div className="email">{account.email || '—'}</div>
            </div>
          </NavLink>
        )}
        <button type="button" className="sb-link sb-logout" title="Sign out" onClick={signOut}>
          <span className="sb-ico"><i className="fas fa-right-from-bracket" /></span>
          <span className="sb-label">Sign out</span>
        </button>
      </div>
    </aside>
  )
}
