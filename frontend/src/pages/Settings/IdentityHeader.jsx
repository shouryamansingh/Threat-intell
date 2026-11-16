import { initials, methodIcon, tier, toneFor } from '../../lib/format'

/** Avatar, name, and the status chips that summarise the account at a glance. */
export default function IdentityHeader({ account: a }) {
  const name = a.name || (a.email ? a.email.split('@')[0] : 'Signed in')
  const [bg, fg, bd] = toneFor((a.email || name).toLowerCase())

  return (
    <div className="identity" id="identity">
      <span>
        {a.picture ? (
          <img
            className="big-avatar"
            src={a.picture}
            alt=""
            referrerPolicy="no-referrer"
            style={{ borderColor: 'var(--accent-line)' }}
          />
        ) : (
          <span className="big-avatar" style={{ background: bg, color: fg, borderColor: bd }}>
            {initials(a.name, a.email)}
          </span>
        )}
      </span>

      <div className="who">
        <div className="nm">{name}</div>
        <div className="ml">{a.email || '—'}</div>
      </div>

      <div className="tags">
        <span className={`rchip t${tier(a.role)}`}>{a.role_label}</span>

        <span className="tag">
          <i className={methodIcon(a.provider)} />
          {a.provider_label}
        </span>

        {a.active ? (
          <span className="tag ok">
            <i className="fas fa-circle-check" />
            Enabled
          </span>
        ) : (
          <span className="tag bad">
            <i className="fas fa-circle-xmark" />
            Disabled
          </span>
        )}

        {a.identity_verified ? (
          <span className="tag ok">
            <i className="fas fa-user-check" />
            Verified identity
          </span>
        ) : (
          <span
            className="tag warn"
            title="Some restricted views, such as the access audit log, require a provider-verified identity."
          >
            <i className="fas fa-user-clock" />
            Unverified identity
          </span>
        )}
      </div>
    </div>
  )
}
