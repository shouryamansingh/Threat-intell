import Panel, { PanelBody } from '../../components/Panel'
import { absolute, methodIcon, relative, tier } from '../../lib/format'

const Fact = ({ label, children }) => (
  <div className="fact">
    <span className="fact-k">{label}</span>
    <div className="fact-v">{children}</div>
  </div>
)

/** What this account may do, and the flat facts about it. Read-only by design. */
export default function RolePanel({ account: a }) {
  const rel = relative(a.last_login)

  return (
    <Panel
      icon="fas fa-shield-halved"
      title="Role & access"
      sub="What this account is permitted to do. Read-only — ask an admin to change it."
      tools={<span className={`rchip t${tier(a.role)}`}>{a.role_label}</span>}
      footer={
        <div className="facts">
          <Fact label="Signed in with">
            <span className="method">
              <i className={methodIcon(a.provider)} />
              {a.provider_label}
            </span>
          </Fact>

          <Fact label="Account created">{absolute(a.created_at)}</Fact>

          <Fact label="Last sign-in">
            {absolute(a.last_login)}
            {rel && <span className="sub">{rel}</span>}
          </Fact>

          <Fact label="Notifications go to">
            {a.notification_email || a.email || '—'}
            {!a.notification_email && <span className="sub">Your sign-in address</span>}
          </Fact>

          <Fact label="User ID">
            <span className="mono" style={{ fontSize: '11.5px' }}>
              {a.uid}
            </span>
          </Fact>

          <Fact label="Role fixed by config">
            {a.is_bootstrap ? (
              <>
                Yes<span className="sub">Listed in BOOTSTRAP_SUPER_ADMINS — always an admin</span>
              </>
            ) : (
              <>
                No<span className="sub">An admin sets this in Users &amp; Access</span>
              </>
            )}
          </Fact>
        </div>
      }
    >
      <PanelBody>
        <div className="fact-v" style={{ color: 'var(--ink-3)' }}>
          {a.role_description || '—'}
        </div>
        <ul className="caps">
          {(a.capabilities || []).map((c) => (
            <li key={c.name} className={c.allowed ? 'yes' : 'no'}>
              <i className={`fas fa-${c.allowed ? 'check' : 'minus'}`} />
              {c.name}
            </li>
          ))}
        </ul>
      </PanelBody>
    </Panel>
  )
}
