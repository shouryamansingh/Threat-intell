import Panel from '../../components/Panel'
import Notice, { useNotice } from '../../components/Notice'
import DetailsPanel from './DetailsPanel'
import IdentityHeader from './IdentityHeader'
import PasswordPanel from './PasswordPanel'
import RolePanel from './RolePanel'
import { signOut } from '../../lib/api'

/**
 * "My account" — the React port of templates/settings.html.
 *
 * Same four sections, same endpoints, same copy. The page owns the notice
 * banner and hands `notify` down, so a save in one panel and a password change
 * in another can't fight over the same banner.
 */
export default function Settings({ account, loading, error, reload }) {
  const { notice, show, dismiss } = useNotice()

  return (
    <main>
      <div className="page-head">
        <div className="eyebrow">Your account</div>
        <h1>My account</h1>
        <p>
          Your details as this platform holds them, the role that decides what you can do, and where
          to change your password. Only an administrator can change your role.
        </p>
      </div>

      <Notice notice={notice || (error && { kind: 'error', message: error })} onDismiss={dismiss} />

      {loading && <div className="hint">Loading your account…</div>}

      {account && (
        <>
          <IdentityHeader account={account} />
          <DetailsPanel account={account} onSaved={reload} notify={show} />
          <RolePanel account={account} />
          <PasswordPanel account={account} onChanged={reload} notify={show} />

          <Panel
            icon="fas fa-right-from-bracket"
            title="Session"
            sub="Sign out of this browser. Sessions expire on their own after seven days."
            tools={
              <button type="button" className="btn danger" onClick={signOut}>
                <i className="fas fa-right-from-bracket" /> Sign out
              </button>
            }
          />
        </>
      )}
    </main>
  )
}
