import { useState } from 'react'
import Panel, { Button, PanelBody, PanelFoot } from '../../components/Panel'
import PasswordInput from '../../components/PasswordInput'
import { post } from '../../lib/api'
import { scorePassword } from '../../lib/format'
import { FB_ERRORS, ensureFirebase } from '../../lib/firebase'

/**
 * Three mutually exclusive states, decided by the server's password_mode:
 *
 *   'set'      Google user with no hash yet — set a first password, no current
 *              one to prove (the signed-in session is the proof).
 *   'local'    a hash exists — change it, current password required.
 *   'firebase' the credential lives with Firebase — email a reset link.
 *   'none'     demo identity, nothing to change.
 *
 * The Jinja page held all four in the DOM at once and toggled style.display on
 * each, which is why the mode logic there runs to forty lines of imperative
 * show/hide. Rendering one branch is the same behaviour, stated once.
 */
export default function PasswordPanel({ account: a, onChanged, notify }) {
  const mode = a.password_mode
  if (mode === 'firebase') return <FirebaseReset account={a} notify={notify} />
  if (mode === 'none') return <NoPassword />
  return <LocalPassword account={a} onChanged={onChanged} notify={notify} />
}

function LocalPassword({ account: a, onChanged, notify }) {
  const firstTime = a.password_mode === 'set'
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [saving, setSaving] = useState(false)

  const match = matchState(next, confirm)

  async function submit(e) {
    e.preventDefault()
    if (!firstTime && !current) return notify('error', 'Enter your current password.')
    if (next.length < 8) return notify('error', 'New password must be at least 8 characters.')
    if (next !== confirm) return notify('error', "The two new passwords don't match.")

    setSaving(true)
    try {
      await post('/api/profile/password', {
        current_password: firstTime ? '' : current,
        new_password: next,
      })
      setCurrent('')
      setNext('')
      setConfirm('')
      notify(
        'success',
        firstTime
          ? 'Password set. You can now sign in with your email and password, or keep using Google.'
          : 'Your password was changed. It applies the next time you sign in.',
      )
      // The account has moved from 'set' to 'local'; re-read so the form now
      // asks for the current password on any further change.
      await onChanged()
    } catch (err) {
      notify('error', err.message || 'Could not change the password.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Panel
      icon="fas fa-key"
      title="Password"
      sub={
        firstTime
          ? 'You sign in with Google. Set a password here and you can use either from then on.'
          : 'You can sign in with Google or with this password.'
      }
    >
      <form onSubmit={submit}>
        <PanelBody>
          <div className="grid2">
            {!firstTime && (
              <div className="field full">
                <label htmlFor="pwCurrent">
                  Current password<span className="req">*</span>
                </label>
                <PasswordInput
                  id="pwCurrent"
                  autoComplete="current-password"
                  required
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                />
              </div>
            )}

            <div className="field">
              <label htmlFor="pwNew">
                New password<span className="req">*</span>
              </label>
              <PasswordInput
                id="pwNew"
                autoComplete="new-password"
                placeholder="At least 8 characters"
                value={next}
                onChange={(e) => setNext(e.target.value)}
              />
              <div className="pwd-meter" data-strength={String(scorePassword(next))}>
                <span />
                <span />
                <span />
                <span />
              </div>
            </div>

            <div className="field">
              <label htmlFor="pwConfirm">
                Confirm new password<span className="req">*</span>
              </label>
              <PasswordInput
                id="pwConfirm"
                autoComplete="new-password"
                placeholder="Re-type the new password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
              <div className={`match${match.tone ? ` ${match.tone}` : ''}`}>
                {match.text || ' '}
              </div>
            </div>
          </div>
        </PanelBody>

        <PanelFoot
          hint={`${firstTime ? 'Setting' : 'Changing'} your password is recorded in the access audit trail.`}
        >
          <Button type="submit" variant="primary" icon="fas fa-key" loading={saving}>
            {firstTime ? 'Set password' : 'Change password'}
          </Button>
        </PanelFoot>
      </form>
    </Panel>
  )
}

function matchState(p1, p2) {
  if (!p1 && !p2) return { text: '', tone: '' }
  if (p1.length < 8) return { text: 'At least 8 characters.', tone: 'bad' }
  if (!p2) return { text: 'Re-enter it to confirm.', tone: '' }
  if (p1 !== p2) return { text: "Passwords don't match yet.", tone: 'bad' }
  return { text: '✓ Passwords match.', tone: 'ok' }
}

function FirebaseReset({ account: a, notify }) {
  const [sending, setSending] = useState(false)

  async function send() {
    if (!a.email) return notify('error', 'No email on file for this account.')
    setSending(true)
    try {
      const firebase = await ensureFirebase()
      await firebase.auth().sendPasswordResetEmail(a.email)
      notify(
        'success',
        `Reset link sent to ${a.email}. It is valid for one hour — check your spam folder if it does not arrive.`,
      )
    } catch (err) {
      notify('error', FB_ERRORS[err.code] || err.message || 'Could not send the reset email.')
    } finally {
      setSending(false)
    }
  }

  return (
    <Panel icon="fas fa-key" title="Password" sub="This account signs in through Firebase.">
      <PanelBody>
        <div className="callout">
          <div className="ico">
            <i className="fas fa-envelope" />
          </div>
          <div>
            <div className="t">Your password is managed by Firebase</div>
            <div className="d">
              {a.provider === 'google.com'
                ? 'You signed in with Google, so there may be no password on this account at all. ' +
                  'If one was added during onboarding, a reset link sent to your sign-in address will change it — ' +
                  'your Google account password is never affected.'
                : 'We never see it, so it can only be changed through a reset link sent to your ' +
                  'sign-in address. The link is valid for one hour.'}
            </div>
          </div>
        </div>
      </PanelBody>
      <PanelFoot hint={`The link goes to ${a.email}.`}>
        <Button variant="primary" icon="fas fa-paper-plane" loading={sending} onClick={send}>
          Send reset link
        </Button>
      </PanelFoot>
    </Panel>
  )
}

function NoPassword() {
  return (
    <Panel icon="fas fa-key" title="Password" sub="This identity has no credential.">
      <PanelBody>
        <div className="callout warn">
          <div className="ico">
            <i className="fas fa-circle-info" />
          </div>
          <div>
            <div className="t">No password on this identity</div>
            <div className="d">
              This session is running in demo mode, which has no credential to change.
            </div>
          </div>
        </div>
      </PanelBody>
    </Panel>
  )
}
