import { useEffect, useMemo, useState } from 'react'
import Panel, { Button, PanelBody, PanelFoot } from '../../components/Panel'
import { post } from '../../lib/api'

const EMPTY = { display_name: '', department: '', phone: '', notification_email: '' }

const fromAccount = (a) => ({
  display_name: a.name || '',
  department: a.department || '',
  phone: a.phone || '',
  notification_email: a.notification_email || '',
})

/**
 * The fields a user owns about themselves.
 *
 * Dirty tracking was ~20 lines of snapshot/compare bookkeeping in the Jinja
 * page (a join on '\n', a CLEAN global, a markClean() called from four
 * places). Here it is one derived comparison — the whole class of "the Save
 * button got stuck enabled" bug goes away with it.
 *
 * Client-side validation deliberately mirrors api_profile_update() rather than
 * improving on it: a rule enforced only here would be a rule the API doesn't
 * actually have.
 */
export default function DetailsPanel({ account, onSaved, notify }) {
  const [form, setForm] = useState(EMPTY)
  const [saving, setSaving] = useState(false)

  const clean = useMemo(() => fromAccount(account), [account])
  useEffect(() => setForm(clean), [clean])

  const editable = account.editable !== false
  const dirty = editable && JSON.stringify(form) !== JSON.stringify(clean)

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  // Spells out the address mail will really go to, so the blank case is never
  // a guess.
  const target = form.notification_email.trim() || account.email || ''
  const usingSignin = !form.notification_email.trim()

  async function submit(e) {
    e.preventDefault()
    const payload = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, v.trim()]))

    if (!payload.display_name) return notify('error', 'A display name is required.')
    if (payload.notification_email && !payload.notification_email.includes('@')) {
      return notify('error', 'Enter a valid notification email, or leave it blank.')
    }

    setSaving(true)
    try {
      await post('/api/profile/update', payload)
      notify('success', 'Your details were saved.')
      await onSaved()
    } catch (err) {
      notify('error', err.message || 'Could not save your details.')
    } finally {
      setSaving(false)
    }
  }

  function discard() {
    setForm(clean)
    notify('info', 'Unsaved changes discarded.')
  }

  return (
    <Panel
      icon="fas fa-id-card"
      title="Your details"
      sub="How you appear across the dashboard, reports and notifications."
      tools={
        <span className={`dirty-chip${dirty ? ' show' : ''}`}>
          <span className="dot" />
          Unsaved changes
        </span>
      }
    >
      <form onSubmit={submit}>
        <PanelBody>
          <div className="fgroup">
            <div className="fgroup-head">
              <span className="fg-t">Identity</span>
              <span className="fg-rule" />
            </div>
            <div className="grid2">
              <div className="field">
                <label htmlFor="display_name">
                  Display name<span className="req">*</span>
                </label>
                <div className="ctl">
                  <i className="fas fa-user ctl-ico" aria-hidden="true" />
                  <input
                    className="inp has-ico"
                    type="text"
                    id="display_name"
                    maxLength={200}
                    required
                    placeholder="e.g. Alex Morgan"
                    value={form.display_name}
                    onChange={set('display_name')}
                    disabled={!editable}
                  />
                </div>
                <div className="hint">Shown in the sidebar, the audit trail and report footers.</div>
              </div>

              <div className="field">
                <label htmlFor="email_ro">
                  Sign-in email
                  <span
                    className="pill lock"
                    title="Fixed to the identity you signed in with. An admin can create a new account if this must change."
                  >
                    <i className="fas fa-lock" />
                    Locked
                  </span>
                </label>
                <div className="ctl">
                  <i className="fas fa-envelope ctl-ico" aria-hidden="true" />
                  <input className="inp has-ico" type="text" id="email_ro" value={account.email || ''} disabled readOnly />
                </div>
                <div className="hint">Set by the identity you signed in with.</div>
              </div>
            </div>
          </div>

          <div className="fgroup">
            <div className="fgroup-head">
              <span className="fg-t">Contact &amp; notifications</span>
              <span className="fg-rule" />
            </div>
            <div className="grid2">
              <div className="field">
                <label htmlFor="department">
                  Department<span className="pill">Optional</span>
                </label>
                <div className="ctl">
                  <i className="fas fa-sitemap ctl-ico" aria-hidden="true" />
                  <input
                    className="inp has-ico"
                    type="text"
                    id="department"
                    maxLength={120}
                    placeholder="e.g. IT Internal Audit"
                    value={form.department}
                    onChange={set('department')}
                    disabled={!editable}
                  />
                </div>
              </div>

              <div className="field">
                <label htmlFor="phone">
                  Phone<span className="pill">Optional</span>
                </label>
                <div className="ctl">
                  <i className="fas fa-phone ctl-ico" aria-hidden="true" />
                  <input
                    className="inp has-ico"
                    type="text"
                    id="phone"
                    maxLength={40}
                    placeholder="e.g. +91 98765 43210"
                    value={form.phone}
                    onChange={set('phone')}
                    disabled={!editable}
                  />
                </div>
              </div>

              <div className="field full">
                <label htmlFor="notification_email">
                  Notification email<span className="pill">Optional</span>
                </label>
                <div className="ctl">
                  <i className="fas fa-bell ctl-ico" aria-hidden="true" />
                  <input
                    className="inp has-ico"
                    type="email"
                    id="notification_email"
                    maxLength={200}
                    placeholder="Leave blank to use your sign-in email"
                    value={form.notification_email}
                    onChange={set('notification_email')}
                    disabled={!editable}
                  />
                </div>
                {target && (
                  <div className="deliver">
                    <i className="fas fa-paper-plane" />
                    <span>
                      Alerts and approval requests go to <b>{target}</b>
                      {usingSignin && <span className="fb"> — your sign-in address</span>}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </PanelBody>

        <PanelFoot
          hint={
            editable
              ? 'Role and account status are managed by an administrator.'
              : 'The demo identity is read-only.'
          }
        >
          <button type="button" className="btn" onClick={discard} disabled={!dirty}>
            Discard changes
          </button>
          <Button type="submit" variant="primary" icon="fas fa-check" loading={saving} disabled={!dirty}>
            Save details
          </Button>
        </PanelFoot>
      </form>
    </Panel>
  )
}
