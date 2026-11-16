/**
 * Display helpers, ported from templates/settings.html.
 *
 * These must stay byte-compatible with the Jinja pages while both exist —
 * an avatar tone or a timestamp that differs between /settings and
 * /admin/users is exactly the kind of drift that makes a half-migrated app
 * feel broken.
 */

/** Server timestamps are naive UTC ("2026-08-03 06:17:24"). */
export function toDate(ts) {
  if (!ts) return null
  const d = new Date(String(ts).replace(' ', 'T') + 'Z')
  return isNaN(d) ? null : d
}

export function absolute(ts) {
  const d = toDate(ts)
  return d
    ? d.toLocaleString(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '—'
}

export function relative(ts) {
  const d = toDate(ts)
  if (!d) return null
  const mins = Math.round((Date.now() - d.getTime()) / 60000)
  if (mins < 1) return 'moments ago'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs} hr ago`
  const days = Math.round(hrs / 24)
  return `${days} ${days === 1 ? 'day' : 'days'} ago`
}

export function initials(name, email) {
  const src = (name || email || '?').trim()
  const parts = src.split(/[\s._-]+/).filter(Boolean)
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : src.slice(0, 2)).toUpperCase()
}

/** Same deterministic tones as the roster, so you recognise yourself there. */
const TONES = [
  ['#EEF2FF', '#3A44A8', '#D3DAFB'],
  ['#E9F7F0', '#0E7350', '#C8E9D9'],
  ['#FDF3E7', '#8A5310', '#F2DCBE'],
  ['#FBEFF4', '#94305C', '#F0D2DF'],
  ['#EAF2FD', '#1F4C9B', '#CBDEF7'],
  ['#F3EEFB', '#5B3695', '#DDD1F2'],
  ['#E8F5F6', '#12656E', '#C6E5E8'],
]

export function toneFor(key) {
  let h = 0
  for (const ch of String(key)) h = (h * 31 + ch.charCodeAt(0)) | 0
  return TONES[Math.abs(h) % TONES.length]
}

export const METHOD_ICONS = {
  'google.com': 'fab fa-google',
  password: 'fas fa-key',
  local: 'fas fa-key',
  demo: 'fas fa-flask',
}

export const methodIcon = (provider) => METHOD_ICONS[provider] || 'fas fa-key'

/** Role chip weight: admin reads strongest. */
export const tier = (role) => (role === 'admin' ? 3 : role === 'analyst_admin' ? 2 : 1)

/** Matches the Jinja pages' scoring: length, then case mix, then digit+symbol. */
export function scorePassword(p) {
  if (!p) return 0
  let s = 0
  if (p.length >= 8) s++
  if (p.length >= 12) s++
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++
  if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++
  return Math.min(s, 4)
}
