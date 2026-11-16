/**
 * Firebase, loaded on demand.
 *
 * Only accounts whose password_mode is 'firebase' ever need this, so the SDK
 * stays out of the bundle until someone clicks "Send reset link". Ported from
 * ensureFirebase() in templates/settings.html.
 *
 * The Jinja page got its config from `{{ firebase_config | tojson }}`. React
 * has no server render, so it reads the same value from /api/public-config
 * (see frontend_bridge.py) — one source of truth either way.
 */

import { get } from './api'

const SDK = 'https://www.gstatic.com/firebasejs/10.12.0'

let ready = null

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script')
    s.src = src
    s.onload = resolve
    s.onerror = () => reject(new Error('Could not reach Firebase.'))
    document.head.appendChild(s)
  })
}

export function ensureFirebase() {
  if (ready) return ready
  ready = (async () => {
    if (window.firebase?.auth) return window.firebase

    const { firebase_config: cfg, firebase_configured: configured } = await get('/api/public-config')
    if (!configured) throw new Error('Firebase is not configured on this server.')

    await loadScript(`${SDK}/firebase-app-compat.js`)
    await loadScript(`${SDK}/firebase-auth-compat.js`)
    window.firebase.initializeApp(cfg)
    return window.firebase
  })().catch((err) => {
    // Don't cache a failure — a dropped connection shouldn't disable the
    // button for the rest of the session.
    ready = null
    throw err
  })
  return ready
}

export const FB_ERRORS = {
  'auth/user-not-found':
    'No Firebase password exists for this address, so there is nothing to reset. ' +
    'Keep signing in with Google, or ask an admin for a local account.',
  'auth/invalid-email': 'Firebase rejected this address as invalid.',
  'auth/too-many-requests': 'Too many attempts. Wait a few minutes and try again.',
  'auth/network-request-failed':
    'Network error reaching Firebase. Check your connection and try again.',
  'auth/operation-not-allowed':
    'Email/password sign-in is disabled in the Firebase console. Ask an admin to enable it.',
}
