/**
 * The one place that talks to Flask.
 *
 * Ported from the `api()` helper in templates/settings.html, keeping its exact
 * contract: throw on non-2xx with the server's own message, and carry the HTTP
 * status plus the machine-readable `error` code on the thrown object. The
 * pages depend on both — `not_signed_in` drives the redirect to /login.
 */

export class ApiError extends Error {
  constructor(message, { status, code } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

export async function api(url, options) {
  const res = await fetch(url, {
    // Same-origin by default, but state it: the whole auth model is the Flask
    // session cookie, and a future move to a second origin must fail loudly
    // here rather than silently sending anonymous requests.
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })

  let body = {}
  try {
    body = await res.json()
  } catch {
    /* Empty or non-JSON body — leave body as {} and fall through. */
  }

  if (!res.ok) {
    throw new ApiError(body.message || body.error || `Request failed (${res.status})`, {
      status: res.status,
      code: body.error,
    })
  }
  return body
}

export const get = (url) => api(url)
export const post = (url, payload) =>
  api(url, { method: 'POST', body: JSON.stringify(payload ?? {}) })

/**
 * Sign out of Flask, then of Firebase if that SDK happens to be loaded.
 *
 * Both halves are best-effort on purpose: a failed logout call must not trap
 * someone on the page. Leaving the Firebase client session behind would let
 * the next visit silently restore it.
 */
export async function signOut() {
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
  } catch {
    /* ignore */
  }
  try {
    if (window.firebase?.auth) await window.firebase.auth().signOut()
  } catch {
    /* ignore */
  }
  window.location.href = '/login'
}
