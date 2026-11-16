import { useCallback, useEffect, useState } from 'react'
import { get } from '../lib/api'

/**
 * The signed-in account, from /api/profile/me.
 *
 * One call feeds both the page and the sidebar identity — the Jinja page did
 * the same thing, and duplicating it would double the request on every save.
 *
 * A 401 means the session expired or never existed. The Jinja page showed an
 * error banner and left you staring at an empty form; sending you to /login is
 * what actually helps, so this hook redirects instead.
 */
export function useProfile() {
  const [account, setAccount] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const reload = useCallback(async () => {
    try {
      const j = await get('/api/profile/me')
      setAccount(j.account)
      setError(null)
      return j.account
    } catch (e) {
      if (e.status === 401) {
        window.location.href = '/login'
        return null
      }
      setError(e.message || 'Could not load your account.')
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    reload()
  }, [reload])

  return { account, loading, error, reload }
}

/**
 * Pending access requests, for the sidebar badge. Admin-only endpoint, so this
 * stays quiet for everyone else rather than logging a 403 on every page load.
 */
export function usePendingCount(role) {
  const [count, setCount] = useState(0)

  useEffect(() => {
    if (role !== 'admin') return
    let cancelled = false
    get('/api/admin/access-requests')
      .then((j) => {
        if (!cancelled) setCount(j.pending_count || 0)
      })
      .catch(() => {
        /* Badge is decorative — a failure here must not surface as an error. */
      })
    return () => {
      cancelled = true
    }
  }, [role])

  return count
}
