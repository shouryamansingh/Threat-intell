import { useEffect, useState } from 'react'
import { get } from './api'

/**
 * Server-supplied branding and Firebase config.
 *
 * The Jinja pages get these from a context processor (`{{ brand.logo }}`,
 * `{{ firebase_config | tojson }}`). React renders in the browser, so it reads
 * the same two values over HTTP instead — see /api/public-config in
 * frontend_bridge.py. Both are already public: today they are inlined into the
 * HTML of every page the app serves.
 *
 * Cached at module scope so the sidebar, top bar and Firebase loader share one
 * request rather than firing three.
 */

const FALLBACK = {
  brand: { name: 'Weekly Cyber Watch', logo: '/static/brand-logo.svg', icon: '/static/brand-icon.svg' },
  firebase_config: {},
  firebase_configured: false,
}

let cached = null

export function loadPublicConfig() {
  if (!cached) {
    cached = get('/api/public-config').catch(() => FALLBACK)
  }
  return cached
}

export function usePublicConfig() {
  const [cfg, setCfg] = useState(FALLBACK)
  useEffect(() => {
    let cancelled = false
    loadPublicConfig().then((c) => {
      if (!cancelled) setCfg({ ...FALLBACK, ...c })
    })
    return () => {
      cancelled = true
    }
  }, [])
  return cfg
}
