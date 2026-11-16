import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * The dismissible banner at the top of the page.
 *
 * Ported from notice() in templates/settings.html, including its two rules:
 * errors stay until dismissed, everything else self-clears after 6s; and the
 * page scrolls to the top so the message is never announced off-screen.
 *
 * The Jinja version built this with innerHTML and hand-escaped the message.
 * React escapes for us, so the whole `esc()` helper disappears here.
 */
export function useNotice() {
  const [notice, setNotice] = useState(null)
  const timer = useRef(null)

  const show = useCallback((kind, message) => {
    clearTimeout(timer.current)
    setNotice({ kind, message })
    if (kind !== 'error') {
      timer.current = setTimeout(() => setNotice(null), 6000)
    }
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const dismiss = useCallback(() => {
    clearTimeout(timer.current)
    setNotice(null)
  }, [])

  useEffect(() => () => clearTimeout(timer.current), [])

  return { notice, show, dismiss }
}

export default function Notice({ notice, onDismiss }) {
  return (
    <div id="noticeWrap">
      <div
        className={notice ? `notice show ${notice.kind}` : 'notice'}
        role={notice?.kind === 'error' ? 'alert' : 'status'}
      >
        {notice && (
          <>
            <span className="bar" />
            <span>{notice.message}</span>
            <button className="x" aria-label="Dismiss" onClick={onDismiss}>
              ✕
            </button>
          </>
        )}
      </div>
    </div>
  )
}
