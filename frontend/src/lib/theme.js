/**
 * Light/dark, stored in localStorage under the same 'theme' key the Jinja
 * pages use — so toggling here and then navigating to /admin keeps the theme.
 *
 * The initial class is set by the inline script in index.html, before paint.
 * This module only handles toggling after mount.
 */

export const isDark = () => document.documentElement.classList.contains('dark')

export function toggleTheme() {
  const dark = document.documentElement.classList.toggle('dark')
  try {
    localStorage.setItem('theme', dark ? 'dark' : 'light')
  } catch {
    /* Private mode — the class still applied, it just won't survive a reload. */
  }
  return dark
}
