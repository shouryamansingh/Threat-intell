import { Navigate, Route, Routes } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import Settings from './pages/Settings'
import { useProfile } from './hooks/useProfile'

/**
 * App shell: sidebar, top bar, and whichever page React owns.
 *
 * The profile is loaded once here and passed down, because both the sidebar
 * and the settings page need it — in the Jinja version each page re-fetched it
 * and then hand-populated the sidebar's DOM nodes.
 *
 * As pages are ported, add a <Route> here and flip that item in Sidebar.jsx
 * from an <a href> to a <NavLink to>. Nothing else has to change.
 */
export default function App() {
  const profile = useProfile()

  return (
    <>
      <Sidebar account={profile.account} />
      <TopBar />
      <Routes>
        <Route path="/settings" element={<Settings {...profile} />} />
        {/* Anything React doesn't own yet lands on the one page it does. */}
        <Route path="*" element={<Navigate to="/settings" replace />} />
      </Routes>
    </>
  )
}
