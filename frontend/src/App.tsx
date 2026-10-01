import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { Landing } from '@/pages/Landing'
import { Login } from '@/pages/Login'
import { Dashboard } from '@/pages/Dashboard'
import { TrafficAnalyzer } from '@/pages/TrafficAnalyzer'
import { Detections } from '@/pages/Detections'
import { ModelHub } from '@/pages/ModelHub'
import { DataHub } from '@/pages/DataHub'
import { Settings } from '@/pages/Settings'
import { LEGACY_REDIRECTS } from '@/lib/routes'
import { NotFound } from '@/pages/NotFound'

/**
 * Route map. Everything under <AppShell /> requires a valid session — the shell
 * redirects to /login itself, so no route is ever rendered for an anonymous user.
 *
 * The navigation is intentionally small: six destinations, with related screens
 * grouped into tabs. The older deep links are kept as redirects so existing
 * bookmarks (and the API docs) keep working.
 */
export function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />

      <Route element={<AppShell />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/analyzer" element={<TrafficAnalyzer />} />
        <Route path="/detections" element={<Detections />} />
        <Route path="/model" element={<ModelHub />} />
        <Route path="/data" element={<DataHub />} />
        <Route path="/settings" element={<Settings />} />

        {/* legacy links → grouped pages */}
        <Route path="/predictions" element={<Navigate to={LEGACY_REDIRECTS["/predictions"]} replace />} />
        <Route path="/alerts" element={<Navigate to={LEGACY_REDIRECTS["/alerts"]} replace />} />
        <Route path="/insights" element={<Navigate to={LEGACY_REDIRECTS["/insights"]} replace />} />
        <Route path="/datasets" element={<Navigate to={LEGACY_REDIRECTS["/datasets"]} replace />} />
        <Route path="/simulation" element={<Navigate to={LEGACY_REDIRECTS["/simulation"]} replace />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}
