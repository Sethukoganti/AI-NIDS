import { useEffect, useState } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { LogOut, Menu, ShieldAlert, UserCircle2, X } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { AssistantPanel } from '@/components/assistant/AssistantPanel'
import { useAuth } from '@/context/AuthContext'
import { cn } from '@/lib/format'

/** Plain-language page names for the header, so the current screen is obvious. */
const PAGE_TITLES: Record<string, string> = {
  '/dashboard': 'Overview',
  '/analyzer': 'Analyze traffic',
  '/detections': 'Detections',
  '/predictions': 'Detections',
  '/alerts': 'Detections',
  '/model': 'AI model',
  '/insights': 'AI model',
  '/data': 'Data',
  '/datasets': 'Data',
  '/simulation': 'Data',
  '/settings': 'Settings',
}

export function AppShell() {
  const { user, loading, logout } = useAuth()
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()
  const title = PAGE_TITLES[location.pathname] ?? 'AI-NIDS'

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setMobileOpen(false)
  }, [location.pathname])

  if (loading) {
    return (
      <div className="grid h-screen place-items-center">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary/30 border-t-primary" />
          <span className="text-xs">Restoring session…</span>
        </div>
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-screen overflow-hidden">
        <div className="hidden lg:block">
          <Sidebar />
        </div>

        {mobileOpen && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <div
              className="absolute inset-0 animate-fade-in bg-black/60 backdrop-blur-sm"
              onClick={() => setMobileOpen(false)}
            />
            <div className="absolute left-0 top-0 h-full animate-slide-in-left">
              <Sidebar onNavigate={() => setMobileOpen(false)} />
            </div>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border/70 bg-panel/50 px-4 backdrop-blur-sm">
            <div className="flex min-w-0 items-center gap-3">
              <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen((v) => !v)}>
                {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
              </Button>
              <div className="flex min-w-0 items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0 text-primary" />
                <span key={location.pathname} className="animate-fade-in truncate text-sm font-medium">
                  {title}
                </span>
                <span className="hidden truncate text-[11px] text-muted-foreground md:inline">
                  · Random Forest intrusion detection on CICIDS2017
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="hidden items-center gap-2 rounded-lg border border-border/70 bg-background/40 px-2.5 py-1.5 transition-colors hover:border-primary/40 sm:flex">
                    <UserCircle2 className="h-4 w-4 text-muted-foreground" />
                    <div className="leading-tight">
                      <div className="text-xs font-medium">{user.name}</div>
                      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{user.role}</div>
                    </div>
                  </div>
                </TooltipTrigger>
                <TooltipContent>{user.email}</TooltipContent>
              </Tooltip>
              <Button
                variant="outline"
                size="sm"
                onClick={logout}
                className={cn('text-muted-foreground hover:text-foreground')}
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Sign out</span>
              </Button>
            </div>
          </header>

          <main className="flex-1 overflow-y-auto">
            {/* key={pathname} re-runs the entrance animation on every navigation */}
            <div key={location.pathname} className="animate-page mx-auto max-w-[1500px] p-4 lg:p-6">
              <Outlet />
            </div>
          </main>
        </div>

        <AssistantPanel />
      </div>
    </TooltipProvider>
  )
}
