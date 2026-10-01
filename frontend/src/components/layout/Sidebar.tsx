import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  Brain,
  Database,
  Gauge,
  LayoutDashboard,
  Settings,
  ShieldCheck,
  Upload,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/format'
import { useHealth } from '@/hooks/useHealth'

interface NavItem {
  to: string
  label: string
  hint: string
  icon: LucideIcon
  /** routes that should light this item up as well (grouped pages) */
  alias?: string[]
}

/**
 * Deliberately short: six destinations, each with a plain-language hint, and one
 * obvious primary action. Related screens live inside a page's tabs rather than
 * in the sidebar, so a new user never has to guess which of nine entries holds
 * what they are looking for.
 */
const GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: 'Monitor',
    items: [
      {
        to: '/dashboard',
        label: 'Overview',
        hint: 'Live summary of the last analysis',
        icon: LayoutDashboard,
      },
    ],
  },
  {
    title: 'Investigate',
    items: [
      {
        to: '/analyzer',
        label: 'Analyze traffic',
        hint: 'Upload a CSV and score it',
        icon: Upload,
      },
      {
        to: '/detections',
        label: 'Detections',
        hint: 'Flagged flows and alerts',
        icon: AlertTriangle,
        alias: ['/predictions', '/alerts'],
      },
    ],
  },
  {
    title: 'Understand',
    items: [
      {
        to: '/model',
        label: 'AI model',
        hint: 'Metrics, features, explanations',
        icon: Brain,
        alias: ['/insights'],
      },
      {
        to: '/data',
        label: 'Data',
        hint: 'Datasets and live simulation',
        icon: Database,
        alias: ['/datasets', '/simulation'],
      },
    ],
  },
  {
    title: 'System',
    items: [
      {
        to: '/settings',
        label: 'Settings',
        hint: 'Account, users, system info',
        icon: Settings,
      },
    ],
  },
]

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { health } = useHealth()
  const location = useLocation()
  const online = health?.status === 'healthy'
  const degraded = health?.status === 'degraded'

  return (
    <aside className="flex h-full w-[248px] shrink-0 flex-col border-r border-border/70 bg-panel/60 backdrop-blur-sm">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <div className="relative grid h-9 w-9 place-items-center rounded-lg border border-primary/30 bg-primary/10">
          <ShieldCheck className="h-5 w-5 text-primary" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-wide">AI-NIDS</div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Intrusion detection</div>
        </div>
      </div>

      <div className="px-3 pb-3">
        <NavLink
          to="/analyzer"
          onClick={onNavigate}
          className="group flex items-center justify-center gap-2 rounded-lg bg-primary px-3 py-2.5 text-sm font-medium text-primary-foreground shadow-sm transition-all duration-300 hover:bg-primary/90 hover:shadow-[0_8px_30px_-12px_rgba(34,211,238,0.8)] active:scale-[0.98]"
        >
          <Upload className="h-4 w-4 transition-transform duration-300 group-hover:-translate-y-0.5" />
          Analyze new traffic
        </NavLink>
      </div>

      <nav className="flex-1 space-y-3 overflow-y-auto px-2 pb-3">
        {GROUPS.map((group) => (
          <div key={group.title}>
            <div className="px-3 pb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">
              {group.title}
            </div>
            <div className="space-y-0.5">
              {group.items.map(({ to, label, hint, icon: Icon, alias }) => {
                const aliased = alias?.some((path) => location.pathname.startsWith(path))
                return (
                  <NavLink
                    key={to}
                    to={to}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        'group relative flex items-start gap-2.5 rounded-lg px-3 py-2 transition-all duration-300',
                        isActive || aliased
                          ? 'bg-primary/12 text-primary shadow-[inset_0_0_0_1px_rgba(34,211,238,0.18)]'
                          : 'text-muted-foreground hover:translate-x-0.5 hover:bg-muted/50 hover:text-foreground',
                      )
                    }
                  >
                    <Icon className="mt-0.5 h-4 w-4 shrink-0" />
                    <span className="min-w-0">
                      <span className="block truncate text-[13px] font-medium leading-tight">{label}</span>
                      <span className="mt-0.5 block truncate text-[10px] leading-tight opacity-70">{hint}</span>
                    </span>
                  </NavLink>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-border/70 p-3">
        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              {online && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" />
              )}
              <span
                className={cn(
                  'relative inline-flex h-2.5 w-2.5 rounded-full',
                  online ? 'bg-emerald-500' : degraded ? 'bg-yellow-500' : 'bg-red-500',
                )}
              />
            </span>
            <span className="text-xs font-medium">
              {health ? (online ? 'All systems normal' : degraded ? 'Degraded' : 'Offline') : 'Checking…'}
            </span>
          </div>
          <div className="mt-2 space-y-1 text-[10px] text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>Model</span>
              <span className={health?.model?.loaded ? 'text-emerald-400' : 'text-red-400'}>
                {health?.model?.loaded ? 'loaded' : 'unavailable'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Explanations</span>
              <span className="text-foreground/80">{health?.ai?.enabled ? health.ai.provider : 'built-in'}</span>
            </div>
          </div>
        </div>
        <div className="mt-2 flex items-center gap-1.5 px-1 text-[10px] text-muted-foreground">
          <Gauge className="h-3 w-3" />
          <span>Defensive monitoring only</span>
        </div>
      </div>
    </aside>
  )
}

export function SidebarIconLegend() {
  return <Activity className="hidden" />
}
