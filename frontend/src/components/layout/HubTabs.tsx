import type { ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { cn } from '@/lib/format'

export interface HubTab {
  id: string
  label: string
  icon?: ReactNode
  /** small right-aligned counter/badge, e.g. how many alerts are waiting */
  badge?: ReactNode
  content: ReactNode
}

/**
 * Tab bar for the grouped pages (Detections / Model / Data).
 *
 * The selected tab lives in the URL (?tab=…) so every view is linkable and the
 * browser back button behaves the way users expect. Panels are keyed so the
 * content animates in on each switch.
 */
export function HubTabs({ tabs, defaultTab }: { tabs: HubTab[]; defaultTab?: string }) {
  const [params, setParams] = useSearchParams()
  const requested = params.get('tab')
  const active = tabs.find((tab) => tab.id === requested)?.id ?? defaultTab ?? tabs[0].id

  return (
    <div>
      <div
        role="tablist"
        className="mb-4 flex flex-wrap items-center gap-1 rounded-xl border border-border/70 bg-panel/60 p-1 backdrop-blur-sm"
      >
        {tabs.map((tab) => {
          const isActive = tab.id === active
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              onClick={() => {
                // keep any other query params the inner page relies on (e.g. ?verdict=attack)
                const next = new URLSearchParams(params)
                next.delete('tab')
                if (tab.id !== (defaultTab ?? tabs[0].id)) next.set('tab', tab.id)
                setParams(next, { replace: true })
              }}
              className={cn(
                'group relative flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-all duration-300',
                isActive
                  ? 'bg-primary/15 text-primary shadow-[inset_0_0_0_1px_rgba(34,211,238,0.25)]'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground',
              )}
            >
              {tab.icon}
              {tab.label}
              {tab.badge !== undefined && tab.badge !== null && (
                <span
                  className={cn(
                    'rounded-full px-1.5 py-0.5 text-[10px] tabular-nums transition-colors',
                    isActive ? 'bg-primary/20 text-primary' : 'bg-muted text-muted-foreground',
                  )}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          )
        })}
      </div>

      <div key={active} className="animate-page">
        {tabs.find((tab) => tab.id === active)?.content}
      </div>
    </div>
  )
}
