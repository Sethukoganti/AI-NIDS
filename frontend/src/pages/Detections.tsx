import { useEffect, useState } from 'react'
import { AlertTriangle, ScrollText } from 'lucide-react'
import { HubTabs } from '@/components/layout/HubTabs'
import { PageHeader } from '@/components/common'
import { Alerts } from '@/pages/Alerts'
import { Predictions } from '@/pages/Predictions'
import { api } from '@/lib/api'

/**
 * One place for "what did the model flag": individual flow verdicts and the
 * aggregated alert queue sit behind two tabs instead of two sidebar entries.
 */
export function Detections() {
  const [counts, setCounts] = useState<{ flows?: number; alerts?: number }>({})

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.get<{ total: number }>('/predictions?page_size=1&verdict=attack').catch(() => ({ total: 0 })),
      api.get<{ total: number }>('/alerts?page_size=1').catch(() => ({ total: 0 })),
    ]).then(([flows, alerts]) => {
      if (!cancelled) setCounts({ flows: flows.total, alerts: alerts.total })
    })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <>
      <PageHeader
        title="Detections"
        subtitle="Every flow the Random Forest flagged, and the alert queue built from them. Open any row and press Why? to see the per-feature explanation."
      />
      <HubTabs
        defaultTab="flows"
        tabs={[
          {
            id: 'flows',
            label: 'Flagged flows',
            icon: <ScrollText className="h-3.5 w-3.5" />,
            badge: counts.flows,
            content: <Predictions />,
          },
          {
            id: 'alerts',
            label: 'Alert queue',
            icon: <AlertTriangle className="h-3.5 w-3.5" />,
            badge: counts.alerts,
            content: <Alerts />,
          },
        ]}
      />
    </>
  )
}
