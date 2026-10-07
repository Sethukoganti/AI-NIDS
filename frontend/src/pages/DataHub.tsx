import { Database, Radio, Wifi } from 'lucide-react'
import { HubTabs } from '@/components/layout/HubTabs'
import { PageHeader } from '@/components/common'
import { Datasets } from '@/pages/Datasets'
import { Simulation } from '@/pages/Simulation'
import { LiveCapture } from '@/pages/LiveCapture'

/** Uploaded datasets, the CICIDS2017 reference card, live simulation and live capture. */
export function DataHub() {
  return (
    <>
      <PageHeader
        title="Data"
        subtitle="Uploaded datasets, the CICIDS2017 reference capture, a replay simulation, and live packet capture."
      />
      <HubTabs
        defaultTab="datasets"
        tabs={[
          { id: 'datasets', label: 'Datasets', icon: <Database className="h-3.5 w-3.5" />, content: <Datasets /> },
          {
            id: 'simulation',
            label: 'Simulation',
            icon: <Radio className="h-3.5 w-3.5" />,
            content: <Simulation />,
          },
          {
            id: 'capture',
            label: 'Live Capture',
            icon: <Wifi className="h-3.5 w-3.5" />,
            content: <LiveCapture />,
          },
        ]}
      />
    </>
  )
}
