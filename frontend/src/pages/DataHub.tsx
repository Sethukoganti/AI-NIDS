import { Database, Radio } from 'lucide-react'
import { HubTabs } from '@/components/layout/HubTabs'
import { PageHeader } from '@/components/common'
import { Datasets } from '@/pages/Datasets'
import { Simulation } from '@/pages/Simulation'

/** Uploaded datasets, the CICIDS2017 reference card and the live simulation feed. */
export function DataHub() {
  return (
    <>
      <PageHeader
        title="Data"
        subtitle="What the model has been fed: your uploads, the full CICIDS2017 reference capture, and a replayed traffic stream for demos."
      />
      <HubTabs
        defaultTab="datasets"
        tabs={[
          { id: 'datasets', label: 'Datasets', icon: <Database className="h-3.5 w-3.5" />, content: <Datasets /> },
          {
            id: 'simulation',
            label: 'Live simulation',
            icon: <Radio className="h-3.5 w-3.5" />,
            content: <Simulation />,
          },
        ]}
      />
    </>
  )
}
