import { Brain, Sparkles } from 'lucide-react'
import { HubTabs } from '@/components/layout/HubTabs'
import { PageHeader } from '@/components/common'
import { Insights } from '@/pages/Insights'
import { ModelPage } from '@/pages/ModelPage'

/** Model card + measured evaluation + the AI insights layer in one place. */
export function ModelHub() {
  return (
    <>
      <PageHeader
        title="AI Model"
        subtitle="The actual Random Forest being used: hyper-parameters, measured test results, feature importance, and the explainability layer behind every verdict."
      />
      <HubTabs
        defaultTab="model"
        tabs={[
          { id: 'model', label: 'Model & metrics', icon: <Brain className="h-3.5 w-3.5" />, content: <ModelPage /> },
          { id: 'insights', label: 'AI insights', icon: <Sparkles className="h-3.5 w-3.5" />, content: <Insights /> },
        ]}
      />
    </>
  )
}
