import { fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { ThreatFeed, type ScoredFlow } from '@/components/ThreatFeed'

const initialFlows: ScoredFlow[] = [
  {
    index: 1,
    prediction: 'Port Scan',
    confidence: 0.98,
    is_attack: true,
    risk_level: 'high',
    risk_score: 0.9,
    source_ip: '192.0.2.10',
  },
  {
    index: 2,
    prediction: 'Normal Traffic',
    confidence: 0.99,
    is_attack: false,
    risk_level: 'low',
    risk_score: 0.01,
    source_ip: '192.0.2.20',
  },
]

function RemovableThreatFeed() {
  const [flows, setFlows] = useState(initialFlows)
  const [removedThreats, setRemovedThreats] = useState(0)

  return (
    <ThreatFeed
      flows={flows}
      streaming
      total={2}
      suspicious={flows.filter(flow => flow.is_attack).length}
      removedThreats={removedThreats}
      onRemoveFlow={flow => {
        setFlows(current => current.filter(item => item.index !== flow.index))
        if (flow.is_attack) setRemovedThreats(count => count + 1)
      }}
    />
  )
}

describe('ThreatFeed remove action', () => {
  it('removes only the selected detection from the displayed list', () => {
    render(<RemovableThreatFeed />)

    fireEvent.click(screen.getAllByRole('button', { name: 'Remove connection from list' })[0])

    expect(screen.queryByText('Port Scan')).not.toBeInTheDocument()
    expect(screen.getByText(/192\.0\.2\.20/)).toBeInTheDocument()
    expect(screen.getByText(/0 threats remain in 2 analysed flows; 0 blocked and 1 removed from this list/)).toBeInTheDocument()
  })

  it('offers remove controls for safe and malicious connections', () => {
    render(<RemovableThreatFeed />)

    expect(screen.getAllByRole('button', { name: 'Remove connection from list' })).toHaveLength(2)
  })
})

function BlockableThreatFeed({ sourceIp = '192.0.2.10' }: { sourceIp?: string | null }) {
  const [blockedThreats, setBlockedThreats] = useState<number[]>([])
  const [blockedCount, setBlockedCount] = useState(0)

  const flows = [{ ...initialFlows[0], source_ip: sourceIp }]

  return (
    <>
      <p>Blocked intrusions: {blockedCount}</p>
      <ThreatFeed
        flows={flows}
        streaming
        total={1}
        suspicious={1}
        onBlockIntrusion={flow => {
          setBlockedThreats(current => [...new Set([...current, flow.index])])
          setBlockedCount(count => count + 1)
        }}
        blockedThreatIndexes={blockedThreats}
      />
    </>
  )
}

describe('ThreatFeed block-intrusion action', () => {
  it('marks the intrusion blocked and increments the count', () => {
    render(<BlockableThreatFeed />)

    fireEvent.click(screen.getByRole('button', { name: 'Block intrusion' }))

    expect(screen.getByText('Blocked intrusions: 1')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Intrusion blocked' })).toBeDisabled()
  })

  it('allows blocking a flow without a source IP', () => {
    render(<BlockableThreatFeed sourceIp={null} />)

    expect(screen.getByRole('button', { name: 'Block intrusion' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Block intrusion' }))

    expect(screen.getByRole('button', { name: 'Intrusion blocked' })).toBeDisabled()
    expect(screen.getByText('Blocked intrusions: 1')).toBeInTheDocument()
  })
})
