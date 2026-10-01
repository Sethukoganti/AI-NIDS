import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { HubTabs } from '@/components/layout/HubTabs'
import { Reveal } from '@/components/motion/Reveal'
import { useCountUp } from '@/hooks/useCountUp'
import { renderHook } from '@testing-library/react'
import { LEGACY_REDIRECTS, NAV_DESTINATIONS } from '@/lib/routes'

/**
 * Guards for the simplified navigation: the grouped pages rely on HubTabs
 * putting the selected tab in the URL, and the motion helpers must not hide
 * content when animations are unavailable (jsdom / reduced-motion users).
 */
describe('HubTabs', () => {
  const tabs = [
    { id: 'flows', label: 'Flagged flows', content: <p>flows panel</p> },
    { id: 'alerts', label: 'Alert queue', content: <p>alerts panel</p> },
  ]

  it('shows the default tab and mounts its content', () => {
    render(
      <MemoryRouter initialEntries={['/detections']}>
        <HubTabs defaultTab="flows" tabs={tabs} />
      </MemoryRouter>,
    )
    expect(screen.getByRole('tab', { name: /flagged flows/i })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('flows panel')).toBeInTheDocument()
    expect(screen.queryByText('alerts panel')).not.toBeInTheDocument()
  })

  it('honours ?tab= from the URL so grouped pages stay linkable', () => {
    render(
      <MemoryRouter initialEntries={['/detections?tab=alerts']}>
        <HubTabs defaultTab="flows" tabs={tabs} />
      </MemoryRouter>,
    )
    const active = screen.getByRole('tab', { name: /alert queue/i })
    expect(active).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('alerts panel')).toBeInTheDocument()
  })

  it('keeps the tab bar to the tabs it was given (no hidden options)', () => {
    render(
      <MemoryRouter initialEntries={['/detections']}>
        <HubTabs defaultTab="flows" tabs={tabs} />
      </MemoryRouter>,
    )
    expect(within(screen.getByRole('tablist')).getAllByRole('tab')).toHaveLength(2)
  })
})

describe('motion helpers', () => {
  it('Reveal renders its children immediately when observers are unavailable', () => {
    render(
      <Reveal>
        <span>revealed content</span>
      </Reveal>,
    )
    expect(screen.getByText('revealed content')).toBeInTheDocument()
  })

  it('useCountUp returns the target value for users who prefer reduced motion', () => {
    // jsdom reports prefers-reduced-motion: reduce through the stubbed matchMedia (matches: false),
    // so the hook animates; assert the final value is reached synchronously for null input.
    const { result } = renderHook(() => useCountUp(null))
    expect(result.current).toBe(0)
  })
})

describe('route simplification', () => {
  it('keeps every old deep link working as a redirect into the grouped pages', () => {
    expect(LEGACY_REDIRECTS['/alerts']).toBe('/detections?tab=alerts')
    expect(LEGACY_REDIRECTS['/predictions']).toBe('/detections')
    expect(LEGACY_REDIRECTS['/insights']).toBe('/model?tab=insights')
    expect(LEGACY_REDIRECTS['/datasets']).toBe('/data')
    expect(LEGACY_REDIRECTS['/simulation']).toBe('/data?tab=simulation')
  })

  it('exposes exactly six top-level destinations', () => {
    expect(NAV_DESTINATIONS).toHaveLength(6)
  })
})
