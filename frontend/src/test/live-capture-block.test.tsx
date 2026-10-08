import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '@/context/AuthContext'
import { api } from '@/lib/api'
import { LiveCapture } from '@/pages/LiveCapture'
import { Simulation } from '@/pages/Simulation'

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>()
  return {
    ...actual,
    api: {
      get: vi.fn(async (path: string) => {
      if (path === '/auth/config') return {}
      if (path === '/auth/me') {
        const role = localStorage.getItem('test-role') ?? 'admin'
        return { id: role, role, name: role === 'admin' ? 'Admin' : 'Analyst' }
      }
      if (path === '/capture/status') {
        return {
          agent_running: false,
          interface: null,
          packet_count: 0,
          flow_count: 0,
          queue_depth: 0,
          error: null,
          model_ready: true,
          npcap_installed: true,
        }
      }
      if (path === '/capture/interfaces') {
        return { interfaces: [{ name: 'test0', description: 'Test interface', ips: [] }] }
      }
      throw new Error(`Unexpected GET ${path}`)
      }),
      post: vi.fn(async (path: string) => {
      if (path === '/capture/start') return { started: true }
      if (path === '/capture/stop') {
        return {
          agent_running: false,
          interface: 'test0',
          packet_count: 1,
          flow_count: 1,
          queue_depth: 0,
          error: null,
          model_ready: true,
          npcap_installed: true,
        }
      }
      if (path === '/admin/network/blocks') return { rule: { id: 'capture-rule-id' } }
      throw new Error(`Unexpected POST ${path}`)
      }),
      del: vi.fn(async () => ({})),
    },
    streamSse: vi.fn(async (_path: string, handlers: { onEvent: (event: string, data: unknown) => void }) => {
      handlers.onEvent('flow', {
        index: 1,
        prediction: 'Port Scan',
        confidence: 0.98,
        is_attack: true,
        risk_level: 'high',
        risk_score: 0.9,
        source_ip: localStorage.getItem('test-source-ip'),
      })
      handlers.onEvent('flow', {
        index: 2,
        prediction: 'DDoS',
        confidence: 0.99,
        is_attack: true,
        risk_level: 'high',
        risk_score: 0.95,
        source_ip: localStorage.getItem('test-source-ip'),
      })
      handlers.onEvent('flow', {
        index: 3,
        prediction: 'Normal Traffic',
        confidence: 0.99,
        is_attack: false,
        risk_level: 'low',
        risk_score: 0.01,
        source_ip: localStorage.getItem('test-source-ip'),
      })
    }),
  }
})

describe('live capture block-intrusion counter', () => {
  afterEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('marks an IP-less intrusion blocked, shows the count, and confirms remove actions', async () => {
    localStorage.setItem('ai-nids.token', 'test-token')

    render(
      <AuthProvider>
        <LiveCapture />
      </AuthProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: 'Start live capture' }))
    fireEvent.click((await screen.findAllByRole('button', { name: 'Block intrusion' }))[0])

    expect(await screen.findByRole('button', { name: /blocked: 1/i })).toBeInTheDocument()
    expect(await screen.findByText(/Blocked the following intrusion:/)).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalledWith('/admin/network/blocks', expect.anything())

    fireEvent.click(screen.getByRole('button', { name: /blocked: 1/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Unblock intrusion' }))
    expect(screen.queryByRole('button', { name: 'Unblock intrusion' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Block intrusion' }).length).toBeGreaterThan(0)

    fireEvent.click(screen.getAllByRole('button', { name: 'Remove connection from list' })[0])
    expect(await screen.findByText(/Removed the following intrusion:/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /removed: 1/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Restore removed connection' }))
    expect(screen.queryByRole('button', { name: 'Restore removed connection' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Remove connection from list' }).length).toBeGreaterThan(0)

    fireEvent.click(screen.getAllByRole('button', { name: 'Block intrusion' })[0])
    expect(await screen.findByRole('button', { name: /blocked: 1/i })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Stop & view results' }))

    await waitFor(() => {
      const summaryCounter = screen.getByText('Blocked intrusions').parentElement
      expect(summaryCounter).not.toBeNull()
      expect(within(summaryCounter as HTMLElement).getByText('1')).toBeInTheDocument()
    })
  })

  it.each([
    { surface: 'live capture', Page: LiveCapture, startButton: 'Start live capture' },
    { surface: 'simulation', Page: Simulation, startButton: 'Run simulation' },
  ])('hides remove and block actions from analysts in $surface', async ({ Page, startButton }) => {
    localStorage.setItem('ai-nids.token', 'test-token')
    localStorage.setItem('test-role', 'analyst')

    render(
      <AuthProvider>
        <Page />
      </AuthProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: startButton }))

    expect(await screen.findByText(/Port Scan/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Block intrusion' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove connection from list' })).not.toBeInTheDocument()
  })

  it('lets an analyst open threat and normal-flow lists without admin actions', async () => {
    localStorage.setItem('ai-nids.token', 'test-token')
    localStorage.setItem('test-role', 'analyst')

    render(
      <AuthProvider>
        <LiveCapture />
      </AuthProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: 'Start live capture' }))
    fireEvent.click(await screen.findByRole('button', { name: /normal: 1/i }))
    expect(await screen.findByText('Normal Traffic')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /blocked:/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /removed:/i })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Show all flows' }))
    fireEvent.click(screen.getByRole('button', { name: /threats: 2/i }))
    expect((await screen.findAllByText(/Port Scan/)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Block intrusion' })).not.toBeInTheDocument()
  })

  it('lets an admin inspect, unblock, and restore simulation flows', async () => {
    localStorage.setItem('ai-nids.token', 'test-token')

    render(
      <AuthProvider>
        <Simulation />
      </AuthProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: 'Run simulation' }))
    fireEvent.click(await screen.findByRole('button', { name: /threats found/i }))
    expect((await screen.findAllByText(/Port Scan/)).length).toBeGreaterThan(0)

    fireEvent.click(screen.getAllByRole('button', { name: 'Block intrusion' })[0])
    fireEvent.click(await screen.findByRole('button', { name: /blocked intrusions/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Unblock intrusion' }))
    expect(screen.queryByRole('button', { name: 'Unblock intrusion' })).not.toBeInTheDocument()

    fireEvent.click(screen.getAllByRole('button', { name: 'Remove connection from list' })[0])
    fireEvent.click(await screen.findByRole('button', { name: /removed connections/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Restore removed connection' }))
    expect(screen.queryByRole('button', { name: 'Restore removed connection' })).not.toBeInTheDocument()
  })

  it('releases the created analysis policy when unblocking an IP-backed capture flow', async () => {
    localStorage.setItem('ai-nids.token', 'test-token')
    localStorage.setItem('test-source-ip', '192.0.2.10')

    render(
      <AuthProvider>
        <LiveCapture />
      </AuthProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: 'Start live capture' }))
    fireEvent.click((await screen.findAllByRole('button', { name: 'Block intrusion' }))[0])
    fireEvent.click(await screen.findByRole('button', { name: /blocked: 1/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Unblock intrusion' }))

    await waitFor(() => {
      expect(api.del).toHaveBeenCalledWith('/admin/network/blocks/capture-rule-id')
    })
  })
})
