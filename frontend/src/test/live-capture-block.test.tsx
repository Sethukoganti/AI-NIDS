import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '@/context/AuthContext'
import { api } from '@/lib/api'
import { LiveCapture } from '@/pages/LiveCapture'

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>()
  return {
    ...actual,
    api: {
      get: vi.fn(async (path: string) => {
      if (path === '/auth/config') return {}
      if (path === '/auth/me') return { id: 'admin', role: 'admin', name: 'Admin' }
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
      throw new Error(`Unexpected POST ${path}`)
      }),
    },
    streamSse: vi.fn(async (_path: string, handlers: { onEvent: (event: string, data: unknown) => void }) => {
      handlers.onEvent('flow', {
        index: 1,
        prediction: 'Port Scan',
        confidence: 0.98,
        is_attack: true,
        risk_level: 'high',
        risk_score: 0.9,
        source_ip: null,
      })
      handlers.onEvent('flow', {
        index: 2,
        prediction: 'DDoS',
        confidence: 0.99,
        is_attack: true,
        risk_level: 'high',
        risk_score: 0.95,
        source_ip: null,
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

    await waitFor(() => {
      const liveCounter = screen.getByText('Blocked intrusions:').parentElement
      expect(liveCounter).not.toBeNull()
      expect(within(liveCounter as HTMLElement).getByText('1')).toBeInTheDocument()
    })
    expect(await screen.findByText(/Blocked the following intrusion:/)).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalledWith('/admin/network/blocks', expect.anything())

    fireEvent.click(screen.getByRole('button', { name: 'Remove connection from list' }))
    expect(await screen.findByText(/Removed the following intrusion:/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Stop & view results' }))

    await waitFor(() => {
      const summaryCounter = screen.getByText('Blocked intrusions').parentElement
      expect(summaryCounter).not.toBeNull()
      expect(within(summaryCounter as HTMLElement).getByText('1')).toBeInTheDocument()
    })
  })
})
