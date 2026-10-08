import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from '@/App'
import { AuthProvider } from '@/context/AuthContext'
import { MemoryRouter } from 'react-router-dom'

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('application routes', () => {
  afterEach(() => {
    cleanup()
    localStorage.clear()
    vi.unstubAllGlobals()
  })

  it.each([
    ['/capture', 'Live Network Capture'],
    ['/simulation', 'Attack Simulation'],
    ['/dashboard', 'Overview'],
    ['/detections', 'Detection Results'],
    ['/notifications', 'Security Notifications'],
    ['/settings', 'Access denied'],
  ])('renders the page at %s', async (path, heading) => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('backend unavailable')))

    renderApp(path)

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
  })

  it('opens the sign-in page at the root route', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('backend unavailable')))

    renderApp('/')

    expect(await screen.findByRole('heading', { name: /sign in to ai-nids/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('offers PDF export from detection results', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('backend unavailable')))

    renderApp('/detections')

    expect(await screen.findByRole('button', { name: /save pdf/i })).toBeInTheDocument()
  })

  it('signs out the current user and returns to sign-in', async () => {
    const user = { id: 'admin', name: 'Admin', email: 'admin@example.test', role: 'admin' }
    localStorage.setItem('ai-nids.token', 'test-token')
    localStorage.setItem('ai-nids.user', JSON.stringify(user))
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const path = String(input)
      const payload = path.endsWith('/auth/me') ? user : {}
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(payload),
      }
    }))

    renderApp('/capture')

    fireEvent.click(await screen.findByRole('button', { name: /sign out/i }))

    expect(await screen.findByRole('heading', { name: /sign in to ai-nids/i })).toBeInTheDocument()
    expect(localStorage.getItem('ai-nids.token')).toBeNull()
    expect(localStorage.getItem('ai-nids.user')).toBeNull()
  })
})
