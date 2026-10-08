import { cleanup, render, screen } from '@testing-library/react'
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
})
