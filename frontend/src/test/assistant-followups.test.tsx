import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { App } from '@/App'

describe('floating assistant follow-up suggestions', () => {
  it('shows more question options after each answer', async () => {
    Object.defineProperty(HTMLElement.prototype, 'scrollTo', {
      configurable: true,
      value: () => undefined,
    })

    render(
      <MemoryRouter initialEntries={['/about']}>
        <App />
      </MemoryRouter>,
    )

    fireEvent.click(screen.getByTitle('Ask the AI assistant'))
    fireEvent.click(screen.getByRole('button', { name: 'What is this system?' }))

    expect(
      await screen.findByText(/This is an AI-powered Network Intrusion Detection System/),
    ).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'How does it detect threats?' }))

    expect(
      await screen.findByText(/Packets are captured via Npcap/),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'What is a Random Forest?' })).toBeInTheDocument()
  })
})
