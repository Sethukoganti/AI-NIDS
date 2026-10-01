import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import type { HealthResponse } from '@/lib/types'

/**
 * Polls /api/health so the sidebar status indicator reflects the real backend
 * state (the green dot is only shown when the API actually reports healthy).
 */
export function useHealth(intervalMs = 30_000) {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const data = await api.get<HealthResponse>('/health')
        if (active) {
          setHealth(data)
          setError(null)
        }
      } catch (err) {
        if (active) setError((err as Error).message)
      }
    }
    load()
    const timer = setInterval(load, intervalMs)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [intervalMs])

  return { health, error }
}
