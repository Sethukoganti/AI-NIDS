import { useEffect, useRef, useState } from 'react'

/**
 * Animate a number from 0 to `value` with requestAnimationFrame (ease-out).
 * Used by the dashboard metric cards so numbers "settle" instead of snapping.
 */
export function useCountUp(value: number | null | undefined, durationMs = 700): number {
  const [display, setDisplay] = useState(value ?? 0)
  const fromRef = useRef(0)

  useEffect(() => {
    if (value === null || value === undefined || Number.isNaN(value)) {
      setDisplay(0)
      return
    }
    const reduce =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduce) {
      setDisplay(value)
      fromRef.current = value
      return
    }

    const from = fromRef.current
    const delta = value - from
    if (delta === 0) return

    let frame = 0
    const start = performance.now()
    const tick = (now: number) => {
      const progress = Math.min((now - start) / durationMs, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(from + delta * eased)
      if (progress < 1) frame = requestAnimationFrame(tick)
      else fromRef.current = value
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, durationMs])

  return display
}
