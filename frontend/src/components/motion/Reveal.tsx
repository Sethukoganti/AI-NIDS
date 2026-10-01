import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cn } from '@/lib/format'

/**
 * Fade/slide an element in when it scrolls into view.
 *
 * Pure CSS animation driven by an IntersectionObserver — no animation library,
 * and the whole thing collapses to "just show it" when the user prefers reduced
 * motion (the CSS side handles that).
 */
export function Reveal({
  children,
  delay = 0,
  className,
  as: Tag = 'div',
}: {
  children: ReactNode
  delay?: number
  className?: string
  as?: 'div' | 'section' | 'li'
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const node = ref.current
    if (!node) return
    if (typeof IntersectionObserver === 'undefined') {
      setVisible(true)
      return
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setVisible(true)
            observer.disconnect()
          }
        }
      },
      { rootMargin: '0px 0px -40px 0px', threshold: 0.05 },
    )
    observer.observe(node)
    return () => observer.disconnect()
  }, [])

  return (
    <Tag
      ref={ref as never}
      className={cn('reveal', visible && 'reveal-visible', className)}
      style={{ animationDelay: visible ? `${delay}ms` : undefined }}
    >
      {children}
    </Tag>
  )
}

/** Staggered list wrapper: `Reveal` each child with an increasing delay. */
export function RevealGroup({
  children,
  step = 60,
  className,
}: {
  children: ReactNode[]
  step?: number
  className?: string
}) {
  return (
    <div className={cn(className)}>
      {children.map((child, index) => (
        <Reveal key={index} delay={Math.min(index * step, 360)}>
          {child}
        </Reveal>
      ))}
    </div>
  )
}
