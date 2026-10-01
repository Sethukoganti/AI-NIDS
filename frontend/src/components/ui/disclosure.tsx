import { useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/format'

/**
 * Collapsible section used to keep the default view simple: the important
 * content is always visible, deeper detail lives one click away.
 */
export function Disclosure({
  title,
  hint,
  children,
  defaultOpen = false,
  className,
}: {
  title: string
  hint?: string
  children: ReactNode
  defaultOpen?: boolean
  className?: string
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <section className={cn('card overflow-hidden', className)}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/30"
      >
        <span className="min-w-0">
          <span className="block text-sm font-medium">{title}</span>
          {hint && <span className="mt-0.5 block text-[11px] text-muted-foreground">{hint}</span>}
        </span>
        <ChevronDown
          className={cn('h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-300', open && 'rotate-180')}
        />
      </button>
      <div className={cn('disclosure-body', open && 'disclosure-body-open')}>
        <div className="min-h-0 overflow-hidden">
          <div className="border-t border-border/60 p-4">{children}</div>
        </div>
      </div>
    </section>
  )
}
