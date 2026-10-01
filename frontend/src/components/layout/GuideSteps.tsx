import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { cn } from '@/lib/format'

export interface GuideStep {
  icon: ReactNode
  title: string
  body: string
  to: string
  cta: string
  done?: boolean
}

/**
 * "Start here" strip: the three things a new user actually needs, in order.
 * Driven by real data (step 2 is ticked once detections exist).
 */
export function GuideSteps({ steps, className }: { steps: GuideStep[]; className?: string }) {
  return (
    <div className={cn('grid gap-3 md:grid-cols-3', className)}>
      {steps.map((step, index) => (
        <Link
          key={step.title}
          to={step.to}
          className="card group relative flex flex-col gap-2 p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-primary/50 hover:shadow-[0_10px_40px_-20px_rgba(34,211,238,0.5)]"
          style={{ animationDelay: `${index * 70}ms` }}
        >
          <div className="flex items-center gap-2">
            <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary/30 bg-primary/10 text-primary transition-transform duration-300 group-hover:scale-110">
              {step.icon}
            </span>
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Step {index + 1}
            </span>
            {step.done && (
              <span className="ml-auto rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                ready
              </span>
            )}
          </div>
          <div className="text-sm font-semibold">{step.title}</div>
          <p className="text-[11px] leading-relaxed text-muted-foreground">{step.body}</p>
          <span className="mt-auto inline-flex items-center gap-1 text-[11px] font-medium text-primary">
            {step.cta}
            <ArrowRight className="h-3 w-3 transition-transform duration-300 group-hover:translate-x-1" />
          </span>
        </Link>
      ))}
    </div>
  )
}
