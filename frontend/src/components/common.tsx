import { createElement, isValidElement, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, Info, Loader2, ShieldAlert, type LucideIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { cn, RISK_BADGE } from '@/lib/format'
import { useCountUp } from '@/hooks/useCountUp'
import type { RiskLevel } from '@/lib/types'

export function PageHeader({
  title,
  subtitle,
  actions,
  icon: Icon,
}: {
  title: string
  subtitle?: ReactNode
  actions?: ReactNode
  icon?: LucideIcon
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="flex items-start gap-3">
        {Icon && (
          <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
            <Icon className="h-4.5 w-4.5" />
          </span>
        )}
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1 max-w-3xl text-xs leading-relaxed text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function StatCard({
  label,
  title,
  value,
  hint,
  icon,
  tone = 'default',
  countTo,
  formatCount,
}: {
  label?: string
  title?: string
  value?: ReactNode
  hint?: ReactNode
  icon?: ReactNode | LucideIcon
  tone?: 'default' | 'good' | 'warn' | 'bad' | 'info'
  /** when provided, the number animates up from 0 instead of appearing at once */
  countTo?: number
  formatCount?: (value: number) => string
}) {
  const tones = {
    default: 'text-foreground',
    good: 'text-emerald-400',
    warn: 'text-yellow-400',
    bad: 'text-red-400',
    info: 'text-primary',
  }
  const animated = useCountUp(countTo)
  const shown = countTo !== undefined ? (formatCount ? formatCount(animated) : Math.round(animated)) : value
  const iconContent = icon
    ? isValidElement(icon)
      ? icon
      : createElement(icon as LucideIcon, { className: 'h-4 w-4' })
    : null

  return (
    <Card className="card-hover p-4">
      <div className="flex items-start justify-between gap-2">
        <span className="label-xs">{label ?? title}</span>
        {iconContent && <span className="text-muted-foreground/70">{iconContent}</span>}
      </div>
      <div className={cn('metric-value mt-2', tones[tone])}>{shown}</div>
      {hint && <div className="mt-1 text-[11px] leading-snug text-muted-foreground">{hint}</div>}
    </Card>
  )
}

export function RiskBadge({ level, className }: { level: RiskLevel | string; className?: string }) {
  const key = (level as RiskLevel) ?? 'low'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide',
        RISK_BADGE[key] ?? RISK_BADGE.low,
        className,
      )}
    >
      {key === 'critical' && <ShieldAlert className="h-3 w-3" />}
      {key}
    </span>
  )
}

export function VerdictBadge({ isAttack, label }: { isAttack: boolean; label: string }) {
  return (
    <Badge variant={isAttack ? 'danger' : 'success'} className="font-medium">
      {label}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { variant: 'success' | 'warning' | 'secondary' | 'danger' | 'default'; label: string }> = {
    new: { variant: 'warning', label: 'NEW' },
    reviewed: { variant: 'default', label: 'REVIEWED' },
    resolved: { variant: 'success', label: 'RESOLVED' },
    completed: { variant: 'success', label: 'COMPLETED' },
    running: { variant: 'warning', label: 'RUNNING' },
    queued: { variant: 'secondary', label: 'QUEUED' },
    failed: { variant: 'danger', label: 'FAILED' },
    ready: { variant: 'success', label: 'READY' },
    reference: { variant: 'secondary', label: 'REFERENCE' },
  }
  const config = map[status] ?? { variant: 'secondary' as const, label: status.toUpperCase() }
  return <Badge variant={config.variant}>{config.label}</Badge>
}

export function Alert({
  variant = 'info',
  title,
  children,
}: {
  variant?: 'info' | 'warn' | 'error' | 'success'
  title?: string
  children: ReactNode
}) {
  const styles = {
    info: 'border-primary/30 bg-primary/5 text-primary',
    warn: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-300',
    error: 'border-red-500/30 bg-red-500/5 text-red-300',
    success: 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300',
  }
  const icons = {
    info: <Info className="mt-0.5 h-4 w-4 shrink-0" />,
    warn: <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />,
    error: <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />,
    success: <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />,
  }
  return (
    <div className={cn('flex gap-2.5 rounded-lg border p-3 text-xs leading-relaxed', styles[variant])}>
      {icons[variant]}
      <div className="min-w-0">
        {title && <div className="mb-0.5 font-semibold">{title}</div>}
        <div className="text-foreground/80">{children}</div>
      </div>
    </div>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-xs text-muted-foreground">
      <Loader2 className="h-3.5 w-3.5 animate-spin" />
      {label}
    </div>
  )
}

export function KeyValue({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/50 py-1.5 last:border-0">
      <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className={cn('text-right text-xs text-foreground/90', mono && 'font-mono')}>{value}</span>
    </div>
  )
}

export function NoData({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="grid place-items-center gap-1 rounded-lg border border-dashed border-border/70 p-8 text-center">
      <p className="text-sm text-foreground/80">{title}</p>
      {hint && <p className="max-w-md text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}
