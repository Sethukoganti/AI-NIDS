import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { attackColor, RISK_COLORS } from '@/lib/format'
import type { RiskLevel, TimelinePoint } from '@/lib/types'

const AXIS = { stroke: '#64748b', fontSize: 11 }
const GRID = { stroke: '#1e293b', strokeDasharray: '3 3' }

const tooltipStyle = {
  contentStyle: {
    background: '#0b1220',
    border: '1px solid #1e293b',
    borderRadius: 10,
    fontSize: 12,
    color: '#e2e8f0',
  },
  labelStyle: { color: '#94a3b8', fontSize: 11 },
}

export function NormalVsSuspiciousDonut({
  normal,
  suspicious,
}: {
  normal: number
  suspicious: number
}) {
  const data = [
    { name: 'Normal', value: normal },
    { name: 'Suspicious', value: suspicious },
  ]
  const total = normal + suspicious
  if (!total) return <EmptyChart label="No traffic analysed yet" />
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius={58}
          outerRadius={86}
          paddingAngle={3}
          stroke="#0b1220"
        >
          <Cell fill="#22c55e" />
          <Cell fill="#f97316" />
        </Pie>
        <Tooltip {...tooltipStyle} formatter={(value: number, name: string) => [`${value.toLocaleString()} flows`, name]} />
        <Legend
          verticalAlign="bottom"
          iconType="circle"
          formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function TrafficOverTime({ points }: { points: TimelinePoint[] }) {
  if (!points.length) return <EmptyChart label="No timeline data for this window" />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={points} margin={{ top: 6, right: 10, left: -18, bottom: 0 }}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="label" {...AXIS} tickLine={false} />
        <YAxis {...AXIS} tickLine={false} allowDecimals={false} />
        <Tooltip {...tooltipStyle} />
        <Legend
          verticalAlign="top"
          height={26}
          iconType="circle"
          formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{value}</span>}
        />
        <Line type="monotone" dataKey="total" name="Total flows" stroke="#22d3ee" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="suspicious" name="Suspicious" stroke="#f97316" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="alerts" name="Alerts" stroke="#ef4444" strokeWidth={1.5} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  )
}

export function AttackDistributionBar({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10)
  if (!rows.length) return <EmptyChart label="No suspicious traffic detected" />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={rows} margin={{ top: 6, right: 12, left: -18, bottom: 4 }}>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="name" {...AXIS} tickLine={false} interval={0} angle={-18} textAnchor="end" height={54} />
        <YAxis {...AXIS} tickLine={false} allowDecimals={false} />
        <Tooltip {...tooltipStyle} formatter={(value: number) => [`${value.toLocaleString()} flows`, 'Detected']} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {rows.map((row) => (
            <Cell key={row.name} fill={attackColor(row.name)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function RiskDistributionBars({ data }: { data: Record<string, number> }) {
  const rows = (['low', 'medium', 'high', 'critical'] as RiskLevel[]).map((level) => ({
    name: level.charAt(0).toUpperCase() + level.slice(1),
    key: level,
    value: data?.[level] ?? 0,
  }))
  const total = rows.reduce((sum, r) => sum + r.value, 0)
  if (!total) return <EmptyChart label="No risk data for this window" />
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 16, left: -8, bottom: 0 }}>
        <CartesianGrid {...GRID} horizontal={false} />
        <XAxis type="number" {...AXIS} allowDecimals={false} tickLine={false} />
        <YAxis type="category" dataKey="name" {...AXIS} width={70} tickLine={false} />
        <Tooltip {...tooltipStyle} formatter={(value: number) => [`${value.toLocaleString()} flows`, 'Records']} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18}>
          {rows.map((row) => (
            <Cell key={row.key} fill={RISK_COLORS[row.key as RiskLevel]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function FeatureImportanceChart({
  data,
  height = 300,
}: {
  data: { feature: string; importance: number }[]
  height?: number
}) {
  if (!data.length) return <EmptyChart label="Feature importances unavailable" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, left: 150, bottom: 0 }}>
        <CartesianGrid {...GRID} horizontal={false} />
        <XAxis type="number" {...AXIS} tickLine={false} tickFormatter={(v) => Number(v).toFixed(2)} />
        <YAxis type="category" dataKey="feature" {...AXIS} width={148} tickLine={false} />
        <Tooltip
          {...tooltipStyle}
          formatter={(value: number) => [value.toFixed(5), 'Importance (Gini)']}
        />
        <Bar dataKey="importance" fill="#22d3ee" radius={[0, 3, 3, 0]} barSize={12} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function ClassPerformanceChart({
  perClass,
}: {
  perClass: Record<string, { precision: number; recall: number; f1: number; support: number }>
}) {
  const rows = Object.entries(perClass).map(([name, m]) => ({
    name,
    precision: Number((m.precision * 100).toFixed(2)),
    recall: Number((m.recall * 100).toFixed(2)),
    f1: Number((m.f1 * 100).toFixed(2)),
    support: m.support,
  }))
  if (!rows.length) return <EmptyChart label="Evaluation data unavailable" />
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={rows} margin={{ top: 6, right: 12, left: -18, bottom: 40 }}>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="name" {...AXIS} tickLine={false} angle={-20} textAnchor="end" height={70} interval={0} />
        <YAxis {...AXIS} domain={[0, 100]} tickLine={false} unit="%" />
        <Tooltip {...tooltipStyle} formatter={(value: number) => [`${value}%`, '']} />
        <Legend
          verticalAlign="top"
          height={26}
          iconType="circle"
          formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{value}</span>}
        />
        <Bar dataKey="precision" name="Precision" fill="#22d3ee" radius={[3, 3, 0, 0]} />
        <Bar dataKey="recall" name="Recall" fill="#22c55e" radius={[3, 3, 0, 0]} />
        <Bar dataKey="f1" name="F1" fill="#a855f7" radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function ShapWaterfall({
  contributions,
  limit = 8,
}: {
  contributions: { feature: string; shap_value: number; value: number; impact_pct: number }[]
  limit?: number
}) {
  const rows = [...contributions]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, limit)
    .map((c) => ({
      feature: c.feature,
      impact: Number((c.impact_pct).toFixed(1)),
      signed: c.shap_value > 0 ? c.impact_pct : -c.impact_pct,
      direction: c.shap_value > 0 ? 'towards attack class' : 'towards normal traffic',
      value: c.value,
    }))
  const max = Math.max(...rows.map((r) => Math.abs(r.signed)), 1)
  return (
    <div className="space-y-2">
      {rows.map((row) => (
        <div key={row.feature} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3">
          <div className="min-w-0">
            <div className="truncate text-xs text-foreground/90">{row.feature}</div>
            <div className="text-[10px] text-muted-foreground">
              value {row.value.toLocaleString(undefined, { maximumFractionDigits: 4 })} · {row.direction}
            </div>
          </div>
          <div className="flex w-40 items-center gap-2 sm:w-56">
            <div className="relative h-2.5 flex-1 overflow-hidden rounded-full bg-muted/60">
              <div
                className={`absolute inset-y-0 ${row.signed >= 0 ? 'left-1/2 bg-orange-500/80' : 'right-1/2 bg-emerald-500/80'}`}
                style={{ width: `${(Math.abs(row.signed) / max) * 50}%` }}
              />
              <div className="absolute inset-y-0 left-1/2 w-px bg-border" />
            </div>
            <span className="w-11 text-right text-[11px] tabular-nums text-muted-foreground">{row.impact}%</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export function EmptyChart({ label }: { label: string }) {
  return (
    <div className="grid h-[200px] place-items-center rounded-lg border border-dashed border-border/70 text-xs text-muted-foreground">
      {label}
    </div>
  )
}
