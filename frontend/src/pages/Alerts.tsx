import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Download,
  Filter,
  Info,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Select } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert as InlineAlert, Loading, PageHeader, RiskBadge, StatCard, StatusBadge } from '@/components/common'
import { api, errorMessage, getToken, API_BASE } from '@/lib/api'
import { formatNumber, formatPercent, relativeTime } from '@/lib/format'
import type { Alert, AlertSummary } from '@/lib/types'

export function Alerts() {
  const [items, setItems] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [summary, setSummary] = useState<AlertSummary | null>(null)
  const [status, setStatus] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [updating, setUpdating] = useState(false)

  const load = useCallback(async () => {
    try {
      const qs = new URLSearchParams({
        status,
        page: String(page),
        page_size: '25',
      })
      if (severity !== 'all') qs.set('severity', severity)
      if (search) qs.set('search', search)
      const [pageData, summaryData] = await Promise.all([
        api.get<{ items: Alert[]; total: number; pages: number }>(`/alerts?${qs.toString()}`),
        api.get<AlertSummary>('/alerts/summary'),
      ])
      setItems(pageData.items)
      setTotal(pageData.total)
      setPages(pageData.pages)
      setSummary(summaryData)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [status, severity, search, page])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    const timer = setInterval(load, 30_000)
    return () => clearInterval(timer)
  }, [load])

  const exportCsv = () => {
    const qs = new URLSearchParams({ limit: '5000' })
    if (status !== 'all') qs.set('status', status)
    if (severity !== 'all') qs.set('severity', severity)
    if (search) qs.set('search', search)
    const url = `${API_BASE}/analyst/alerts/export?${qs.toString()}`
    const token = getToken()
    // Use a hidden anchor with Authorization via fetch + blob for auth header support
    fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then((res) => res.blob())
      .then((blob) => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `ai_nids_alerts_${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(a.href)
      })
      .catch(() => setError('Export failed. Please try again.'))
  }

  const updateStatus = async (alert: Alert, next: string) => {
    setUpdating(true)
    try {
      const updated = await api.patch<Alert>(`/alerts/${alert.id}`, { status: next })
      setItems((current) => current.map((item) => (item.id === alert.id ? updated : item)))
      setSelected(updated)
      const summaryData = await api.get<AlertSummary>('/alerts/summary')
      setSummary(summaryData)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setUpdating(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Alerts Center"
        subtitle={
          <>
            Alerts are generated only for flows the Random Forest classified as an attack family with a
            medium-or-higher risk score. Volume is controlled: the highest-risk flows raise individual
            alerts, the rest are aggregated per attack type and destination port, so a scan storm never
            floods the queue.
          </>
        }
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={exportCsv} disabled={total === 0}>
              <Download className="h-3.5 w-3.5" />
              Export CSV
            </Button>
            <Button variant="outline" size="sm" onClick={load}>
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Could not load alerts">
            {error}
          </InlineAlert>
        </div>
      )}

      {summary && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Total alerts"
            value={formatNumber(summary.total)}
            hint={`${summary.new ?? 0} awaiting triage`}
            icon={<ShieldAlert className="h-4 w-4" />}
            tone="info"
          />
          <StatCard
            label="Critical"
            value={formatNumber(summary.by_severity?.critical ?? 0)}
            hint="risk score ≥ 0.96"
            icon={<AlertTriangle className="h-4 w-4" />}
            tone="bad"
          />
          <StatCard
            label="High"
            value={formatNumber(summary.by_severity?.high ?? 0)}
            hint="risk score ≥ 0.85"
            icon={<AlertTriangle className="h-4 w-4" />}
            tone="warn"
          />
          <StatCard
            label="Open (high + critical)"
            value={formatNumber(summary.open_high_or_critical ?? 0)}
            hint={`${summary.by_status?.resolved ?? 0} resolved · ${
              summary.by_status?.reviewed ?? 0
            } reviewed`}
            icon={<CheckCheck className="h-4 w-4" />}
          />
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <div>
          <Card className="mb-3">
            <CardContent className="flex flex-wrap items-end gap-3 p-4">
              <div className="min-w-[140px] flex-1">
                <label className="label-xs mb-1 block">
                  <Filter className="mr-1 inline h-3 w-3" />
                  Status
                </label>
                <Select
                  value={status}
                  onChange={(e) => {
                    setStatus(e.target.value)
                    setPage(1)
                  }}
                >
                  {['all', 'open', 'new', 'reviewed', 'resolved'].map((value) => (
                    <option key={value} value={value}>
                      {value === 'all' ? 'All statuses' : value}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="min-w-[140px] flex-1">
                <label className="label-xs mb-1 block">Severity</label>
                <Select
                  value={severity}
                  onChange={(e) => {
                    setSeverity(e.target.value)
                    setPage(1)
                  }}
                >
                  {['all', 'critical', 'high', 'medium'].map((value) => (
                    <option key={value} value={value}>
                      {value === 'all' ? 'All severities' : value}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="min-w-[200px] flex-[1.5]">
                <label className="label-xs mb-1 block">Search</label>
                <Input
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  placeholder="attack type, port, message…"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-0">
              {loading && items.length === 0 ? (
                <Loading label="Loading alerts…" />
              ) : items.length === 0 ? (
                <p className="p-8 text-center text-xs text-muted-foreground">
                  No alerts match these filters. Analyse a dataset on the{' '}
                  <Link to="/analyzer" className="text-primary underline">
                    Traffic Analyzer
                  </Link>{' '}
                  to generate detections.
                </p>
              ) : (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Attack type</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Destination</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Message</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {items.map((alert) => (
                        <TableRow key={alert.id} className="cursor-pointer" onClick={() => setSelected(alert)}>
                          <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                            {relativeTime(alert.created_at)}
                          </TableCell>
                          <TableCell className="text-xs font-medium">{alert.attack_type}</TableCell>
                          <TableCell>
                            <RiskBadge level={alert.severity} />
                          </TableCell>
                          <TableCell className="mono">
                            {alert.destination_port ? `:${alert.destination_port}` : '—'}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {formatPercent(alert.confidence, 1)}
                          </TableCell>
                          <TableCell>
                            <StatusBadge status={alert.status} />
                          </TableCell>
                          <TableCell className="max-w-[280px] truncate text-xs text-muted-foreground">
                            {alert.message}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>

                  <div className="flex items-center justify-between gap-3 border-t border-border/60 p-3 text-xs text-muted-foreground">
                    <span>
                      {formatNumber(total)} alert(s) · page {page} of {pages}
                    </span>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={page <= 1}
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                      >
                        <ChevronLeft className="h-3.5 w-3.5" />
                        Prev
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={page >= pages}
                        onClick={() => setPage((p) => p + 1)}
                      >
                        Next
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          {/* What is an alert? — plain language explainer */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Info className="h-4 w-4 text-primary" />
                What is an alert?
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-[11px] leading-relaxed text-muted-foreground">
              <p>
                An alert is raised when the Random Forest classifies a flow as an attack with{' '}
                <span className="text-foreground font-medium">medium risk or higher</span>. Multiple flows
                of the same attack type hitting the same destination port are collapsed into one
                <span className="text-foreground font-medium"> "burst" alert</span> to avoid flooding the queue.
              </p>
              <div className="space-y-1.5">
                <div className="font-semibold text-foreground">Severity levels</div>
                <div className="flex items-center justify-between">
                  <RiskBadge level="critical" />
                  <span className="font-mono">risk score ≥ 0.96</span>
                </div>
                <div className="flex items-center justify-between">
                  <RiskBadge level="high" />
                  <span className="font-mono">score ≥ 0.85</span>
                </div>
                <div className="flex items-center justify-between">
                  <RiskBadge level="medium" />
                  <span className="font-mono">score ≥ 0.65</span>
                </div>
                <p className="pt-1">
                  Risk score = attack severity weight × model confidence, with a small bonus for sensitive ports (22, 80, 443…).
                </p>
              </div>
              <div className="space-y-1.5 border-t border-border/60 pt-3">
                <div className="font-semibold text-foreground">What to do with an alert</div>
                <div className="space-y-1">
                  {[
                    { status: 'new', action: 'Just created — needs triage' },
                    { status: 'reviewed', action: 'You looked at it' },
                    { status: 'investigating', action: 'Linked to an open investigation' },
                    { status: 'resolved', action: 'Confirmed and closed' },
                    { status: 'false_positive', action: 'Model was wrong on this one' },
                  ].map(({ status, action }) => (
                    <div key={status} className="flex items-center gap-2">
                      <StatusBadge status={status} />
                      <span>{action}</span>
                    </div>
                  ))}
                </div>
              </div>
              {summary && Object.keys(summary.by_attack_type ?? {}).length > 0 && (
                <div className="border-t border-border/60 pt-3">
                  <div className="font-semibold text-foreground mb-1.5">Current alert mix</div>
                  <div className="space-y-1">
                    {Object.entries(summary.by_attack_type ?? {})
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 6)
                      .map(([type, count]) => (
                        <div key={type} className="flex justify-between">
                          <span className="truncate">{type}</span>
                          <span className="font-mono text-foreground/80">{count}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <Dialog open={Boolean(selected)} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-2xl">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-2">
                  {selected.attack_type}
                  <RiskBadge level={selected.severity} />
                  <StatusBadge status={selected.status} />
                </DialogTitle>
                <DialogDescription>
                  Raised {relativeTime(selected.created_at)} · confidence {formatPercent(selected.confidence, 2)}{' '}
                  · risk score {selected.risk_score.toFixed(4)}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3">
                <p className="rounded-lg border border-border/70 bg-background/40 p-3 text-xs leading-relaxed">
                  {selected.message}
                </p>

                <div className="grid gap-2 text-xs sm:grid-cols-2">
                  <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                    <div className="label-xs mb-1">Destination</div>
                    <div className="font-mono">
                      {selected.destination_port ? `port ${selected.destination_port}` : 'not specified'}
                    </div>
                    <div className="mt-1 text-[10px] text-muted-foreground">
                      CICIDS2017 flow features do not include host IPs; source IP is shown when a dataset
                      provides one.
                    </div>
                  </div>
                  <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                    <div className="label-xs mb-1">Linked evidence</div>
                    <div className="space-y-1 font-mono text-[11px]">
                      <div>record: {selected.record_index ?? '—'}</div>
                      <div>prediction: {selected.prediction_id?.slice(0, 8) ?? 'aggregated'}</div>
                      <div>job: {selected.job_id?.slice(0, 8) ?? '—'}</div>
                    </div>
                  </div>
                </div>

                {(selected.notes || selected.status !== 'resolved') && (
                  <div className="flex flex-wrap gap-2">
                    {['reviewed', 'resolved', 'new'].map((next) =>
                      next === selected.status ? null : (
                        <Button
                          key={next}
                          size="sm"
                          variant={next === 'resolved' ? 'default' : 'outline'}
                          disabled={updating}
                          onClick={() => updateStatus(selected, next)}
                        >
                          Mark {next}
                        </Button>
                      ),
                    )}
                  </div>
                )}

                <p className="text-[10px] leading-relaxed text-muted-foreground">
                  Alerts reflect the classifier's output on the analysed flows; they are detection leads for an
                  analyst to triage - not proof of an intrusion.
                </p>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
