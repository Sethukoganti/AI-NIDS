import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  FileUp,
  Gauge,
  HelpCircle,
  Radio,
  RefreshCw,
  ShieldAlert,
  Target,
  TrendingUp,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Select } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert as InlineAlert, KeyValue, Loading, PageHeader, RiskBadge, StatCard, StatusBadge } from '@/components/common'
import { AttackDistributionBar, NormalVsSuspiciousDonut, RiskDistributionBars, TrafficOverTime } from '@/components/charts/Charts'
import { Disclosure } from '@/components/ui/disclosure'
import { GuideSteps } from '@/components/layout/GuideSteps'
import { Reveal } from '@/components/motion/Reveal'
import { useCountUp } from '@/hooks/useCountUp'
import { api, errorMessage } from '@/lib/api'
import { cn, formatNumber, formatPercent, relativeTime } from '@/lib/format'
import type { DashboardStats } from '@/lib/types'

// ---- Network status types (analyst read-only view) ----
interface NetworkStatusSummary {
  status: string
  status_key: string
  label: string
  description: string
  tone: 'success' | 'info' | 'warning' | 'danger'
  source: string
  reason?: string | null
  started_at?: string | null
  recent_history: { status: string; source: string; reason?: string | null; started_at: string; ended_at?: string | null }[]
}

const TONE_CLASSES: Record<string, string> = {
  success: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
  info:    'text-sky-400 border-sky-500/30 bg-sky-500/10',
  warning: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  danger:  'text-red-400 border-red-500/30 bg-red-500/10',
}
const DOT_CLASSES: Record<string, string> = {
  success: 'bg-emerald-500',
  info:    'bg-sky-500',
  warning: 'bg-yellow-500',
  danger:  'bg-red-500',
}

function NetworkStatusCard() {
  const [status, setStatus] = useState<NetworkStatusSummary | null>(null)

  useEffect(() => {
    api.get<NetworkStatusSummary>('/analyst/network/status')
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  if (!status) return null

  const tone = status.tone ?? 'info'
  const toneClass = TONE_CLASSES[tone] ?? TONE_CLASSES.info
  const dotClass = DOT_CLASSES[tone] ?? DOT_CLASSES.info

  return (
    <Card className={cn('border', toneClass)}>
      <CardContent className="flex flex-wrap items-start justify-between gap-3 p-4">
        <div className="flex items-start gap-3">
          <span className="relative mt-0.5 flex h-3 w-3 shrink-0">
            {tone === 'success' && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
            )}
            <span className={cn('relative inline-flex h-3 w-3 rounded-full', dotClass)} />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <Radio className="h-3.5 w-3.5 opacity-70" />
              <span className="text-xs font-semibold uppercase tracking-wide opacity-70">Network status</span>
            </div>
            <div className="mt-0.5 text-sm font-bold">{status.label}</div>
            <p className="mt-0.5 max-w-lg text-[11px] text-muted-foreground">{status.description}</p>
            {status.reason && (
              <p className="mt-1 text-[11px] italic text-muted-foreground">Reason: {status.reason}</p>
            )}
          </div>
        </div>
        <div className="text-right text-[10px] text-muted-foreground">
          <div>Source: <span className="capitalize text-foreground/80">{status.source}</span></div>
          {status.started_at && (
            <div>Since: {relativeTime(status.started_at)}</div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

const WINDOWS = [
  { value: '24', label: 'Last 24 hours' },
  { value: '72', label: 'Last 3 days' },
  { value: '168', label: 'Last 7 days' },
  { value: '0', label: 'All time' },
]

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [window, setWindow] = useState('24')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.get<DashboardStats>(`/dashboard/stats?hours=${window}&alert_limit=8`)
      setStats(data)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [window])

  useEffect(() => {
    load()
  }, [load])

  const running = stats?.last_job?.status === 'running' || stats?.last_job?.status === 'queued'

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="A summary of everything analysed so far. Numbers are live aggregates of real detections — accuracy is the measured result on the held-out CICIDS2017 test split, not a real-world guarantee."
        icon={Gauge}
        actions={
          <>
            <Select value={window} onChange={(e) => setWindow(e.target.value)} className="w-[150px]">
              {WINDOWS.map((w) => (
                <option key={w.value} value={w.value}>
                  {w.label}
                </option>
              ))}
            </Select>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
              Refresh
            </Button>
            <Button size="sm" asChild>
              <Link to="/analyzer">
                <FileUp className="h-3.5 w-3.5" />
                Analyze traffic
              </Link>
            </Button>
          </>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Could not load dashboard statistics">
            {error}
          </InlineAlert>
        </div>
      )}

      {loading && !stats ? (
        <Loading label="Loading dashboard aggregates…" />
      ) : stats ? (
        <div className="space-y-4">
          {/* Three steps, in order — the only thing a new user has to read. */}
          <GuideSteps
            steps={[
              {
                icon: <FileUp className="h-4 w-4" />,
                title: 'Analyze a traffic file',
                body: 'Drop in a CICIDS2017-style CSV (or click a bundled sample) and the Random Forest scores every flow.',
                to: '/analyzer',
                cta: 'Open the analyzer',
              },
              {
                icon: <AlertTriangle className="h-4 w-4" />,
                title: 'Review what was flagged',
                body: 'Filter the suspicious flows, open one record and press Why? to see the exact features behind the verdict.',
                to: '/detections',
                cta: 'See detections',
                done: stats.metrics.suspicious_traffic > 0,
              },
              {
                icon: <Target className="h-4 w-4" />,
                title: 'Watch a live feed',
                body: 'Replay a held-out attack stream flow-by-flow to demo detection as it happens (simulation, not packet capture).',
                to: '/data?tab=simulation',
                cta: 'Start simulation',
              },
            ]}
          />

          {running && stats.last_job && (
            <Card className="p-4">
              <div className="flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <BrainCircuit className="h-4 w-4 text-primary" />
                  <span className="font-medium">Random Forest processing</span>
                  <span className="text-muted-foreground">
                    {stats.last_job.stage} · {formatNumber(stats.last_job.processed_rows)} /{' '}
                    {formatNumber(stats.last_job.total_rows)} rows
                  </span>
                </div>
                <span className="font-mono text-primary">Processing {stats.last_job.progress.toFixed(0)}%…</span>
              </div>
              <Progress value={stats.last_job.progress} className="mt-3" />
            </Card>
          )}

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
            <StatCard
              label="Flows analysed"
              countTo={stats.metrics.total_traffic}
              formatCount={formatNumber}
              hint={`${stats.jobs} analysis job(s) · ${stats.datasets} dataset(s)`}
              icon={<Activity className="h-4 w-4" />}
              tone="info"
            />
            <StatCard
              label="Normal"
              countTo={stats.metrics.normal_traffic}
              formatCount={formatNumber}
              hint={`${stats.verdict_share.normal_pct.toFixed(1)}% of analysed flows`}
              icon={<ShieldAlert className="h-4 w-4" />}
              tone="good"
            />
            <StatCard
              label="Suspicious"
              countTo={stats.metrics.suspicious_traffic}
              formatCount={formatNumber}
              hint={`${stats.verdict_share.suspicious_pct.toFixed(1)}% classified as an attack family`}
              icon={<AlertTriangle className="h-4 w-4" />}
              tone="warn"
            />
            <StatCard
              label="Open alerts"
              countTo={stats.metrics.active_alerts}
              formatCount={formatNumber}
              hint={`${formatNumber(stats.metrics.alerts_total)} raised in window · ${
                stats.risk_distribution.critical ?? 0
              } critical flows`}
              icon={<Gauge className="h-4 w-4" />}
              tone={stats.metrics.active_alerts > 0 ? 'bad' : 'good'}
            />
            <StatCard
              label="Detection Rate"
              value={formatPercent(stats.metrics.detection_rate, 2)}
              hint="Share of analysed flows the model classified as suspicious"
              icon={<Target className="h-4 w-4" />}
            />
            <StatCard
              label="Model accuracy (test split)"
              value={stats.model.test_accuracy ? formatPercent(stats.model.test_accuracy, 2) : '—'}
              hint={
                <>
                  99.59%-class result on {formatNumber(stats.model.n_test)} held-out CICIDS2017 flows ·{' '}
                  {stats.model.algorithm} ×{stats.model.n_estimators}
                </>
              }
              icon={<TrendingUp className="h-4 w-4" />}
              tone="info"
            />
          </div>

          <NetworkStatusCard />

          <Reveal>
            <div className="grid gap-3 xl:grid-cols-3">
            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>Traffic Classification</CardTitle>
                <CardDescription>Normal vs suspicious among analysed flows</CardDescription>
              </CardHeader>
              <CardContent>
                <NormalVsSuspiciousDonut
                  normal={stats.metrics.normal_traffic}
                  suspicious={stats.metrics.suspicious_traffic}
                />
              </CardContent>
            </Card>

            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle>Traffic Over Time</CardTitle>
                <CardDescription>
                  Hourly buckets from the detection rollup · records are plotted by analysis time
                  (CICIDS2017 flow CSVs carry no timestamps)
                </CardDescription>
              </CardHeader>
              <CardContent>
                <TrafficOverTime points={stats.timeline} />
              </CardContent>
            </Card>
          </div>

          <div className="mt-3 grid gap-3 xl:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Attack Distribution</CardTitle>
                <CardDescription>Suspicious flows grouped by predicted attack family</CardDescription>
              </CardHeader>
              <CardContent>
                <AttackDistributionBar data={stats.attack_distribution} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Risk Distribution</CardTitle>
                <CardDescription>
                  From the documented risk engine: severity weight × confidence (+ sensitive-port bonus)
                </CardDescription>
              </CardHeader>
              <CardContent>
                <RiskDistributionBars data={stats.risk_distribution} />
              </CardContent>
            </Card>
            </div>
          </Reveal>

          <Reveal as="section">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <div>
                <CardTitle>Recent Alerts</CardTitle>
                <CardDescription>
                  Highest-volume detections raise their own alert; the remainder are aggregated per
                  attack type and destination port
                </CardDescription>
              </div>
              <Button variant="ghost" size="sm" asChild>
                <Link to="/detections?tab=alerts">Open Alerts Center</Link>
              </Button>
            </CardHeader>
            <CardContent>
              {stats.recent_alerts.length === 0 ? (
                <p className="py-6 text-center text-xs text-muted-foreground">
                  No alerts yet - analyze a dataset to populate this table.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Attack Type</TableHead>
                      <TableHead>Risk</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {stats.recent_alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                          {relativeTime(alert.created_at)}
                        </TableCell>
                        <TableCell className="mono text-muted-foreground">
                          {alert.source_ip ?? 'n/a *'}
                        </TableCell>
                        <TableCell className="mono">
                          {alert.destination_port ? `port ${alert.destination_port}` : '—'}
                        </TableCell>
                        <TableCell className="text-xs">{alert.attack_type}</TableCell>
                        <TableCell>
                          <RiskBadge level={alert.severity} />
                        </TableCell>
                        <TableCell className="font-mono text-xs">{formatPercent(alert.confidence, 1)}</TableCell>
                        <TableCell>
                          <StatusBadge status={alert.status} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              <p className="mt-3 text-[10px] leading-relaxed text-muted-foreground">
                * CICIDS2017 MachineLearningCVE flows contain no IP addresses, so hosts cannot be identified
                from this dataset. IP columns are displayed when an uploaded file provides them.
              </p>
            </CardContent>
          </Card>
          </Reveal>

          <Disclosure
            title="How the model works"
            hint="Algorithm details, dataset provenance and how each verdict is explained"
          >
            <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Model &amp; dataset</CardTitle>
                <CardDescription>Straight from model_metadata.json and evaluation.json</CardDescription>
              </CardHeader>
              <CardContent className="space-y-0.5">
                <KeyValue label="Algorithm" value={stats.model.algorithm ?? '—'} />
                <KeyValue label="Trees" value={stats.model.n_estimators ?? '—'} />
                <KeyValue label="Features" value={stats.model.n_features ?? '—'} />
                <KeyValue label="Classes" value={stats.model.classes?.length ?? '—'} />
                <KeyValue label="Dataset" value={stats.model.dataset ?? '—'} />
                <KeyValue
                  label="Reference capture"
                  value={`${formatNumber(stats.reference_dataset.full_rows)} flows × ${
                    stats.reference_dataset.full_columns ?? '—'
                  } cols`}
                />
                <KeyValue
                  label="Macro F1 (test split)"
                  value={stats.model.macro_f1 ? stats.model.macro_f1.toFixed(4) : '—'}
                />
                <KeyValue label="Model loaded" value={stats.model.loaded ? 'yes' : 'no'} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Explainability</CardTitle>
                <CardDescription>How the console justifies each detection</CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="shap">
                  <TabsList className="w-full">
                    <TabsTrigger value="shap" className="flex-1">
                      Per-record SHAP
                    </TabsTrigger>
                    <TabsTrigger value="importance" className="flex-1">
                      Global importance
                    </TabsTrigger>
                  </TabsList>
                  <TabsContent value="shap" className="space-y-2 text-xs leading-relaxed text-muted-foreground">
                    <p>
                      Opening any prediction computes real <span className="text-foreground">TreeSHAP</span>{' '}
                      values for that record - the exact contribution of each flow feature to the predicted
                      class. Positive values push towards the attack class, negative values towards normal
                      traffic.
                    </p>
                    <p>
                      If SHAP cannot run, the console falls back to global feature importance and labels the
                      panel accordingly, so a per-record claim is never faked.
                    </p>
                  </TabsContent>
                  <TabsContent value="importance" className="space-y-2 text-xs leading-relaxed text-muted-foreground">
                    <p>
                      Global importances come from <span className="font-mono">model.feature_importances_</span>{' '}
                      (mean decrease in impurity across all 100 trees) and describe the model as a whole -
                      not an individual verdict. See the AI Model page for the full ranking.
                    </p>
                  </TabsContent>
                </Tabs>
                <div className="mt-4 rounded-lg border border-border/70 bg-background/40 p-3 text-[11px] text-muted-foreground">
                  AI layer: <span className="text-foreground">{stats.ai.mode}</span>
                  {!stats.ai.enabled && ' — deterministic explanations built from model output and dataset profiles.'}
                </div>
              </CardContent>
            </Card>
            </div>
          </Disclosure>
        </div>
      ) : null}
    </>
  )
}
