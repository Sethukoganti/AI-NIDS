import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  CircleStop,
  Info,
  Play,
  Radio,
  RefreshCw,
  ShieldAlert,
  Waves,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Select } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Alert, PageHeader, RiskBadge, StatCard } from '@/components/common'
import { api, errorMessage, streamSse } from '@/lib/api'
import { RISK_COLORS, formatNumber, formatPercent } from '@/lib/format'
import type { LiveFlowEvent, RiskLevel } from '@/lib/types'

interface StreamDone {
  total: number
  suspicious: number
  normal: number
  risk_distribution: Record<string, number>
  attack_distribution: Record<string, number>
}

interface SimulateResult {
  processed?: number
  elapsed_ms?: number
  summary?: {
    total_records: number
    normal_records: number
    suspicious_records: number
    risk_distribution: Record<string, number>
    attack_distribution: Record<string, number>
  }
  persisted?: boolean
  job_id?: string
  [key: string]: unknown
}

export function Simulation() {
  const [samples, setSamples] = useState<string[]>([])
  const [disclaimer, setDisclaimer] = useState<string>('')
  const [sample, setSample] = useState('simulation_stream.csv')
  const [rows, setRows] = useState(120)
  const [running, setRunning] = useState(false)
  const [flows, setFlows] = useState<LiveFlowEvent[]>([])
  const [startInfo, setStartInfo] = useState<Record<string, unknown> | null>(null)
  const [done, setDone] = useState<StreamDone | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [persisting, setPersisting] = useState(false)
  const [persistResult, setPersistResult] = useState<SimulateResult | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const loadSamples = useCallback(async () => {
    try {
      const data = await api.get<{ samples: string[]; disclaimer?: string }>('/live/samples')
      setSamples(Array.isArray(data) ? data : data.samples ?? [])
      if (data.disclaimer) setDisclaimer(data.disclaimer)
    } catch {
      setSamples(['simulation_stream.csv', 'sample_traffic.csv'])
    }
  }, [])

  useEffect(() => {
    loadSamples()
    return () => controllerRef.current?.abort()
  }, [loadSamples])

  const stop = () => {
    controllerRef.current?.abort()
    controllerRef.current = null
    setRunning(false)
  }

  const start = async () => {
    stop()
    setFlows([])
    setDone(null)
    setError(null)
    setStartInfo(null)
    setRunning(true)
    const controller = new AbortController()
    controllerRef.current = controller

    await streamSse(
      `/live/stream?rows=${rows}&sample=${encodeURIComponent(sample)}`,
      {
        onEvent: (event, data) => {
          if (event === 'start') setStartInfo(data)
          else if (event === 'flow') {
            setFlows((current) => [data as LiveFlowEvent, ...current].slice(0, 300))
          } else if (event === 'done') {
            setDone(data as StreamDone)
            setRunning(false)
          } else if (event === 'error') {
            setError(String((data as { message?: string })?.message ?? 'Stream error'))
            setRunning(false)
          }
        },
        onError: (message) => {
          if (controller.signal.aborted) return
          setError(message)
          setRunning(false)
        },
        onDone: () => setRunning(false),
      },
      controller.signal,
    )
  }

  const persistResults = async () => {
    setPersisting(true)
    setError(null)
    try {
      const result = await api.post<SimulateResult>('/predictions/simulate', {
        rows,
        sample: sample.replace(/\.csv$/, ''),
        persist: true,
      })
      setPersistResult(result)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setPersisting(false)
    }
  }

  const cursor = flows[0]?.cursor
  const totalSeen = cursor?.total ?? 0
  const suspiciousSeen = cursor?.suspicious ?? 0
  const progress = cursor?.progress ?? 0

  const riskCounts = useMemo(() => {
    const counts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    flows.forEach((flow) => {
      counts[flow.risk_level] = (counts[flow.risk_level] ?? 0) + 1
    })
    return counts
  }, [flows])

  const attackCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    flows.forEach((flow) => {
      if (flow.is_attack) counts[flow.prediction] = (counts[flow.prediction] ?? 0) + 1
    })
    return Object.entries(counts).sort(([, a], [, b]) => b - a)
  }, [flows])

  const activeSummary = done ?? (persistResult?.summary as StreamDone | undefined) ?? null

  return (
    <>
      <PageHeader
        title="Live Traffic Simulation"
        subtitle={
          <>
            Real held-out CICIDS2017 flows replayed one at a time through the production detection pipeline
            (preprocessing → Random Forest → risk engine) over Server-Sent Events. This is a simulation, not
            packet capture: no network interface is being monitored.
          </>
        }
        actions={
          <>
            <Select
              value={sample}
              onChange={(event) => setSample(event.target.value)}
              className="w-[210px]"
              disabled={running}
            >
              {(samples.length ? samples : ['simulation_stream.csv', 'sample_traffic.csv']).map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </Select>
            <Select
              value={String(rows)}
              onChange={(event) => setRows(Number(event.target.value))}
              className="w-[120px]"
              disabled={running}
            >
              {[50, 120, 250, 500, 1000].map((value) => (
                <option key={value} value={value}>
                  {value} flows
                </option>
              ))}
            </Select>
            {running ? (
              <Button variant="destructive" size="sm" onClick={stop}>
                <CircleStop className="h-3.5 w-3.5" />
                Stop stream
              </Button>
            ) : (
              <Button size="sm" onClick={start}>
                <Play className="h-3.5 w-3.5" />
                Start simulation
              </Button>
            )}
          </>
        }
      />

      <div className="mb-4">
        <Alert variant="warn" title="Simulation — not live packet capture">
          {disclaimer ||
            'Live Traffic Simulation replays real, held-out CICIDS2017 flow records one at a time. It does not capture packets from a network interface. Capturing real traffic would require a separately configured, privileged capture agent and is out of scope for this deployment.'}
        </Alert>
      </div>

      {error && (
        <div className="mb-4">
          <Alert variant="error" title="Simulation error">
            {error}
          </Alert>
        </div>
      )}

      {startInfo && (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-border/70 bg-panel/60 px-4 py-3 text-xs">
          <Badge variant="default">
            <Radio className="mr-1 h-3 w-3" />
            {String((startInfo as { label?: string }).label ?? 'stream started')}
          </Badge>
          {typeof (startInfo as { sample?: string }).sample === 'string' && (
            <span className="text-muted-foreground">sample: {(startInfo as { sample?: string }).sample}</span>
          )}
          {typeof (startInfo as { source?: string }).source === 'string' && (
            <span className="text-muted-foreground">source: {(startInfo as { source?: string }).source}</span>
          )}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Flows processed"
          value={formatNumber(totalSeen)}
          hint={`of ${formatNumber(rows)} requested · ${progress.toFixed(0)}% complete`}
          icon={<Activity className="h-4 w-4" />}
          tone="info"
        />
        <StatCard
          label="Suspicious"
          value={formatNumber(suspiciousSeen)}
          hint={
            totalSeen
              ? `${formatPercent(suspiciousSeen / totalSeen, 1)} of processed flows`
              : 'waiting for the first flows'
          }
          icon={<ShieldAlert className="h-4 w-4" />}
          tone="warn"
        />
        <StatCard
          label="Normal"
          value={formatNumber(Math.max(totalSeen - suspiciousSeen, 0))}
          hint="classified as Normal Traffic"
          icon={<Waves className="h-4 w-4" />}
          tone="good"
        />
        <StatCard
          label="Newest detection"
          value={flows[0] ? flows[0].prediction : '—'}
          hint={
            flows[0]
              ? `confidence ${formatPercent(flows[0].confidence, 2)} · risk ${flows[0].risk_level}`
              : 'stream idle'
          }
          tone={flows[0]?.is_attack ? 'bad' : 'good'}
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[1.6fr_1fr]">
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <div>
              <CardTitle>Live detection feed</CardTitle>
              <CardDescription>
                Newest first · each row was scored by the Random Forest as it streamed in. “Ground truth” is
                the dataset label carried by the held-out record (never shown to the model).
              </CardDescription>
            </div>
            {(running || flows.length > 0) && <Progress value={progress} className="w-32" />}
          </CardHeader>
          <CardContent className="p-0">
            {flows.length === 0 ? (
              <p className="p-8 text-center text-xs text-muted-foreground">
                {running
                  ? 'Waiting for the first flow…'
                  : 'Press “Start simulation” to stream held-out flows through the model.'}
              </p>
            ) : (
              <div className="max-h-[520px] overflow-y-auto">
                <Table>
                  <TableHeader className="sticky top-0 bg-panel">
                    <TableRow>
                      <TableHead>#</TableHead>
                      <TableHead>Prediction</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Risk</TableHead>
                      <TableHead>Dest port</TableHead>
                      <TableHead>Packet rate</TableHead>
                      <TableHead>Ground truth</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {flows.map((flow) => (
                      <TableRow key={`${flow.index}-${flow.cursor?.total ?? 0}`}>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {flow.index}
                        </TableCell>
                        <TableCell>
                          <Badge variant={flow.is_attack ? 'danger' : 'success'}>{flow.prediction}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {formatPercent(flow.confidence, 2)}
                        </TableCell>
                        <TableCell>
                          <RiskBadge level={flow.risk_level as RiskLevel} />
                        </TableCell>
                        <TableCell className="font-mono text-xs">{flow.destination_port ?? '—'}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {flow.packet_rate !== null && flow.packet_rate !== undefined
                            ? formatNumber(flow.packet_rate, 1)
                            : '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {flow.ground_truth ?? '—'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Risk levels in this run</CardTitle>
              <CardDescription>
                {flows.length ? `${flows.length} flows streamed (latest 300 kept)` : 'No data yet'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map((level) => {
                const value = riskCounts[level] ?? 0
                const share = flows.length ? value / flows.length : 0
                return (
                  <div key={level} className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="capitalize text-muted-foreground">{level}</span>
                      <span className="font-mono text-foreground/85">
                        {value} · {formatPercent(share, 1)}
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/60">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${share * 100}%`, background: RISK_COLORS[level] }}
                      />
                    </div>
                  </div>
                )
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Attack families observed</CardTitle>
              <CardDescription>Among the streamed flows</CardDescription>
            </CardHeader>
            <CardContent>
              {attackCounts.length === 0 ? (
                <p className="py-4 text-center text-xs text-muted-foreground">
                  No suspicious flows in this run yet.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {attackCounts.map(([name, count]) => (
                    <div key={name} className="flex items-center justify-between text-xs">
                      <span className="truncate text-foreground/85">{name}</span>
                      <span className="font-mono text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {activeSummary && (
            <Card>
              <CardHeader>
                <CardTitle>Run summary</CardTitle>
                <CardDescription>
                  {done ? 'Stream completed' : 'Persisted simulation'}: {formatNumber(activeSummary.total)} flows
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Normal</span>
                  <span className="font-mono">{formatNumber(activeSummary.normal)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Suspicious</span>
                  <span className="font-mono">{formatNumber(activeSummary.suspicious)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Detection rate</span>
                  <span className="font-mono">
                    {formatPercent(
                      activeSummary.total ? activeSummary.suspicious / activeSummary.total : 0,
                      1,
                    )}
                  </span>
                </div>
                <div className="border-t border-border/60 pt-2">
                  <div className="label-xs mb-1.5">Attack distribution</div>
                  {Object.entries(activeSummary.attack_distribution ?? {}).length === 0 ? (
                    <p className="text-muted-foreground">Only normal traffic in this run.</p>
                  ) : (
                    Object.entries(activeSummary.attack_distribution).map(([name, count]) => (
                      <div key={name} className="flex justify-between">
                        <span className="truncate text-muted-foreground">{name}</span>
                        <span className="font-mono text-foreground/85">{count}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Persist a simulation</CardTitle>
              <CardDescription>
                Stores the simulated flows as predictions (and alerts) so they appear in the dashboard,
                results table and alert queue.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button className="w-full" onClick={persistResults} disabled={persisting || running}>
                <RefreshCw className={persisting ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
                {persisting ? 'Storing results…' : `Simulate & store ${rows} flows`}
              </Button>
              {persistResult && (
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  Stored {formatNumber(persistResult.processed ?? 0)} flows in{' '}
                  {persistResult.elapsed_ms ?? 0} ms
                  {persistResult.summary
                    ? ` · ${persistResult.summary.suspicious_records} suspicious, ${formatNumber(
                        Object.values(persistResult.summary.risk_distribution).reduce((a, b) => a + b, 0),
                      )} scored`
                    : ''}
                  . <Link className="text-primary underline" to="/detections?verdict=attack">Open results</Link>{' '}
                  · <Link className="text-primary underline" to="/detections?tab=alerts">Alerts</Link>
                </p>
              )}
              <p className="flex items-start gap-1.5 text-[10px] leading-relaxed text-muted-foreground">
                <Info className="mt-0.5 h-3 w-3 shrink-0" />
                Persisted simulations are labelled with source “simulation” in the database, keeping them
                distinguishable from uploaded datasets.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
