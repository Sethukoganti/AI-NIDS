import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity, Ban, CircleStop, Info, Play, Radio,
  RefreshCw, ShieldAlert, ShieldCheck, Waves, Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Select } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Alert } from '@/components/common'
import { ThreatFeed } from '@/components/ThreatFeed'
import type { ScoredFlow } from '@/components/ThreatFeed'
import { api, errorMessage, streamSse } from '@/lib/api'
import { cn, formatNumber, formatPercent } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'

interface StreamDone {
  total: number
  suspicious: number
  normal: number
  risk_distribution: Record<string, number>
  attack_distribution: Record<string, number>
}

interface SampleOption {
  name: string
  label: string
  rows: number
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
}

type FlowView = 'threats' | 'normal' | 'blocked' | 'removed'

export function Simulation() {
  const { isAdmin } = useAuth()
  const [samples, setSamples] = useState<SampleOption[]>([])
  const [sample, setSample] = useState('simulation_stream.csv')
  const [rows, setRows] = useState(120)
  const [running, setRunning] = useState(false)
  const [flows, setFlows] = useState<ScoredFlow[]>([])
  const [removedFlows, setRemovedFlows] = useState<ScoredFlow[]>([])
  const [blockedFlows, setBlockedFlows] = useState<ScoredFlow[]>([])
  const [blockedRuleIds, setBlockedRuleIds] = useState<Record<number, string>>({})
  const [flowView, setFlowView] = useState<FlowView | null>(null)
  const [totalSeen, setTotalSeen] = useState(0)
  const [suspiciousSeen, setSuspiciousSeen] = useState(0)
  const [removedThreats, setRemovedThreats] = useState<Set<number>>(() => new Set())
  const [removedCount, setRemovedCount] = useState(0)
  const [blockedThreats, setBlockedThreats] = useState<Set<number>>(() => new Set())
  const [blockingFlowIndex, setBlockingFlowIndex] = useState<number | null>(null)
  const [unblockingFlowIndex, setUnblockingFlowIndex] = useState<number | null>(null)
  const [actionNotice, setActionNotice] = useState<string | null>(null)
  const [startInfo, setStartInfo] = useState<Record<string, unknown> | null>(null)
  const [done, setDone] = useState<StreamDone | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [persisting, setPersisting] = useState(false)
  const [persistResult, setPersistResult] = useState<SimulateResult | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const loadSamples = useCallback(async () => {
    try {
      const data = await api.get<{ samples: SampleOption[]; disclaimer?: string }>('/live/samples')
      const list = Array.isArray(data) ? data : (data.samples ?? [])
      const normalized: SampleOption[] = list.map((s: any) =>
        typeof s === 'string' ? { name: s, label: s, rows: 0 } : s
      )
      setSamples(normalized)
    } catch {
      setSamples([
        { name: 'simulation_stream.csv', label: 'Simulation stream', rows: 800 },
        { name: 'sample_traffic.csv', label: 'Mixed sample', rows: 1500 },
      ])
    }
  }, [])

  useEffect(() => { loadSamples(); return () => controllerRef.current?.abort() }, [loadSamples])

  const stop = () => { controllerRef.current?.abort(); controllerRef.current = null; setRunning(false) }

  const start = async () => {
    stop()
    setFlows([]); setDone(null); setError(null); setStartInfo(null); setPersistResult(null)
    setRemovedFlows([]); setBlockedFlows([]); setBlockedRuleIds({}); setFlowView(null)
    setTotalSeen(0); setSuspiciousSeen(0)
    setRemovedThreats(new Set())
    setRemovedCount(0); setBlockedThreats(new Set()); setActionNotice(null)
    setRunning(true)
    const controller = new AbortController()
    controllerRef.current = controller
    await streamSse(
      `/live/stream?rows=${rows}&sample=${encodeURIComponent(sample)}`,
      {
        onEvent: (event, data) => {
          if (event === 'start') setStartInfo(data)
          else if (event === 'flow') {
            const raw = data as any
            const flow: ScoredFlow = {
              index: raw.index,
              prediction: raw.prediction,
              confidence: raw.confidence,
              is_attack: raw.is_attack,
              risk_level: raw.risk_level,
              risk_score: raw.risk_score,
              destination_port: raw.destination_port ?? null,
              packet_rate: raw.packet_rate ?? null,
              flow_duration: raw.flow_duration ?? null,
              ground_truth: raw.ground_truth ?? null,
              source_ip: null, destination_ip: null, source_port: null, protocol: null,
            }
            setFlows(prev => [flow, ...prev].slice(0, 300))
            setTotalSeen(count => count + 1)
            if (flow.is_attack) setSuspiciousSeen(count => count + 1)
          }
          else if (event === 'done') {
            const summary = data as StreamDone
            setDone(summary)
            setTotalSeen(summary.total)
            setSuspiciousSeen(summary.suspicious)
            setRunning(false)
          }
          else if (event === 'error') { setError(String((data as any)?.message ?? 'Error')); setRunning(false) }
        },
        onError: msg => { if (controller.signal.aborted) return; setError(msg); setRunning(false) },
        onDone: () => setRunning(false),
      },
      controller.signal,
    )
  }

  const persistResults = async () => {
    setPersisting(true); setError(null)
    try {
      setPersistResult(await api.post<SimulateResult>('/predictions/simulate', {
        rows, sample: sample.replace(/\.csv$/, ''), persist: true,
      }))
    } catch (err) { setError(errorMessage(err)) }
    finally { setPersisting(false) }
  }

  const visibleSuspicious = Math.max(suspiciousSeen - removedThreats.size - blockedThreats.size, 0)
  const progress = done ? 100 : Math.min((totalSeen / rows) * 100, 100)
  const activeSummary = done ?? null
  const handleRemoveFlow = (flow: ScoredFlow) => {
    if (!isAdmin) return
    setFlows(current => current.filter(item => item.index !== flow.index))
    setRemovedFlows(current => [...current, flow])
    setRemovedCount(count => count + 1)
    if (flow.is_attack) {
      setRemovedThreats(current => new Set(current).add(flow.index))
      setActionNotice(`Removed the following intrusion: ${flow.prediction} (flow #${flow.index}).`)
    } else {
      setActionNotice(`Removed connection (flow #${flow.index}).`)
    }
  }
  const handleBlockIntrusion = async (flow: ScoredFlow) => {
    if (!isAdmin) return
    setBlockingFlowIndex(flow.index)
    setError(null)
    setActionNotice(null)
    setBlockedThreats(current => new Set(current).add(flow.index))
    setBlockedFlows(current => [...current, flow])
    setFlows(current => current.filter(item => item.index !== flow.index))
    try {
      if (flow.source_ip && isAdmin) {
        const result = await api.post<{ rule: { id: string } }>('/admin/network/blocks', {
          network: flow.source_ip,
          reason: `Attack simulation intrusion: ${flow.prediction} (flow #${flow.index})`,
        })
        setBlockedRuleIds(current => ({ ...current, [flow.index]: result.rule.id }))
      }
      setActionNotice(
        flow.source_ip && isAdmin
          ? `Blocked the following intrusion: ${flow.prediction} from ${flow.source_ip}. The IP is added to the AI-NIDS analysis blocklist; this simulation does not block live network traffic.`
          : flow.source_ip
            ? `Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}) for this run only. An admin can add the source IP to the analysis blocklist; this does not block live network traffic.`
            : `Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}). Simulation data has no source IP, so this is recorded for this run only.`,
      )
    } catch (err) {
      setActionNotice(`Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}) for this run; the IP policy could not be added.`)
      setError(`Intrusion marked blocked for this run, but the analysis blocklist update failed: ${errorMessage(err)}`)
    } finally {
      setBlockingFlowIndex(null)
    }
  }

  const handleUnblockIntrusion = async (flow: ScoredFlow) => {
    if (!isAdmin) return
    setUnblockingFlowIndex(flow.index)
    setError(null)
    try {
      const ruleId = blockedRuleIds[flow.index]
      if (ruleId) await api.del(`/admin/network/blocks/${ruleId}`)
      setBlockedFlows(current => current.filter(item => item.index !== flow.index))
      setBlockedThreats(current => {
        const next = new Set(current)
        next.delete(flow.index)
        return next
      })
      setBlockedRuleIds(current => {
        const next = { ...current }
        delete next[flow.index]
        return next
      })
      setFlows(current => [...current, flow])
      setFlowView('threats')
      setActionNotice(
        ruleId
          ? `Unblocked ${flow.prediction} (flow #${flow.index}) and released its analysis policy.`
          : `Unblocked ${flow.prediction} (flow #${flow.index}) for this simulation run.`,
      )
    } catch (err) {
      setError(`Could not unblock the intrusion: ${errorMessage(err)}`)
    } finally {
      setUnblockingFlowIndex(null)
    }
  }

  const handleRestoreFlow = (flow: ScoredFlow) => {
    if (!isAdmin) return
    setRemovedFlows(current => current.filter(item => item.index !== flow.index))
    setRemovedCount(count => Math.max(0, count - 1))
    setRemovedThreats(current => {
      const next = new Set(current)
      next.delete(flow.index)
      return next
    })
    setFlows(current => [...current, flow])
    setFlowView(flow.is_attack ? 'threats' : 'normal')
    setActionNotice(`Restored ${flow.is_attack ? 'intrusion' : 'connection'} (flow #${flow.index}) to the active list.`)
  }

  const visibleFlows = flowView === 'threats'
    ? flows.filter(flow => flow.is_attack)
    : flowView === 'normal'
      ? flows.filter(flow => !flow.is_attack)
      : flowView === 'blocked'
        ? blockedFlows
        : flowView === 'removed'
          ? removedFlows
          : flows

  return (
    <div className="space-y-5">

      {/* ══ Hero header ═════════════════════════════════════════════════════ */}
      <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-panel/60 p-6">
        <div className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-orange-500/5 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-10 left-10 h-40 w-40 rounded-full bg-primary/5 blur-2xl" />

        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-orange-500/30 bg-orange-500/10 shadow-[0_0_30px_rgba(249,115,22,0.15)]">
              <Radio className="h-7 w-7 text-orange-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Attack Simulation</h1>
              <p className="mt-1 max-w-lg text-sm text-muted-foreground">
                Replays real CICIDS2017 attack flows through the production pipeline. Use this to demo what threats look like — identical to live capture output.
              </p>
              {/* Info badge */}
              <div className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-blue-500/20 bg-blue-500/5 px-2.5 py-1 text-[11px] text-blue-300">
                <Info className="h-3 w-3" />
                Held-out test data — never used for training
              </div>
            </div>
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <Select value={sample} onChange={e => setSample(e.target.value)}
              className="w-[210px] text-xs" disabled={running}>
              {samples.map(s => (
                <option key={s.name} value={s.name}>
                  {s.label} {s.rows > 0 ? `(${s.rows} flows)` : ''}
                </option>
              ))}
            </Select>
            <Select value={String(rows)} onChange={e => setRows(Number(e.target.value))}
              className="w-[110px] text-xs" disabled={running}>
              {[50, 120, 250, 500].map(v => (
                <option key={v} value={v}>{v} flows</option>
              ))}
            </Select>
            {running ? (
              <Button size="lg" variant="destructive" onClick={stop}
                className="gap-2 shadow-[0_0_20px_rgba(239,68,68,0.25)]">
                <CircleStop className="h-4 w-4" /> Stop
              </Button>
            ) : (
              <Button size="lg" onClick={start}
                className="gap-2 bg-orange-500 hover:bg-orange-400 text-white shadow-[0_0_20px_rgba(249,115,22,0.3)] hover:shadow-[0_0_30px_rgba(249,115,22,0.4)]">
                <Play className="h-4 w-4" /> Run simulation
              </Button>
            )}
          </div>
        </div>
      </div>

      {error && <Alert variant="error" title="Stream error">{error}</Alert>}
      {actionNotice && <Alert variant="success" title="Action completed">{actionNotice}</Alert>}

      {/* ══ Progress bar ════════════════════════════════════════════════════ */}
      {startInfo && (running || totalSeen > 0) && (
        <div className="rounded-xl border border-border/60 bg-panel/50 px-5 py-3">
          <div className="flex items-center justify-between text-xs mb-2.5">
            <div className="flex items-center gap-3">
              <Badge variant="secondary" className="gap-1.5">
                <span className={cn('h-1.5 w-1.5 rounded-full', running ? 'bg-orange-400 animate-pulse' : 'bg-muted-foreground')} />
                {String((startInfo as any).label ?? 'Simulation')}
              </Badge>
              <span className="text-muted-foreground">
                {formatNumber(totalSeen)} flows · {formatNumber(suspiciousSeen)} threats
              </span>
            </div>
            <span className={cn('font-mono font-bold', running ? 'text-orange-400' : 'text-muted-foreground')}>
              {progress.toFixed(0)}%
            </span>
          </div>
          <Progress value={progress}
            className={cn('[&>div]:transition-all', running ? '[&>div]:bg-orange-400' : '[&>div]:bg-muted-foreground/40')} />
        </div>
      )}

      {/* ══ Live stats ══════════════════════════════════════════════════════ */}
      {totalSeen > 0 && (
        <div className="space-y-2">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {[
            { label: 'Flows processed', value: totalSeen, hint: `of ${rows} requested`, icon: <Activity className="h-4 w-4" />, color: 'text-primary', bg: 'bg-primary/10 border-primary/20', view: null },
            { label: 'Threats found', value: visibleSuspicious, hint: totalSeen ? `${formatPercent(visibleSuspicious / totalSeen, 1)} of flows` : '', icon: <ShieldAlert className="h-4 w-4" />, color: visibleSuspicious > 0 ? 'text-orange-400' : 'text-emerald-400', bg: visibleSuspicious > 0 ? 'bg-orange-500/10 border-orange-500/20' : 'bg-emerald-500/10 border-emerald-500/20', view: 'threats' as const },
            { label: 'Normal traffic', value: Math.max(totalSeen - suspiciousSeen, 0), hint: 'no action needed', icon: <ShieldCheck className="h-4 w-4" />, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', view: 'normal' as const },
            ...(isAdmin ? [
              { label: 'Blocked intrusions', value: blockedFlows.length, hint: 'handled this run', icon: <Ban className="h-4 w-4" />, color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/20', view: 'blocked' as const },
              { label: 'Removed connections', value: removedFlows.length, hint: 'hidden from this list', icon: <CircleStop className="h-4 w-4" />, color: 'text-muted-foreground', bg: 'bg-muted/30 border-border/50', view: 'removed' as const },
            ] : []),
          ].map(({ label, value, hint, icon, color, bg, view }) => (
            <button key={label} type="button" onClick={() => setFlowView(view)} className={cn('rounded-xl border p-4 text-left transition-colors hover:border-primary/40', bg)}>
              <div className={cn('flex items-center gap-2 mb-2', color)}>{icon}<span className="text-xs font-semibold uppercase tracking-wide">{label}</span></div>
              <div className={cn('text-3xl font-bold tabular-nums', color)}>{formatNumber(value)}</div>
              {hint && <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div>}
            </button>
          ))}
        </div>
        {isAdmin && (
          <p className="text-[10px] text-muted-foreground">
            Blocking marks an intrusion handled in this run. Where a source IP is available, it is also added to the AI-NIDS analysis blocklist; this does not interrupt network traffic.
          </p>
        )}
        </div>
      )}

      {/* ══ Threat feed ═════════════════════════════════════════════════════ */}
      {(running || totalSeen > 0) && (
        <>
        {flowView && (
          <div className="flex items-center justify-between rounded-lg border border-border/60 bg-panel/40 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Showing {flowView} flows</span>
            <Button size="sm" variant="outline" onClick={() => setFlowView(null)}>Show all flows</Button>
          </div>
        )}
        <ThreatFeed
          flows={visibleFlows}
          streaming={running}
          total={totalSeen}
          suspicious={visibleSuspicious}
          removedThreats={isAdmin ? removedFlows.length : 0}
          blockedThreats={isAdmin ? blockedFlows.length : 0}
          onRemoveFlow={isAdmin ? handleRemoveFlow : undefined}
          onBlockIntrusion={isAdmin ? handleBlockIntrusion : undefined}
          onUnblockIntrusion={isAdmin && flowView === 'blocked' ? handleUnblockIntrusion : undefined}
          unblockingFlowIndex={isAdmin ? unblockingFlowIndex : null}
          onRestoreFlow={isAdmin && flowView === 'removed' ? handleRestoreFlow : undefined}
          blockedThreatIndexes={isAdmin && flowView === 'blocked' ? blockedFlows.map(flow => flow.index) : []}
          blockingFlowIndex={isAdmin ? blockingFlowIndex : null}
          emptyMessage='Click "Run simulation" to replay CICIDS2017 attack flows.'
          waitingMessage="Streaming flows through the model…"
        />
        </>
      )}

      {/* ══ Empty state ═════════════════════════════════════════════════════ */}
      {flows.length === 0 && !running && (
        <div className="relative overflow-hidden rounded-2xl border border-border/50 bg-panel/40 py-20 text-center">
          <div className="pointer-events-none absolute inset-0 grid-line opacity-25" />
          <div className="relative space-y-4">
            <div className="mx-auto grid h-20 w-20 place-items-center rounded-3xl border border-orange-500/20 bg-orange-500/5 shadow-[0_0_40px_rgba(249,115,22,0.1)]">
              <Radio className="h-10 w-10 text-orange-400/50" />
            </div>
            <div>
              <p className="text-lg font-semibold text-muted-foreground">Ready to simulate</p>
              <p className="mt-1 text-sm text-muted-foreground/60 max-w-md mx-auto">
                Replays real attacks from the CICIDS2017 dataset through the model.
                Great for demos — shows exactly what each threat looks like.
              </p>
            </div>
            {/* Attack types grid */}
            <div className="flex flex-wrap justify-center gap-2 pt-2">
              {['DoS Hulk', 'DDoS', 'Port Scanning', 'SSH Brute Force', 'SQL Injection', 'Botnet', 'Heartbleed', 'Normal Traffic'].map(a => (
                <span key={a} className="rounded-full border border-border/60 bg-background/40 px-3 py-1 text-[11px] text-muted-foreground">
                  {a}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ══ Run summary + persist ════════════════════════════════════════════ */}
      {activeSummary && !running && (
        <div className="grid gap-4 sm:grid-cols-2">
          {/* Summary */}
          <div className="rounded-xl border border-border/60 bg-panel/50 p-5 space-y-3">
            <p className="text-sm font-semibold">Run summary</p>
            <div className="grid grid-cols-2 gap-3 text-center">
              {[
                { label: 'Total', value: activeSummary.total },
                { label: 'Threats', value: visibleSuspicious },
                { label: 'Normal', value: activeSummary.normal },
                { label: 'Detection rate', value: null, pct: activeSummary.total ? visibleSuspicious / activeSummary.total : 0 },
              ].map(({ label, value, pct }) => (
                <div key={label} className="rounded-lg border border-border/50 bg-background/40 p-2.5">
                  <div className="text-xl font-bold tabular-nums text-foreground">
                    {pct !== undefined ? formatPercent(pct, 1) : formatNumber(value ?? 0)}
                  </div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
                </div>
              ))}
            </div>
            {Object.keys(activeSummary.attack_distribution ?? {}).length > 0 && (
              <div className="space-y-1 pt-1 border-t border-border/50">
                <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Attack types found</p>
                {Object.entries(activeSummary.attack_distribution).sort(([,a],[,b])=>b-a).map(([name, count]) => (
                  <div key={name} className="flex justify-between text-xs">
                    <span className="text-muted-foreground truncate">{name}</span>
                    <span className="font-mono font-semibold text-orange-400">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Save to DB */}
          <div className="rounded-xl border border-border/60 bg-panel/50 p-5 space-y-3">
            <p className="text-sm font-semibold">Save results to database</p>
            <p className="text-xs text-muted-foreground">
              Stores scored flows as predictions so they appear in the Detections and Alerts pages for deeper investigation.
            </p>
            <Button className="w-full gap-2" onClick={persistResults} disabled={persisting || running}>
              <RefreshCw className={cn('h-3.5 w-3.5', persisting && 'animate-spin')} />
              {persisting ? 'Saving…' : `Save ${rows} flows to database`}
            </Button>
            {persistResult && (
              <p className="text-[11px] text-emerald-400">
                ✓ Saved {formatNumber(persistResult.processed ?? 0)} flows
              </p>
            )}
            <p className="flex items-start gap-1.5 text-[10px] text-muted-foreground">
              <Info className="mt-0.5 h-3 w-3 shrink-0" />
              Saved flows are labelled "simulation" — distinct from real uploaded datasets.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
