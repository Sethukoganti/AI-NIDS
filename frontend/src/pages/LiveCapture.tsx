import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Activity, Ban, CircleStop, Clock, Network,
  ShieldAlert, ShieldCheck, Wifi, Zap, FlaskConical, X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert } from '@/components/common'
import { Select } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { ThreatFeed } from '@/components/ThreatFeed'
import type { ScoredFlow } from '@/components/ThreatFeed'
import { api, errorMessage, streamSse } from '@/lib/api'
import { cn, formatNumber, formatPercent } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'

interface CaptureStatus {
  agent_running: boolean
  interface: string | null
  packet_count: number
  flow_count: number
  queue_depth: number
  error: string | null
  model_ready: boolean
  npcap_installed: boolean
}

interface IfaceOption { name: string; description: string; ips: string[] }

interface StartCaptureResponse {
  started: boolean
  error?: string
  hint?: string
  reason?: string
}

interface SessionSummary {
  total: number
  suspicious: number
  safe: number
  packetsCaptured: number
  flowsCompleted: number
  interface: string | null
  durationSec: number
}

// ── Animated counter ───────────────────────────────────────────────────── //
function AnimatedNumber({ value, className }: { value: number; className?: string }) {
  return <span className={className}>{formatNumber(value)}</span>
}

export function LiveCapture() {
  const { isAdmin } = useAuth()
  const [status, setStatus] = useState<CaptureStatus | null>(null)
  const [ifaces, setIfaces] = useState<IfaceOption[]>([])
  const [selectedIface, setSelectedIface] = useState('')
  const [streaming, setStreaming] = useState(false)
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [flows, setFlows] = useState<ScoredFlow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [total, setTotal] = useState(0)
  const [suspicious, setSuspicious] = useState(0)
  const [removedThreats, setRemovedThreats] = useState<Set<number>>(() => new Set())
  const [removedCount, setRemovedCount] = useState(0)
  const [blockedThreats, setBlockedThreats] = useState<Set<number>>(() => new Set())
  const [blockingFlowIndex, setBlockingFlowIndex] = useState<number | null>(null)
  const [actionNotice, setActionNotice] = useState<string | null>(null)
  const [sessionSummary, setSessionSummary] = useState<SessionSummary | null>(null)
  const [sessionStartTime, setSessionStartTime] = useState(0)
  const [elapsedSec, setElapsedSec] = useState(0)
  const [injecting, setInjecting] = useState(false)
  const [injectMsg, setInjectMsg] = useState<string | null>(null)
  const controllerRef = useRef<AbortController | null>(null)
  const timerRef = useRef<number | null>(null)

  const loadStatus = useCallback(async () => {
    try { setStatus(await api.get<CaptureStatus>('/capture/status')) } catch { /* ignore */ }
  }, [])

  const loadIfaces = useCallback(async () => {
    try {
      const data = await api.get<{ interfaces: IfaceOption[] }>('/capture/interfaces')
      const list = data.interfaces ?? []
      setIfaces(list)
      if (list.length && !selectedIface) setSelectedIface(list[0].name)
    } catch { /* ignore */ }
  }, [selectedIface])

  useEffect(() => {
    loadStatus(); loadIfaces()
    const t = setInterval(loadStatus, 3000)
    return () => { clearInterval(t); controllerRef.current?.abort() }
  }, [loadStatus, loadIfaces])

  // Elapsed timer while streaming
  useEffect(() => {
    if (streaming) {
      timerRef.current = window.setInterval(() => {
        setElapsedSec(Math.round((Date.now() - sessionStartTime) / 1000))
      }, 1000)
    } else {
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null }
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [streaming, sessionStartTime])

  const handleStart = async () => {
    setError(null); setStarting(true)
    setFlows([]); setTotal(0); setSuspicious(0); setSessionSummary(null); setElapsedSec(0)
    setRemovedThreats(new Set())
    setRemovedCount(0); setBlockedThreats(new Set()); setActionNotice(null)
    try {
      const result = await api.post<StartCaptureResponse>('/capture/start', { iface: selectedIface || null })
      if (!result.started) {
        setError(
          result.error === 'NPCAP_MISSING'
            ? 'NPCAP_MISSING'
            : result.error === 'SCAPY_MISSING'
              ? 'Scapy is not installed. Run "pip install -r requirements.txt" from the backend folder, then restart the backend.'
              : result.error || result.hint || 'Could not start.',
        )
        return
      }
      const startTs = Date.now()
      setSessionStartTime(startTs)
      setStreaming(true)
      const controller = new AbortController()
      controllerRef.current = controller

      const connectStream = async () => {
        // Small delay so backend stream endpoint is ready
        await new Promise(r => setTimeout(r, 500))
        await streamSse('/capture/stream', {
          onEvent: (_e, data) => {
            if (_e === 'flow') {
              const f = data as ScoredFlow & { cursor?: { total: number; suspicious: number } }
              setFlows(prev => [f, ...prev].slice(0, 300))
              if ((f as any).cursor) {
                setTotal((f as any).cursor.total)
                setSuspicious((f as any).cursor.suspicious)
              } else {
                setTotal(p => p + 1)
                if (f.is_attack) setSuspicious(p => p + 1)
              }
            } else if (_e === 'error') {
              setError(String((data as any)?.message ?? 'Stream error'))
              setStreaming(false)
            }
          },
          onError: msg => {
            if (controller.signal.aborted) return
            console.error('SSE stream error:', msg)
            setError('Stream error: ' + msg)
            setTimeout(() => {
              if (!controller.signal.aborted) { setError(null); connectStream() }
            }, 2000)
          },
          onDone: () => {
            if (!controller.signal.aborted) {
              // Reconnect if not manually stopped
              setTimeout(() => {
                if (!controller.signal.aborted) connectStream()
              }, 1000)
            } else {
              setStreaming(false)
            }
          },
        }, controller.signal)
      }
      connectStream()
    } catch (err) { setError(errorMessage(err)); setStreaming(false) }
    finally { setStarting(false) }
  }

  const handleInject = async () => {
    setInjecting(true)
    setInjectMsg(null)
    try {
      const r = await api.post<{ injected: number; labels: string[] }>('/capture/inject', { count: 4 })
      setInjectMsg(`Injected ${r.injected} demo flows: ${r.labels.join(', ')}`)
      setTimeout(() => setInjectMsg(null), 4000)
    } catch (err) {
      setInjectMsg('Injection failed — make sure capture stream is open')
      setTimeout(() => setInjectMsg(null), 3000)
    } finally {
      setInjecting(false)
    }
  }

  const handleStop = async () => {
    setStopping(true)
    try {
      controllerRef.current?.abort(); controllerRef.current = null; setStreaming(false)
      const result = await api.post<CaptureStatus>('/capture/stop', {})
      setStatus(result)
      setSessionSummary({
        total, suspicious: visibleSuspicious,
        safe: total - suspicious,
        packetsCaptured: result.packet_count ?? 0,
        flowsCompleted: result.flow_count ?? 0,
        interface: result.interface,
        durationSec: elapsedSec,
      })
    } catch (err) { setError(errorMessage(err)) }
    finally { setStopping(false) }
  }

  const handleRemoveFlow = (flow: ScoredFlow) => {
    if (!isAdmin) return
    setFlows(current => current.filter(item => item.index !== flow.index))
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
    setFlows(current => current.filter(item => item.index !== flow.index))
    try {
      if (flow.source_ip && isAdmin) {
        await api.post('/admin/network/blocks', {
          network: flow.source_ip,
          reason: `Live capture intrusion: ${flow.prediction} (flow #${flow.index})`,
        })
      }
      setActionNotice(
        flow.source_ip && isAdmin
          ? `Blocked the following intrusion: ${flow.prediction} from ${flow.source_ip}. The IP is added to the AI-NIDS analysis blocklist; live traffic is not interrupted.`
          : flow.source_ip
            ? `Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}). It is recorded for this capture session only; an admin can add the source IP to the analysis blocklist. Live traffic is not interrupted.`
            : `Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}). No source IP was available, so this is recorded for this capture session only; live traffic is not interrupted.`,
      )
    } catch (err) {
      setActionNotice(`Blocked the following intrusion: ${flow.prediction} (flow #${flow.index}) for this capture session; the IP policy could not be added.`)
      setError(`Intrusion marked blocked in this session, but the analysis blocklist update failed: ${errorMessage(err)}`)
    } finally {
      setBlockingFlowIndex(null)
    }
  }

  const agentRunning = status?.agent_running ?? false
  const modelReady = status?.model_ready ?? false
  const npcapMissing = error === 'NPCAP_MISSING' || (status !== null && !status.npcap_installed)
  const visibleSuspicious = Math.max(suspicious - removedThreats.size - blockedThreats.size, 0)
  const threatRate = total > 0 ? visibleSuspicious / total : 0

  return (
    <div className="space-y-5">

      {/* ══ Hero header ═════════════════════════════════════════════════════ */}
      <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-panel/60 p-6">
        {/* Background glow */}
        <div className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-primary/5 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-10 left-10 h-40 w-40 rounded-full bg-blue-500/5 blur-2xl" />

        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-primary/30 bg-primary/10 shadow-[0_0_30px_rgba(34,211,238,0.2)]">
              <Wifi className="h-7 w-7 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Live Network Capture</h1>
              <p className="mt-1 max-w-lg text-sm text-muted-foreground">
                Monitors every TCP/UDP connection on your network adapter in real-time.
                The Random Forest scores each completed flow and flags threats with plain-language advice.
              </p>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-3">
            {ifaces.length > 0 && !agentRunning && (
              <Select value={selectedIface} onChange={e => setSelectedIface(e.target.value)}
                className="w-[160px] text-xs" disabled={streaming || starting}>
                {ifaces.map(i => <option key={i.name} value={i.name}>{i.name}</option>)}
              </Select>
            )}
            {streaming || agentRunning ? (
              <Button size="lg" variant="destructive" onClick={handleStop} disabled={stopping}
                className="gap-2 shadow-[0_0_20px_rgba(239,68,68,0.3)]">
                <CircleStop className="h-4 w-4" />
                {stopping ? 'Stopping…' : 'Stop & view results'}
              </Button>
            ) : (
              <Button size="lg" onClick={handleStart}
                disabled={starting || !modelReady || npcapMissing}
                className="gap-2 shadow-[0_0_20px_rgba(34,211,238,0.25)] hover:shadow-[0_0_30px_rgba(34,211,238,0.4)]">
                <Wifi className="h-4 w-4" />
                {starting ? 'Starting capture…' : sessionSummary ? 'Start new session' : 'Start live capture'}
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Npcap missing */}
      {npcapMissing && (
        <div className="rounded-xl border border-yellow-500/40 bg-yellow-500/5 p-5">
          <div className="flex items-start gap-3">
            <span className="text-2xl">⚠</span>
            <div className="space-y-3">
              <div>
                <p className="font-semibold text-yellow-300">One-time setup required — install Npcap</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Live capture needs <strong className="text-foreground">Npcap</strong> — a free Windows packet driver (also used by Wireshark). Install once, works forever.
                </p>
              </div>
              <div className="rounded-lg border border-yellow-500/20 bg-background/60 p-4 font-mono text-xs space-y-1.5">
                <div><span className="text-yellow-400">1.</span> <span className="text-muted-foreground">Download: </span><span className="text-yellow-300 font-bold">https://npcap.com/#download</span></div>
                <div><span className="text-yellow-400">2.</span> <span className="text-muted-foreground">Run installer — keep all default options</span></div>
                <div><span className="text-yellow-400">3.</span> <span className="text-muted-foreground">Restart backend → click "Start live capture"</span></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {error && error !== 'NPCAP_MISSING' && (
        <Alert variant="error" title="Capture error">{error}</Alert>
      )}

      {/* ══ Live status bar ═════════════════════════════════════════════════ */}
      {!npcapMissing && streaming && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 px-5 py-3">
          <div className="flex flex-wrap items-center gap-6">
            {/* Pulse + status */}
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-50" />
                <span className="relative inline-flex h-3 w-3 rounded-full bg-primary" />
              </span>
              <span className="text-sm font-bold text-primary">CAPTURING</span>
              {selectedIface && <span className="text-xs text-muted-foreground">on {selectedIface}</span>}
            </div>

            <div className="h-4 w-px bg-border/60" />

            {/* Live counters */}
            <div className="flex items-center gap-5 text-xs">
              <div className="flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">Packets:</span>
                <span className="font-mono font-bold text-foreground">{formatNumber(status?.packet_count ?? 0)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Network className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">Flows scored:</span>
                <span className="font-mono font-bold text-foreground">{formatNumber(total)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-orange-400" />
                <span className="text-muted-foreground">Threats:</span>
                <span className={cn('font-mono font-bold', visibleSuspicious > 0 ? 'text-orange-400' : 'text-emerald-400')}>
                  {formatNumber(visibleSuspicious)}
                </span>
              </div>
              {isAdmin && (
                <>
                  <div className="flex items-center gap-1.5" title="Intrusions marked blocked in this capture session; no live traffic is interrupted">
                    <Ban className="h-3.5 w-3.5 text-rose-400" />
                    <span className="text-muted-foreground">Blocked intrusions:</span>
                    <span className="font-mono font-bold text-rose-400">{blockedThreats.size}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <X className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-muted-foreground">Removed:</span>
                    <span className="font-mono font-bold text-foreground">{removedCount}</span>
                  </div>
                </>
              )}
              <div className="flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="font-mono font-bold text-foreground">{elapsedSec}s</span>
              </div>
            </div>

            {/* Threat rate bar */}
            {total > 0 && (
              <div className="ml-auto flex items-center gap-2 text-xs">
                <span className="text-muted-foreground">Threat rate:</span>
                <div className="w-24">
                  <Progress
                    value={threatRate * 100}
                    className={cn('h-1.5', visibleSuspicious > 0 ? '[&>div]:bg-orange-400' : '[&>div]:bg-emerald-400')}
                  />
                </div>
                <span className={cn('font-mono font-semibold w-12 text-right',
                  threatRate > 0.1 ? 'text-orange-400' : 'text-emerald-400')}>
                  {formatPercent(threatRate, 1)}
                </span>
              </div>
            )}
          </div>
          {isAdmin && (
            <p className="mt-2 text-[10px] text-muted-foreground">
              Block intrusion marks it handled in this session. Admins can also add an available source IP to the AI-NIDS analysis blocklist; neither action interrupts live traffic.
            </p>
          )}
          {/* Inject button + feedback */}
          <div className="mt-2.5 flex flex-wrap items-center gap-3 border-t border-primary/20 pt-2.5">
            <Button
              size="sm"
              variant="outline"
              onClick={handleInject}
              disabled={injecting}
              className="gap-1.5 border-orange-500/40 bg-orange-500/5 text-orange-400 hover:bg-orange-500/10 hover:text-orange-300"
            >
              <FlaskConical className="h-3.5 w-3.5" />
              {injecting ? 'Injecting…' : 'Inject test threats (demo)'}
            </Button>
            <span className="text-[11px] text-muted-foreground">
              Pushes realistic DoS · DDoS · Port Scan · Brute Force flows into the model for presentation
            </span>
            {injectMsg && (
              <span className="text-[11px] font-medium text-orange-400 animate-fade-in">{injectMsg}</span>
            )}
          </div>
        </div>
      )}

      {/* ══ Session summary (after stop) ════════════════════════════════════ */}
      {sessionSummary && !streaming && (
        <div className="space-y-4">
          {/* Big result card */}
          <div className={cn(
            'relative overflow-hidden rounded-2xl border p-6',
            sessionSummary.suspicious === 0
              ? 'border-emerald-500/40 bg-emerald-500/5'
              : sessionSummary.suspicious >= 5
              ? 'border-red-500/40 bg-red-500/5'
              : 'border-orange-500/40 bg-orange-500/5'
          )}>
            <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full blur-3xl opacity-20"
              style={{ background: sessionSummary.suspicious === 0 ? '#10b981' : '#f97316' }} />
            <div className="relative flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className={cn('grid h-16 w-16 shrink-0 place-items-center rounded-2xl border',
                  sessionSummary.suspicious === 0
                    ? 'border-emerald-500/40 bg-emerald-500/10'
                    : 'border-orange-500/40 bg-orange-500/10'
                )}>
                  {sessionSummary.suspicious === 0
                    ? <ShieldCheck className="h-8 w-8 text-emerald-400" />
                    : <ShieldAlert className="h-8 w-8 text-orange-400" />
                  }
                </div>
                <div>
                  <div className={cn('text-xl font-bold',
                    sessionSummary.suspicious === 0 ? 'text-emerald-400' : 'text-orange-400')}>
                    {sessionSummary.suspicious === 0
                      ? '✓ Network looks clean'
                      : `⚠ ${sessionSummary.suspicious} threat${sessionSummary.suspicious !== 1 ? 's' : ''} detected`}
                  </div>
                  <p className="mt-0.5 text-sm text-muted-foreground">
                    {sessionSummary.durationSec}s session · {sessionSummary.interface} · {formatNumber(sessionSummary.packetsCaptured)} packets captured
                  </p>
                </div>
              </div>
              {/* Stats row */}
              <div className="flex items-center gap-6 text-center">
                {[
                  { label: 'Flows scored', value: sessionSummary.total, color: 'text-primary' },
                  { label: 'Threats', value: sessionSummary.suspicious, color: sessionSummary.suspicious > 0 ? 'text-orange-400' : 'text-emerald-400' },
                  { label: 'Safe', value: sessionSummary.safe, color: 'text-emerald-400' },
                  ...(isAdmin ? [{ label: 'Blocked intrusions', value: blockedThreats.size, color: 'text-rose-400' }] : []),
                  { label: 'Packets', value: sessionSummary.packetsCaptured, color: 'text-foreground' },
                ].map(({ label, value, color }) => (
                  <div key={label}>
                    <div className={cn('text-2xl font-bold tabular-nums', color)}>{formatNumber(value)}</div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ══ Threat feed ═════════════════════════════════════════════════════ */}
      {actionNotice && (
        <Alert variant="success" title="Action completed">{actionNotice}</Alert>
      )}
      {!npcapMissing && (streaming || flows.length > 0 || blockedThreats.size > 0 || removedCount > 0) && (
        <ThreatFeed
          flows={flows}
          streaming={streaming}
          total={total}
          suspicious={visibleSuspicious}
          removedThreats={isAdmin ? removedThreats.size : 0}
          blockedThreats={isAdmin ? blockedThreats.size : 0}
          onRemoveFlow={isAdmin ? handleRemoveFlow : undefined}
          onBlockIntrusion={isAdmin ? handleBlockIntrusion : undefined}
          blockedThreatIndexes={isAdmin ? [...blockedThreats] : []}
          blockingFlowIndex={isAdmin ? blockingFlowIndex : null}
          emptyMessage='Click "Start live capture" to begin monitoring.'
          waitingMessage="Monitoring… flows appear when TCP connections close or go idle (up to 12s)."
        />
      )}

      {/* Empty state */}
      {!npcapMissing && !streaming && flows.length === 0 && !sessionSummary && (
        <div className="relative overflow-hidden rounded-2xl border border-border/50 bg-panel/40 py-20 text-center">
          <div className="pointer-events-none absolute inset-0 grid-line opacity-30" />
          <div className="relative space-y-4">
            <div className="mx-auto grid h-20 w-20 place-items-center rounded-3xl border border-primary/20 bg-primary/5 shadow-[0_0_40px_rgba(34,211,238,0.1)]">
              <Wifi className="h-10 w-10 text-primary/50" />
            </div>
            <div>
              <p className="text-lg font-semibold text-muted-foreground">Ready to monitor</p>
              <p className="mt-1 text-sm text-muted-foreground/60 max-w-md mx-auto">
                Select your network interface and click Start. Every connection will be rated — Safe or a named threat with steps to take.
              </p>
            </div>
            {/* Feature pills */}
            <div className="flex flex-wrap justify-center gap-2 pt-2">
              {['Real-time scoring', 'Threat explanations', 'Precaution steps', '100-tree Random Forest', 'CICIDS2017 trained'].map(f => (
                <span key={f} className="rounded-full border border-border/60 bg-background/40 px-3 py-1 text-[11px] text-muted-foreground">
                  {f}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
