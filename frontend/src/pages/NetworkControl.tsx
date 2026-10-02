import { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, Clock, RefreshCw, Ban, Plus, Unlock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useAuth } from '@/context/AuthContext'
import { api, errorMessage } from '@/lib/api'

type NetworkStatusHistoryEntry = {
  started_at?: string | null
  status: string
  source?: string | null
  reason?: string | null
  changed_by?: string | null
}

type NetworkBlockRule = {
  id: string
  network: string
  reason: string
  active: boolean
  source_alert_id?: string | null
  activated_at?: string | null
  released_at?: string | null
}

export default function NetworkControl() {
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<any>(null)
  const [history, setHistory] = useState<any[]>([])
  const [evaluating, setEvaluating] = useState(false)
  const [evalResult, setEvalResult] = useState<any>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [newStatus, setNewStatus] = useState('')
  const [reason, setReason] = useState('')
  const [confirm, setConfirm] = useState('')
  const [blockRules, setBlockRules] = useState<NetworkBlockRule[]>([])
  const [blockNetwork, setBlockNetwork] = useState('')
  const [blockReason, setBlockReason] = useState('')
  const [savingBlock, setSavingBlock] = useState(false)

  const loadStatus = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const s = await api.get('/admin/network/status')
      setStatus(s)
      const response = await api.get<{ items: NetworkStatusHistoryEntry[] }>(
        '/admin/network/status/history?limit=20',
      )
      setHistory(response.items ?? [])
      const blocks = await api.get<{ items: NetworkBlockRule[] }>('/admin/network/blocks')
      setBlockRules(blocks.items ?? [])
    } catch (e: any) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (user?.role === 'admin') loadStatus() }, [user, loadStatus])

  const handleEvaluate = async () => {
    setEvaluating(true)
    try {
      const res = await api.post('/admin/network/status/evaluate?apply=false')
      setEvalResult(res)
    } catch (e: any) {
      setError(errorMessage(e))
    } finally {
      setEvaluating(false)
    }
  }

  const handleApplyStatus = async () => {
    if (!newStatus || confirm !== 'confirm' || !reason) return
    try {
      await api.post('/admin/network/status', { status: newStatus, reason, confirm: true })
      setDialogOpen(false)
      setNewStatus('')
      setReason('')
      setConfirm('')
      loadStatus()
    } catch (e: any) {
      setError(errorMessage(e))
    }
  }

  const addBlockRule = async () => {
    if (!blockNetwork.trim() || !blockReason.trim()) return
    setSavingBlock(true)
    setError(null)
    try {
      await api.post('/admin/network/blocks', {
        network: blockNetwork.trim(),
        reason: blockReason.trim(),
      })
      setBlockNetwork('')
      setBlockReason('')
      await loadStatus()
    } catch (e: any) {
      setError(errorMessage(e))
    } finally {
      setSavingBlock(false)
    }
  }

  const releaseBlockRule = async (rule: NetworkBlockRule) => {
    setError(null)
    try {
      await api.del(`/admin/network/blocks/${rule.id}`)
      await loadStatus()
    } catch (e: any) {
      setError(errorMessage(e))
    }
  }

  if (user?.role !== 'admin') return <div className="p-8 text-center"><h2 className="text-xl font-semibold mb-2">Access denied</h2><p className="text-muted-foreground">Admin only.</p></div>

  if (loading) return <div className="p-8 space-y-4"><Skeleton className="h-24 w-full" /><Skeleton className="h-64 w-full" /></div>

  const st = status?.status ?? 'unknown'
  const label = status?.label ?? 'Unknown'
  const tone = status?.tone ?? 'info'
  const source = status?.source ?? 'system'
  const indicators = status?.indicators ?? {}
  const triggers = status?.triggers ?? []

  const validStatuses = ['NORMAL','HIGH_TRAFFIC','UNDER_INVESTIGATION','ELEVATED_THREAT','CRITICAL_THREAT','MAINTENANCE']

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-2">
        <div className="rounded-lg bg-amber-500/10 p-2"><ShieldCheck className="h-5 w-5 text-amber-400" /></div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Network Control Center</h1>
          <p className="text-sm text-muted-foreground">Operational network state — derived from detection indicators.</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-base">Current Status</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-2"><Badge variant={tone==='danger'?'danger':tone==='warning'?'warning':'default'}>{label}</Badge><span className="text-xs text-muted-foreground">source: {source}</span></div>
            <div className="text-xs text-muted-foreground">Status key: {st}</div>
            <div className="text-xs"><span className="text-muted-foreground">Reason:</span> <span className="font-medium">{status?.reason ?? 'Not set'}</span></div>
            <div className="text-xs"><span className="text-muted-foreground">Changed by:</span> <span className="font-medium">{status?.changed_by ?? 'system'}</span></div>
            <Button size="sm" onClick={() => setDialogOpen(true)}>Change Status</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-base">Indicators & Triggers</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-xs">
            {Object.entries(indicators).slice(0,6).map(([k,v]) => (
              <div key={k} className="flex justify-between border-b border-border/30 py-1"><span className="text-muted-foreground">{k}</span><span className="font-medium">{typeof v==='number'?v.toFixed(2):String(v ?? '—')}</span></div>
            ))}
            <div className="pt-1"><span className="font-medium">Active triggers</span> <span className="text-muted-foreground">{triggers.length}</span></div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-base">Evaluation</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            <div className="flex gap-2"><Button size="sm" onClick={handleEvaluate} disabled={evaluating}>{evaluating ? <RefreshCw className="h-3 w-3 animate-spin mr-1" /> : null}Evaluate</Button></div>
            {evalResult && (
              <div className="rounded-md bg-muted p-3 text-xs space-y-2">
                <div><span className="font-medium">Recommended:</span> {evalResult.recommendation?.status ?? '--'}</div>
                <div><span className="font-medium">Reason:</span> {evalResult.recommendation?.reason ?? '--'}</div>
                <div><span className="font-medium">Confidence:</span> {evalResult.recommendation?.confidence ?? '--'}</div>
                {evalResult.recommendation?.triggers?.map((t:any,i:number) => <div key={i} className="text-muted-foreground">{t.metric} {t.operator} {t.threshold} (actual {t.actual})</div>)}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><Clock className="h-4 w-4" />Status History</CardTitle></CardHeader>
        <CardContent>
          {history.length === 0 ? <div className="text-xs text-muted-foreground">No history available.</div> : (
            <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="border-b"><th className="text-left py-2 font-medium">Time</th><th>Status</th><th>Source</th><th>Reason</th><th>Changed by</th></tr></thead><tbody>{history.map((h:any,i:number) => (
              <tr key={i} className="border-b border-border/40"><td className="py-2 text-muted-foreground">{h.started_at ? new Date(h.started_at).toLocaleString() : '-'}</td><td><Badge variant="outline" className="text-[10px]">{h.status}</Badge></td><td>{h.source}</td><td className="max-w-xs truncate">{h.reason ?? '-'}</td><td>{h.changed_by ?? '-'}</td></tr>
            ))}</tbody></table></div>
          )}
        </CardContent>
      </Card>

      {error && <div className="rounded-lg border border-destructive bg-destructive/10 p-4 text-sm text-destructive">{error}</div>}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base"><Ban className="h-4 w-4 text-rose-400" />Managed IP / CIDR Blocklist</CardTitle>
          <p className="text-xs text-muted-foreground">
            Active entries label matching source IPs in future analyzed flow data and help admins track response policy.
            They do not block live packets or configure a firewall.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-[1fr_2fr_auto] md:items-end">
            <div className="space-y-1"><Label htmlFor="block-network">IP address or CIDR</Label><Input id="block-network" value={blockNetwork} onChange={(event) => setBlockNetwork(event.target.value)} placeholder="203.0.113.8 or 203.0.113.0/24" /></div>
            <div className="space-y-1"><Label htmlFor="block-reason">Reason</Label><Input id="block-reason" value={blockReason} onChange={(event) => setBlockReason(event.target.value)} placeholder="Why is this source network on the blocklist?" /></div>
            <Button onClick={addBlockRule} disabled={savingBlock || !blockNetwork.trim() || !blockReason.trim()}><Plus className="h-4 w-4" />Add policy</Button>
          </div>
          {blockRules.length === 0 ? (
            <div className="rounded-md border border-dashed p-5 text-center text-xs text-muted-foreground">No IP/CIDR policies have been added.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b text-left"><th className="py-2">Network</th><th>State</th><th>Reason</th><th>Added</th><th className="text-right">Action</th></tr></thead>
                <tbody>{blockRules.map((rule) => (
                  <tr key={rule.id} className="border-b border-border/40">
                    <td className="py-2 font-mono">{rule.network}</td>
                    <td><Badge variant={rule.active ? 'danger' : 'outline'}>{rule.active ? 'Active policy' : 'Released'}</Badge></td>
                    <td className="max-w-sm truncate">{rule.reason}</td>
                    <td>{rule.activated_at ? new Date(rule.activated_at).toLocaleString() : '—'}</td>
                    <td className="text-right">{rule.active && <Button size="sm" variant="outline" onClick={() => releaseBlockRule(rule)}><Unlock className="h-3 w-3" />Release</Button>}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-4 text-xs text-amber-900">
        <div className="font-semibold mb-1">Simulation / Real data</div>
        <div>Network status is derived from stored detection indicators, thresholds, and active alerts. When no real live capture exists, the system uses historical CICIDS2017 patterns — clearly labeled above. This is defensive monitoring only; no automatic blocking is performed.</div>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Change Network Status</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div><Label>New Status</Label><div className="flex flex-wrap gap-2 mt-1">{validStatuses.map(s => <button key={s} onClick={() => setNewStatus(s)} className={`text-xs px-2 py-1 rounded-md border ${newStatus===s?'bg-primary text-primary-foreground border-primary':'bg-background border-border'}`}>{s.replace('_',' ')}</button>)}</div></div>
            <div><Label htmlFor="status-reason">Reason</Label><textarea id="status-reason" value={reason} onChange={e => setReason(e.target.value)} placeholder="Why is status changing?" rows={3} className="flex min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" /></div>
            <div><Label>Confirm (type "confirm")</Label><Input value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="confirm" /></div>
          </div>
          <div className="flex justify-end gap-2 border-t border-border/70 pt-3"><Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button><Button onClick={handleApplyStatus} disabled={!newStatus || confirm !== 'confirm' || !reason}>Apply</Button></div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
