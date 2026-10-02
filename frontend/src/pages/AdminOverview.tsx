import { useState, useEffect, useMemo } from 'react'
import { LayoutDashboard, ShieldCheck, Activity, Brain, Database, Users, Bell, FileSearch, Zap, AlertTriangle, ChevronRight } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { PageHeader, Alert, NoData, StatCard } from '@/components/common'
import { useAuth } from '@/context/AuthContext'
import { api, errorMessage } from '@/lib/api'

export default function AdminOverview() {
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [networkStatus, setNetworkStatus] = useState<any>(null)
  const [systemHealth, setSystemHealth] = useState<any>(null)
  const [auditRecent, setAuditRecent] = useState<any>(null)
  const [settingsMeta, setSettingsMeta] = useState<any>(null)

  useEffect(() => {
    if (user?.role !== 'admin') return
    setLoading(true)
    setError(null)
    Promise.all([
      api.get('/admin/network/status').catch(() => null),
      api.get('/admin/system/health').catch(() => null),
      api.get('/admin/audit-logs?page=1&page_size=10').catch(() => null),
      api.get('/admin/settings').catch(() => null),
    ]).then(([net, sys, audit, settings]) => {
      setNetworkStatus(net)
      setSystemHealth(sys)
      setAuditRecent(audit)
      setSettingsMeta(settings)
      setLoading(false)
    }).catch((e) => {
      setError(errorMessage(e))
      setLoading(false)
    })
  }, [user])

  if (user?.role !== 'admin') {
    return (
      <div className="p-8 text-center"><h2 className="text-xl font-semibold mb-2">Access denied</h2><p className="text-muted-foreground">Admin only.</p></div>
    )
  }

  if (loading) return <div className="p-8 space-y-4"><Skeleton className="h-32 w-full" /><Skeleton className="h-32 w-full" /><Skeleton className="h-32 w-full" /></div>
  if (error) return <div className="p-8"><div className="rounded-lg border border-destructive bg-destructive/10 p-4 text-destructive">{error}</div></div>

  const netStatus = networkStatus?.status ?? 'unknown'
  const netLabel = networkStatus?.label ?? 'Unknown'
  const netTone = networkStatus?.tone ?? 'info'
  const netIndicators = networkStatus?.indicators ?? {}
  const healthChecks = systemHealth?.checks ?? {}
  const healthStatus = systemHealth?.status ?? 'unknown'
  const auditItems = auditRecent?.items ?? []

  return (
    <div className="space-y-6">

      <PageHeader title="Admin Control Center" subtitle="Network, security, ML and system overview — derived from live API data" icon={LayoutDashboard} />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* Network */}
        <Card>
          <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="h-4 w-4 text-emerald-400" />Network Status</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-2"><Badge variant={netTone === 'danger' ? 'destructive' : netTone === 'warning' ? 'outline' : 'secondary'}>{netLabel}</Badge><span className="text-xs text-muted-foreground">{networkStatus?.source ?? 'system'}</span></div>
            <div className="grid grid-cols-2 gap-2 text-xs"><div className="rounded-md bg-muted p-2"><div className="text-muted-foreground">Status</div><div className="font-medium">{netStatus}</div></div><div className="rounded-md bg-muted p-2"><div className="text-muted-foreground">Evaluable</div><div className="font-medium">{networkStatus?.evaluable ? 'Yes' : 'No'}</div></div></div>
            {Object.entries(netIndicators).slice(0,5).map(([k,v]) => (
              <div key={k} className="flex justify-between text-xs border-b border-border/40 py-1"><span className="text-muted-foreground">{k}</span><span className="font-medium">{typeof v === 'number' ? v.toFixed(2) : String(v ?? '—')}</span></div>
            ))}
          </CardContent>
        </Card>

        {/* Security */}
        <Card>
          <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><AlertTriangle className="h-4 w-4 text-amber-400" />Security</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs"><div className="rounded-md bg-muted p-2"><div className="text-muted-foreground">Active alerts</div><div className="font-medium text-amber-400">{systemHealth?.audit_summary?.open_high_or_critical ?? '--'}</div></div><div className="rounded-md bg-muted p-2"><div className="text-muted-foreground">Investigations</div><div className="font-medium">{systemHealth?.investigation_stats?.open ?? '--'}</div></div></div>
            <div className="text-xs text-muted-foreground">Recent audit events visible in Audit Logs.</div>
            <Button size="sm" variant="outline" onClick={() => window.location.href = '/audit-logs'}>Open Audit Logs <ChevronRight className="h-3 w-3 ml-1" /></Button>
          </CardContent>
        </Card>

        {/* ML */}
        <Card>
          <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><Brain className="h-4 w-4 text-violet-400" />ML Model</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="text-xs"><span className="text-muted-foreground">Algorithm</span><span className="font-medium">{(systemHealth?.model as any)?.algorithm ?? "Random Forest"}</span></div>
            <div className="text-xs"><span className="text-muted-foreground">Test accuracy</span><span className="font-medium">{(systemHealth?.model as any)?.test_accuracy!=null?`${((systemHealth?.model as any).test_accuracy*100).toFixed(2)}%`:"--"}</span></div>
            <div className="text-xs"><span className="text-muted-foreground">Macro F1</span><span className="font-medium">{(systemHealth?.model as any)?.macro_f1 ?? "--"}</span></div>
            <div className="text-xs"><span className="text-muted-foreground">Classes</span><span className="font-medium">{(systemHealth?.model as any)?.classes ? (systemHealth?.model as any).classes.length : "--"}</span></div>
            <div className="text-xs text-muted-foreground">Model artifacts from backend ML pipeline.</div>
          </CardContent>
        </Card>

        {/* System */}
        <Card>
          <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><Zap className="h-4 w-4 text-cyan-400" />System Health</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-2"><Badge variant={healthStatus === 'healthy' ? 'default' : healthStatus === 'degraded' ? 'outline' : 'destructive'}>{healthStatus}</Badge></div>
            <div className="grid grid-cols-2 gap-2 text-xs">{Object.entries(healthChecks).slice(0,4).map(([k,v]) => (
              <div key={k} className="rounded-md bg-muted p-2"><div className="text-muted-foreground">{k}</div><div className="font-medium">{(v as any)?.ok ? 'OK' : 'Issue'}</div></div>
            ))}</div>
            <Button size="sm" variant="outline" onClick={() => window.location.href = '/system-health'}>Full Health <ChevronRight className="h-3 w-3 ml-1" /></Button>
          </CardContent>
        </Card>

        {/* Administration */}
        <Card className="md:col-span-2 lg:col-span-3">
          <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><Users className="h-4 w-4 text-rose-400" />Administration</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="rounded-md bg-muted p-3"><div className="text-muted-foreground">Active users</div><div className="text-lg font-semibold">{systemHealth?.audit_summary?.active_users ?? '--'}</div></div>
              <div className="rounded-md bg-muted p-3"><div className="text-muted-foreground">Analyst accounts</div><div className="text-lg font-semibold">{systemHealth?.audit_summary?.analyst_count ?? '--'}</div></div>
              <div className="rounded-md bg-muted p-3"><div className="text-muted-foreground">Admin actions (7d)</div><div className="text-lg font-semibold">{systemHealth?.audit_summary?.recent_admin_actions ?? '--'}</div></div>
              <div className="rounded-md bg-muted p-3"><div className="text-muted-foreground">Configuration changes</div><div className="text-lg font-semibold">{systemHealth?.audit_summary?.config_changes ?? '--'}</div></div>
            </div>
            <div className="text-xs text-muted-foreground">Recent audit entries: {auditItems.length > 0 ? auditItems.slice(0,3).map((a:any) => a.action).join(', ') : 'None loaded'}</div>
            <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => window.location.href = '/users'}>User Management</Button><Button size="sm" variant="outline" onClick={() => window.location.href = '/settings'}>Settings Center</Button><Button size="sm" variant="outline" onClick={() => window.location.href = '/network'}>Network Control</Button></div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
