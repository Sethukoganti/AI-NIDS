import { useState, useEffect, useCallback } from 'react'
import { Settings, Save, RotateCcw, AlertTriangle, ShieldCheck, Zap, Database, Bell, FileText, Wrench, Lock, Server } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { useAuth } from '@/context/AuthContext'
import { api, errorMessage } from '@/lib/api'

const SECTIONS = [
  { key: 'network', label: 'Network', icon: ShieldCheck, desc: 'Network configuration, status automation, monitoring mode.', perm: 'network.configure' },
  { key: 'detection', label: 'Detection', icon: Zap, desc: 'Prediction settings, risk thresholds, batch processing.', perm: 'detection.configure' },
  { key: 'alerts', label: 'Alerts', icon: AlarmIcon, desc: 'Severity thresholds, grouping, duplication, escalation.', perm: 'alerts.configure' },
  { key: 'model', label: 'Model', icon: BrainIcon, desc: 'Active version, deployment, runtime settings.', perm: 'model.configure' },
  { key: 'dataset', label: 'Dataset', icon: Database, desc: 'Dataset versioning, training candidates.', perm: 'settings.retention' },
  { key: 'notifications', label: 'Notifications', icon: Bell, desc: 'Notification categories, escalation policy.', perm: 'notifications.view' },
  { key: 'users', label: 'Users', icon: UserIcon, desc: 'Account maintenance, roles, access reset.', perm: 'users.manage' },
  { key: 'security', label: 'Security', icon: Lock, desc: 'Security settings, headers, rate limits.', perm: 'settings.security' },
  { key: 'data', label: 'Data Retention', icon: FileText, desc: 'Retention periods, log cleanup, archival.', perm: 'settings.retention' },
  { key: 'system', label: 'System', icon: Server, desc: 'System, logging, dashboard, API settings.', perm: 'settings.system' },
  { key: 'audit', label: 'Audit Logs', icon: Wrench, desc: 'Audit log settings and retention.', perm: 'audit.view' },
]

function AlarmIcon(p: any) { return <AlertTriangle {...p} /> }
function BrainIcon(p: any) { return <Zap {...p} /> } // placeholder
function UserIcon(p: any) { return <Settings {...p} /> } // placeholder

export default function SettingsCenter() {
  const { user } = useAuth()
  const [scopes, setScopes] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [edited, setEdited] = useState<Record<string, Record<string, string>>>({})
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [confirmScope, setConfirmScope] = useState('')
  const [notes, setNotes] = useState('')

  const loadAll = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const meta = await api.get('/admin/settings')
      const scopesData: Record<string, any> = {}
      for (const s of SECTIONS.map(x => x.key)) {
        try { const r = await api.get(`/admin/settings/${s}`); scopesData[s] = r } catch { scopesData[s] = null }
      }
      setScopes(scopesData)
    } catch (e: any) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (user?.role === 'admin') loadAll() }, [user, loadAll])

  const handleEdit = (scope: string, key: string, val: string | number | boolean) => {
    setEdited(prev => ({ ...prev, [scope]: { ...(prev[scope] || {}), [key]: String(val) } }))
  }

  const handleSave = async (scope: string) => {
    if (!edited[scope]) return
    const values = edited[scope]
    const dangerous = scope === 'system' || scope === 'security' || scope === 'model'
    if (dangerous) {
      setConfirmScope(scope)
      setConfirmOpen(true)
      return
    }
    await saveScope(scope, values)
  }

  const saveScope = async (scope: string, values: Record<string, string>) => {
    try {
      await api.put(`/admin/settings/${scope}`, { values: values, note: notes || undefined })
      setEdited(prev => { const n = { ...prev }; delete n[scope]; return n })
      setNotes('')
      loadAll()
    } catch (e: any) {
      setError(errorMessage(e))
    }
  }

  const handleConfirmSave = () => { setConfirmOpen(false); saveScope(confirmScope, edited[confirmScope] || {}) }

  if (user?.role !== 'admin') return <div className="p-8 text-center"><h2 className="text-xl font-semibold mb-2">Access denied</h2><p className="text-muted-foreground">Admin only.</p></div>
  if (loading) return <div className="p-8 space-y-4"><Skeleton className="h-32 w-full" /><Skeleton className="h-32 w-full" /></div>
  if (error) return <div className="p-8"><div className="rounded-lg border border-destructive bg-destructive/10 p-4 text-destructive">{error}</div></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-2"><div className="rounded-lg bg-violet-500/10 p-2"><Settings className="h-5 w-5 text-violet-400" /></div><div><h1 className="text-2xl font-bold tracking-tight">Settings Center</h1><p className="text-sm text-muted-foreground">Eleven configuration sections — validated, revisioned and audited.</p></div></div>

      <Tabs defaultValue="network" className="space-y-4">
        <TabsList className="flex-wrap h-auto gap-1"><div className="flex flex-wrap gap-1">
          {SECTIONS.map(s => <TabsTrigger key={s.key} value={s.key} className="text-xs"><s.icon className="h-3 w-3 mr-1" />{s.label}</TabsTrigger>)}
        </div></TabsList>
        {SECTIONS.map(s => {
          const data = scopes[s.key]
          const fields = data?.fields || data?.sections?.flatMap((sec: any) => sec.fields || []) || []
          const isEdited = !!edited[s.key]
          return (
            <TabsContent key={s.key} value={s.key}>
              <Card>
                <CardHeader><CardTitle className="text-base flex items-center gap-2"><s.icon className="h-4 w-4 text-violet-400" />{s.label}</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="text-xs text-muted-foreground">{s.desc}</div>
                  {fields.length === 0 ? <div className="text-xs text-muted-foreground">No fields loaded from backend.</div> : (
                    <div className="space-y-3">
                      {fields.map((f: any) => (
                        <div key={f.key || f.name} className="grid md:grid-cols-3 gap-3 items-start rounded-md border border-border/40 bg-muted/30 p-3">
                          <div>
                            <div className="text-xs font-medium">{f.title || f.name || f.key}</div>
                            <div className="text-[10px] text-muted-foreground">{f.description}</div>
                            <div className="text-[10px] text-muted-foreground">Current: <span className="font-medium text-foreground">{f.current ?? f.default ?? '-'}</span> · Recommended: <span className="font-medium">{f.recommended ?? '-'}</span></div>
                          </div>
                          <div className="md:col-span-2">
                            <Input
                              value={isEdited && edited[s.key]?.[f.key || f.name] !== undefined ? edited[s.key][f.key || f.name] : String(f.current ?? f.default ?? '')}
                              onChange={e => handleEdit(s.key, f.key || f.name, e.target.value)}
                              className="text-sm"
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex gap-2 items-center"><Button size="sm" onClick={() => handleSave(s.key)} disabled={!isEdited}>Save Changes</Button><Button size="sm" variant="outline" onClick={() => { setEdited(prev => { const n={...prev}; delete n[s.key]; return n }) }}>Reset</Button></div>
                  <div className="text-[10px] text-muted-foreground">Changes are validated by the backend, audited automatically, and shown to admins in Audit Logs.</div>
                </CardContent>
              </Card>
            </TabsContent>
          )
        })}
      </Tabs>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent><DialogHeader><DialogTitle>Confirm Dangerous Change</DialogTitle></DialogHeader>
          <div className="text-sm space-y-2"><p>You are changing a system-wide setting.</p><p>This may affect detection, alerts and processing.</p><p>Confirm by typing <code>confirm</code> below.</p><Input value={notes} onChange={e => setNotes(e.target.value)} placeholder="Reason for change (optional)" /></div>
          <DialogFooter><Button variant="outline" onClick={() => setConfirmOpen(false)}>Cancel</Button><Button onClick={handleConfirmSave} disabled={notes.length < 3}>Confirm & Save</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
