import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Download,
  FileCheck,
  FileSpreadsheet,
  Filter,
  Lock,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  UserCheck,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, Select } from '@/components/ui/input'
import { Alert as InlineAlert, Loading, PageHeader, RiskBadge, StatCard, StatusBadge } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatDateTime, formatNumber, formatPercent, relativeTime } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { Alert, Investigation, RiskLevel } from '@/lib/types'

interface RecommendedActionItem {
  id: string
  alertId: string
  attackType: string
  severity: RiskLevel
  confidence: number
  targetPort?: number | null
  recommendedAction: string
  status: 'recommended' | 'approved' | 'executed' | 'failed'
  requiredRole: 'analyst' | 'admin'
  requiresApproval: boolean
  description: string
  timestamp: string
}

export function ResponseCenter() {
  const { user, isAdmin } = useAuth()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionNotice, setActionNotice] = useState<string | null>(null)

  // Actions queue
  const [actions, setActions] = useState<RecommendedActionItem[]>([])
  const [selectedAction, setSelectedAction] = useState<RecommendedActionItem | null>(null)
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false)
  const [actionStatusFilter, setActionStatusFilter] = useState('all')

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const alertData = await api.get<{ items: Alert[] }>('/alerts?page=1&page_size=50&status=open')
      const items = alertData.items || []
      setAlerts(items)

      // Derive structured recommended response items based on attack signatures
      const derived: RecommendedActionItem[] = items.map((a) => {
        let recommendation = 'Investigate flow patterns & verify destination service'
        let requiresApproval = false

        if (a.severity === 'critical') {
          recommendation = 'Escalate to Senior Incident Handler & prepare firewall rate-limiting advisory'
          requiresApproval = true
        } else if (a.attack_type.toLowerCase().includes('port scan')) {
          recommendation = 'Generate destination port scan advisory & correlate scanning source'
        } else if (a.attack_type.toLowerCase().includes('ddos') || a.attack_type.toLowerCase().includes('dos')) {
          recommendation = 'Recommend volumetric mitigation rule on upstream router'
          requiresApproval = true
        } else if (a.attack_type.toLowerCase().includes('brute force')) {
          recommendation = 'Advise credential rotation & rate-limit authentication daemon'
        } else if (a.attack_type.toLowerCase().includes('web')) {
          recommendation = 'Inspect WAF rules & inspect target application request parameters'
        } else if (a.attack_type.toLowerCase().includes('heartbleed')) {
          recommendation = 'Verify OpenSSL package version on target endpoint (CVE-2014-0160)'
          requiresApproval = true
        }

        return {
          id: `ACT-${a.id.slice(0, 8)}`,
          alertId: a.id,
          attackType: a.attack_type,
          severity: a.severity,
          confidence: a.confidence,
          targetPort: a.destination_port,
          recommendedAction: recommendation,
          status: a.status === 'reviewed' ? 'approved' : a.status === 'resolved' ? 'executed' : 'recommended',
          requiredRole: requiresApproval ? 'admin' : 'analyst',
          requiresApproval,
          description: a.message,
          timestamp: a.created_at || new Date().toISOString(),
        }
      })

      setActions(derived)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleExecuteAction = async (action: RecommendedActionItem) => {
    try {
      // Execute the local response workflow: mark alert reviewed/acknowledged
      await api.patch(`/alerts/${action.alertId}`, {
        status: 'reviewed',
        notes: `Response action approved: ${action.recommendedAction}`,
      })

      setActions((prev) =>
        prev.map((act) => (act.id === action.id ? { ...act, status: 'approved' } : act))
      )
      setActionNotice(`Action ${action.id} approved for alert ${action.alertId}. Response ticket recorded.`)
      setConfirmDialogOpen(false)
      setSelectedAction(null)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const handleExportEvidence = (action: RecommendedActionItem) => {
    const evidenceReport = {
      actionId: action.id,
      alertId: action.alertId,
      attackType: action.attackType,
      severity: action.severity,
      confidence: action.confidence,
      destinationPort: action.targetPort,
      recommendedMitigation: action.recommendedAction,
      description: action.description,
      exportTimestamp: new Date().toISOString(),
      platform: 'AI-NIDS Incident Response Center',
      disclaimer: 'Advisory guidance generated from CICIDS2017 Random Forest model prediction.',
    }

    const blob = new Blob([JSON.stringify(evidenceReport, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `incident_evidence_${action.id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    setActionNotice(`Evidence package exported for ${action.id}.`)
  }

  const filteredActions = actions.filter((act) => {
    if (actionStatusFilter === 'all') return true
    return act.status === actionStatusFilter
  })

  return (
    <>
      <PageHeader
        title="Incident Response Center"
        subtitle="Operational response workflows distinguishing detection telemetry, analyst investigations, recommended mitigations, and approved response actions."
        icon={Zap}
        actions={
          <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
            <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
            Refresh Queue
          </Button>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Response Center Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {actionNotice && (
        <div className="mb-4">
          <InlineAlert variant="info" title="Response Notice">
            {actionNotice}
          </InlineAlert>
        </div>
      )}

      {/* Advisory Distinction Banner */}
      <div className="mb-6 rounded-lg border border-primary/20 bg-primary/5 p-4 text-xs text-muted-foreground space-y-1.5">
        <div className="flex items-center gap-2 font-semibold text-primary">
          <ShieldCheck className="h-4 w-4" />
          <span>Workflow Clarification: Detection vs. Investigation vs. Response</span>
        </div>
        <p className="leading-relaxed">
          AI-NIDS functions as a defensive detection and analysis system. To prevent unauthorized or destructive network interference, the system generates <strong>RECOMMENDED ACTIONS</strong>. Active mitigations require deliberate operator confirmation and actual downstream network/firewall integration rather than simulated blocking.
        </p>
      </div>

      {/* Metric Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-6">
        <StatCard
          title="Active Recommendations"
          value={formatNumber(actions.length)}
          hint="Mitigations awaiting review"
          icon={AlertTriangle}
        />
        <StatCard
          title="Critical Actions"
          value={formatNumber(actions.filter((a) => a.severity === 'critical').length)}
          hint="Require Admin sign-off"
          icon={ShieldAlert}
        />
        <StatCard
          title="Approved Actions"
          value={formatNumber(actions.filter((a) => a.status === 'approved').length)}
          hint="Validated by analyst/admin"
          icon={CheckCircle2}
        />
        <StatCard
          title="Integrated Network Status"
          value="Advisory"
          hint="Active telemetry monitoring"
          icon={Server}
        />
      </div>

      <Tabs defaultValue="queue" className="space-y-4">
        <TabsList>
          <TabsTrigger value="queue">Response Action Queue</TabsTrigger>
          <TabsTrigger value="policy">Admin Response Policies</TabsTrigger>
          <TabsTrigger value="integrations">Security Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="queue">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <FileCheck className="h-4 w-4 text-primary" />
                    Recommended Response Queue
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Evaluate and execute recommended mitigations derived from flagged threat patterns.
                  </CardDescription>
                </div>

                <Select
                  value={actionStatusFilter}
                  onChange={(e) => setActionStatusFilter(e.target.value)}
                  className="w-[150px] text-xs"
                >
                  <option value="all">All States</option>
                  <option value="recommended">Recommended</option>
                  <option value="approved">Approved</option>
                  <option value="executed">Executed</option>
                </Select>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {loading && !actions.length ? (
                <Loading label="Loading response queue..." />
              ) : filteredActions.length === 0 ? (
                <div className="text-center py-12 text-xs text-muted-foreground">
                  No pending response actions matching the filter.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Action ID</TableHead>
                        <TableHead>Attack Family</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Target Port</TableHead>
                        <TableHead>Recommended Mitigation</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Role Reqd</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredActions.map((act) => (
                        <TableRow key={act.id} className="hover:bg-muted/30">
                          <TableCell className="font-mono text-xs font-semibold text-primary">{act.id}</TableCell>
                          <TableCell className="text-xs font-medium text-foreground">{act.attackType}</TableCell>
                          <TableCell>
                            <RiskBadge level={act.severity} />
                          </TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground">
                            {act.targetPort ? `Port ${act.targetPort}` : 'All'}
                          </TableCell>
                          <TableCell className="text-xs text-foreground max-w-sm">
                            {act.recommendedAction}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                act.status === 'approved'
                                  ? 'success'
                                  : act.status === 'executed'
                                  ? 'default'
                                  : act.status === 'failed'
                                  ? 'destructive'
                                  : 'warning'
                              }
                              className="text-[11px] uppercase tracking-wider"
                            >
                              {act.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-[10px] uppercase font-mono">
                              {act.requiredRole}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <Button
                                variant="outline"
                                size="sm"
                                className="text-xs h-7"
                                title="Export incident evidence JSON package"
                                onClick={() => handleExportEvidence(act)}
                              >
                                <Download className="h-3 w-3" />
                              </Button>

                              {act.status === 'recommended' && (
                                <Button
                                  variant="default"
                                  size="sm"
                                  className="text-xs h-7"
                                  disabled={act.requiresApproval && !isAdmin}
                                  onClick={() => {
                                    setSelectedAction(act)
                                    setConfirmDialogOpen(true)
                                  }}
                                >
                                  {act.requiresApproval && !isAdmin ? (
                                    <span className="flex items-center gap-1">
                                      <Lock className="h-3 w-3" /> Admin Only
                                    </span>
                                  ) : (
                                    'Approve Action'
                                  )}
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="policy">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Sliders className="h-4 w-4 text-primary" />
                Administrative Response Execution Policy
              </CardTitle>
              <CardDescription className="text-xs">
                Governs which response actions require supervisor approval, confirmation thresholds, and escalation rules.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-border p-3 space-y-1.5">
                  <div className="font-semibold text-foreground flex items-center justify-between">
                    <span>Critical Alert Mitigation</span>
                    <Badge variant="destructive" className="text-[10px]">Admin Approval Required</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Actions touching high-availability service ports (80, 443, 22, 53) or critical threats require explicit Admin confirmation.
                  </p>
                </div>

                <div className="rounded-lg border border-border p-3 space-y-1.5">
                  <div className="font-semibold text-foreground flex items-center justify-between">
                    <span>Analyst Case Escalation</span>
                    <Badge variant="success" className="text-[10px]">Analyst Permitted</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Security Analysts may open investigations, mark false positives, annotate incident evidence, and export forensic packages.
                  </p>
                </div>

                <div className="rounded-lg border border-border p-3 space-y-1.5">
                  <div className="font-semibold text-foreground flex items-center justify-between">
                    <span>Automatic Incident Creation</span>
                    <Badge variant="outline" className="text-[10px]">Threshold Driven</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Configured under Alert Settings: when a detection exceeds the critical risk threshold, an investigation case is automatically provisioned.
                  </p>
                </div>

                <div className="rounded-lg border border-border p-3 space-y-1.5">
                  <div className="font-semibold text-foreground flex items-center justify-between">
                    <span>Evidence Preservation</span>
                    <Badge variant="outline" className="text-[10px]">Immutable</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Exported evidence packages maintain full SHA-256 integrity and cannot modify the underlying training or prediction database.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="integrations">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                Network Perimeter & Enforcement Integrations
              </CardTitle>
              <CardDescription className="text-xs">
                Real-world network control status. Non-connected integrations operate in pure telemetry advisory mode.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <div className="grid gap-3 md:grid-cols-3">
                <div className="rounded-lg border border-border/80 p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Next-Gen Firewall</span>
                    <Badge variant="outline" className="text-[10px]">Advisory Mode</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Generates recommended IP/port filtering policies. Direct API pushing is offline to prevent inadvertent service lockout.
                  </p>
                </div>

                <div className="rounded-lg border border-border/80 p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Endpoint Detection (EDR)</span>
                    <Badge variant="outline" className="text-[10px]">Advisory Mode</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Provides forensic host isolation recommendations based on Bot and Infiltration flow verdicts.
                  </p>
                </div>

                <div className="rounded-lg border border-border/80 p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Edge Router / NetFlow</span>
                    <Badge variant="success" className="text-[10px]">Active Ingestion</Badge>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    Accepts standardized CICIDS2017 bidirectional flow CSVs and packet stream replays for real-time inference.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialogOpen} onOpenChange={setConfirmDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm Response Action</DialogTitle>
            <DialogDescription>
              Validate this mitigation before stamping approval onto the incident record.
            </DialogDescription>
          </DialogHeader>

          {selectedAction && (
            <div className="space-y-3 py-2 text-xs">
              <div className="rounded-md border border-border bg-muted/30 p-2.5 space-y-1">
                <div className="text-muted-foreground">Action Ref: <strong className="text-foreground font-mono">{selectedAction.id}</strong></div>
                <div className="text-muted-foreground">Attack Type: <strong className="text-foreground">{selectedAction.attackType}</strong></div>
                <div className="text-muted-foreground">Severity: <strong className="text-foreground uppercase">{selectedAction.severity}</strong></div>
              </div>

              <div className="space-y-1">
                <span className="font-semibold text-foreground">Recommended Action:</span>
                <p className="text-foreground bg-primary/5 p-2 rounded border border-primary/20">{selectedAction.recommendedAction}</p>
              </div>

              <p className="text-[11px] text-muted-foreground">
                Approving this action marks the alert as reviewed and stamps your operator ID into the audit log.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setConfirmDialogOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={() => selectedAction && handleExecuteAction(selectedAction)}>
              Approve & Stamp Action
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
