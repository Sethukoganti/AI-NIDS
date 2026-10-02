import { useCallback, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  ExternalLink,
  FileText,
  Filter,
  Layers,
  MessageSquare,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCheck,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input, Select } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert as InlineAlert, KeyValue, Loading, PageHeader, RiskBadge, StatCard, StatusBadge } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatDateTime, formatNumber, formatPercent, relativeTime } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { Investigation, InvestigationPage, RiskLevel } from '@/lib/types'

export function Investigations() {
  const { user } = useAuth()
  const [params, setParams] = useSearchParams()
  const [items, setItems] = useState<Investigation[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [stats, setStats] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [statusFilter, setStatusFilter] = useState(params.get('status') || 'all')
  const [priorityFilter, setPriorityFilter] = useState('all')
  const [search, setSearch] = useState('')

  // Detail Modal
  const [selectedInv, setSelectedInv] = useState<Investigation | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [newNote, setNewNote] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [statusChange, setStatusChange] = useState('')
  const [aiSummary, setAiSummary] = useState<string | null>(null)
  const [aiGenerating, setAiGenerating] = useState(false)

  // Create Dialog
  const [creatingOpen, setCreatingOpen] = useState(false)
  const [createTitle, setCreateTitle] = useState('')
  const [createPriority, setCreatePriority] = useState<RiskLevel>('medium')
  const [createSummary, setCreateSummary] = useState('')
  const [submittingCreate, setSubmittingCreate] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const qs = new URLSearchParams({
        page: String(page),
        page_size: '25',
      })
      if (statusFilter !== 'all') qs.set('status', statusFilter)
      if (priorityFilter !== 'all') qs.set('priority', priorityFilter)
      if (search) qs.set('search', search)

      const [pageData, statsData] = await Promise.all([
        api.get<InvestigationPage>(`/analyst/investigations?${qs.toString()}`),
        api.get<Record<string, number>>('/analyst/investigations/stats'),
      ])
      setItems(pageData.items)
      setTotal(pageData.total)
      setPages(pageData.pages)
      setStats(statsData)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [page, statusFilter, priorityFilter, search])

  useEffect(() => {
    loadData()
  }, [loadData])

  const openDetail = async (id: string) => {
    setDetailLoading(true)
    setAiSummary(null)
    try {
      const inv = await api.get<Investigation>(`/analyst/investigations/${id}`)
      setSelectedInv(inv)
      setStatusChange(inv.status)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setDetailLoading(false)
    }
  }

  const handleAddNote = async () => {
    if (!selectedInv || !newNote.trim()) return
    setAddingNote(true)
    try {
      const updated = await api.patch<Investigation>(`/analyst/investigations/${selectedInv.id}`, {
        note: newNote.trim(),
      })
      setSelectedInv(updated)
      setNewNote('')
      loadData()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setAddingNote(false)
    }
  }

  const handleStatusUpdate = async (nextStatus: string) => {
    if (!selectedInv) return
    try {
      const updated = await api.patch<Investigation>(`/analyst/investigations/${selectedInv.id}`, {
        status: nextStatus,
      })
      setSelectedInv(updated)
      setStatusChange(nextStatus)
      loadData()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const handleGenerateAiSummary = async () => {
    if (!selectedInv) return
    setAiGenerating(true)
    try {
      const res = await api.post<{ answer: string }>('/assistant/ask', {
        question: `Summarize investigation ${selectedInv.reference} (${selectedInv.title}). What was detected, what is the risk, and what are the recommended next steps?`,
        prediction_id: selectedInv.prediction_id || undefined,
      })
      setAiSummary(res.answer)
    } catch (err) {
      setAiSummary('Could not generate AI summary at this time.')
    } finally {
      setAiGenerating(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createTitle.trim()) return
    setSubmittingCreate(true)
    try {
      await api.post('/analyst/investigations', {
        title: createTitle.trim(),
        priority: createPriority,
        summary: createSummary.trim() || undefined,
      })
      setCreatingOpen(false)
      setCreateTitle('')
      setCreateSummary('')
      loadData()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSubmittingCreate(false)
    }
  }

  const evidence = selectedInv?.evidence as Record<string, any> | undefined
  const pred = evidence?.prediction
  const flow = evidence?.flow
  const drivers = evidence?.feature_deviation || []

  return (
    <>
      <PageHeader
        title="Investigation Center"
        subtitle="Manage and investigate confirmed threat detections and suspicious traffic bursts. Correlate flow features, SHAP factors, analyst notes, and resolution actions."
        icon={Shield}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
              <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreatingOpen(true)}>
              <Plus className="h-3.5 w-3.5" />
              New Investigation
            </Button>
          </div>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Investigation Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {/* Stats Counters */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 mb-6">
        <StatCard
          title="Total Cases"
          value={formatNumber(stats.total || 0)}
          hint="All recorded investigations"
          icon={Layers}
        />
        <StatCard
          title="Open"
          value={formatNumber(stats.open || 0)}
          hint="Awaiting analyst triage"
          icon={AlertTriangle}
        />
        <StatCard
          title="In Progress"
          value={formatNumber(stats.in_progress || 0)}
          hint="Active investigation"
          icon={Clock}
        />
        <StatCard
          title="Escalated"
          value={formatNumber(stats.escalated || 0)}
          hint="High severity escalation"
          icon={ShieldAlert}
        />
        <StatCard
          title="Resolved"
          value={formatNumber(stats.closed || 0)}
          hint="Remediated / closed"
          icon={CheckCircle2}
        />
      </div>

      {/* Filters */}
      <Card className="mb-4">
        <CardContent className="p-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[220px]">
                <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search reference, title, attack..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="pl-8 text-xs"
                />
              </div>

              <Select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value)
                  setPage(1)
                }}
                className="w-[140px] text-xs"
              >
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="pending">Pending</option>
                <option value="escalated">Escalated</option>
                <option value="closed">Closed</option>
              </Select>

              <Select
                value={priorityFilter}
                onChange={(e) => {
                  setPriorityFilter(e.target.value)
                  setPage(1)
                }}
                className="w-[140px] text-xs"
              >
                <option value="all">All Priorities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Select>
            </div>

            <div className="text-xs text-muted-foreground font-mono">
              Showing {items.length} of {total} cases
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {loading && !items.length ? (
            <Loading label="Loading investigations..." />
          ) : items.length === 0 ? (
            <div className="text-center py-12 text-xs text-muted-foreground">
              No investigations match the selected filters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Case Ref</TableHead>
                    <TableHead>Title & Attack Type</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>Notes</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((inv) => (
                    <TableRow key={inv.id} className="hover:bg-muted/30">
                      <TableCell className="font-mono text-xs font-semibold text-primary">
                        {inv.reference}
                      </TableCell>
                      <TableCell>
                        <div className="font-medium text-xs text-foreground">{inv.title}</div>
                        {inv.attack_type && (
                          <div className="text-[11px] text-muted-foreground">{inv.attack_type}</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <RiskBadge level={inv.priority} />
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            inv.status === 'closed'
                              ? 'success'
                              : inv.status === 'escalated'
                              ? 'destructive'
                              : inv.status === 'in_progress'
                              ? 'warning'
                              : 'outline'
                          }
                          className="text-[11px] uppercase tracking-wide"
                        >
                          {inv.status.replace('_', ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground font-mono">
                        {inv.assigned_to || 'Unassigned'}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <span className="inline-flex items-center gap-1 font-mono">
                          <MessageSquare className="h-3 w-3" /> {inv.notes?.length || 0}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {relativeTime(inv.updated_at || inv.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          onClick={() => openDetail(inv.id)}
                        >
                          Open Workspace
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Pagination */}
          {pages > 1 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-3 text-xs text-muted-foreground">
              <span>Page {page} of {pages}</span>
              <div className="flex gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(pages, p + 1))}
                  disabled={page >= pages}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Workspace Dialog */}
      <Dialog open={!!selectedInv} onOpenChange={(open) => !open && setSelectedInv(null)}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          {selectedInv && (
            <>
              <DialogHeader>
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-primary">{selectedInv.reference}</span>
                    <RiskBadge level={selectedInv.priority} />
                    <Badge variant="outline" className="text-xs uppercase">
                      {selectedInv.status.replace('_', ' ')}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Created {formatDateTime(selectedInv.created_at)}
                  </div>
                </div>
                <DialogTitle className="text-base text-foreground pt-1">{selectedInv.title}</DialogTitle>
                <DialogDescription className="text-xs">
                  {selectedInv.summary || 'Investigation opened for flagged network intrusion telemetry.'}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-2">
                {/* Status Switcher & Assignment */}
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border/80 bg-muted/20 p-3">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs font-semibold">Change Status:</Label>
                    <Select
                      value={statusChange}
                      onChange={(e) => handleStatusUpdate(e.target.value)}
                      className="text-xs w-[140px]"
                    >
                      <option value="open">Open</option>
                      <option value="in_progress">In Progress</option>
                      <option value="pending">Pending</option>
                      <option value="escalated">Escalated</option>
                      <option value="closed">Closed / Resolved</option>
                    </Select>
                  </div>

                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <UserCheck className="h-3.5 w-3.5 text-primary" />
                    <span>Assignee: <strong className="text-foreground">{selectedInv.assigned_to || user?.name || 'Unassigned'}</strong></span>
                  </div>
                </div>

                {/* Evidence Section */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <FileText className="h-3.5 w-3.5 text-primary" />
                      Observed Forensic Evidence
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-xs">
                    {pred ? (
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 rounded-md border border-border/60 bg-background/50 p-2.5">
                        <KeyValue label="Predicted Class" value={pred.predicted_class} />
                        <KeyValue label="Model Confidence" value={formatPercent(pred.confidence)} />
                        <KeyValue label="Risk Level" value={pred.risk_level?.toUpperCase()} />
                        <KeyValue label="Risk Score" value={pred.risk_score?.toFixed(3)} />
                      </div>
                    ) : (
                      <div className="text-muted-foreground">General investigation record (no individual flow linked).</div>
                    )}

                    {flow && (
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 rounded-md border border-border/60 bg-background/50 p-2.5 font-mono text-[11px]">
                        <div>Source: <span className="text-foreground font-semibold">{flow.source_ip || 'unknown'}:{flow.source_port || '?'}</span></div>
                        <div>Target: <span className="text-foreground font-semibold">{flow.destination_ip || 'unknown'}:{flow.destination_port || '?'}</span></div>
                        <div>Protocol: <span className="text-foreground">{flow.protocol || 'TCP'}</span></div>
                        <div>Packets/s: <span className="text-foreground">{formatNumber(flow.packet_rate || 0)}</span></div>
                      </div>
                    )}

                    {drivers.length > 0 && (
                      <div>
                        <span className="font-semibold text-muted-foreground">Top Feature Deviations vs Training Medians:</span>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {drivers.map((d: any, idx: number) => (
                            <Badge key={idx} variant="outline" className="text-[10px] font-mono">
                              {d.feature}: {d.deviation_from_median > 0 ? `+${d.deviation_from_median?.toFixed(1)}` : d.deviation_from_median?.toFixed(1)}σ
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* AI Summary Section */}
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                      <Sparkles className="h-3.5 w-3.5" /> AI Copilot Investigation Summary
                    </span>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs h-7"
                      onClick={handleGenerateAiSummary}
                      disabled={aiGenerating}
                    >
                      {aiGenerating ? 'Analyzing data...' : 'Generate AI Summary'}
                    </Button>
                  </div>
                  {aiSummary && (
                    <div className="rounded-md border border-border/60 bg-background/80 p-3 text-xs leading-relaxed whitespace-pre-line text-foreground">
                      {aiSummary}
                    </div>
                  )}
                </div>

                {/* Analyst Notes History */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <MessageSquare className="h-3.5 w-3.5 text-primary" /> Analyst Notes & Findings
                  </span>

                  <div className="space-y-1.5 max-h-48 overflow-y-auto rounded-md border border-border p-2">
                    {selectedInv.notes && selectedInv.notes.length > 0 ? (
                      selectedInv.notes.map((note, idx) => (
                        <div key={idx} className="rounded border border-border/50 bg-muted/20 p-2 text-xs">
                          <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
                            <span className="font-medium text-foreground">{note.author_name || note.author || 'Analyst'}</span>
                            <span>{relativeTime(note.timestamp)}</span>
                          </div>
                          <p className="text-foreground">{note.text}</p>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-4 text-xs text-muted-foreground">No notes recorded yet.</div>
                    )}
                  </div>

                  {/* Add note input */}
                  <div className="flex gap-2 pt-1">
                    <Input
                      placeholder="Add investigation observation or response finding..."
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      className="text-xs"
                      onKeyDown={(e) => e.key === 'Enter' && handleAddNote()}
                    />
                    <Button size="sm" onClick={handleAddNote} disabled={addingNote || !newNote.trim()}>
                      {addingNote ? 'Saving...' : 'Add Note'}
                    </Button>
                  </div>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" size="sm" onClick={() => setSelectedInv(null)}>
                  Close
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Manual Create Dialog */}
      <Dialog open={creatingOpen} onOpenChange={setCreatingOpen}>
        <DialogContent>
          <form onSubmit={handleCreate}>
            <DialogHeader>
              <DialogTitle>Open New Investigation</DialogTitle>
              <DialogDescription>
                Create a formal investigation ticket to correlate suspicious telemetry, document findings, and assign response actions.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-3">
              <div className="space-y-1">
                <Label htmlFor="title" className="text-xs">Investigation Title (Required)</Label>
                <Input
                  id="title"
                  placeholder="e.g., Suspicious Port 443 burst from external subnet"
                  value={createTitle}
                  onChange={(e) => setCreateTitle(e.target.value)}
                  className="text-xs"
                  required
                />
              </div>

              <div className="space-y-1">
                <Label htmlFor="priority" className="text-xs">Priority Severity</Label>
                <Select
                  id="priority"
                  value={createPriority}
                  onChange={(e) => setCreatePriority(e.target.value as RiskLevel)}
                  className="text-xs"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </Select>
              </div>

              <div className="space-y-1">
                <Label htmlFor="summary" className="text-xs">Initial Summary / Observations</Label>
                <Input
                  id="summary"
                  placeholder="Observed anomalous packet rates or sensitive port probes..."
                  value={createSummary}
                  onChange={(e) => setCreateSummary(e.target.value)}
                  className="text-xs"
                />
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" size="sm" onClick={() => setCreatingOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={submittingCreate || !createTitle.trim()}>
                {submittingCreate ? 'Creating...' : 'Create Case'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
