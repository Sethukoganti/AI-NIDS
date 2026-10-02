import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  Calendar,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Eye,
  FileText,
  Filter,
  History,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  User,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Input, Select } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert as InlineAlert, Loading, PageHeader, StatCard } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatDateTime, formatNumber, relativeTime } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { AuditLogEntry } from '@/lib/types'

export function AuditLogsPage() {
  const { isAdmin } = useAuth()
  const [items, setItems] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [search, setSearch] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  const [sinceDays, setSinceDays] = useState('7')

  // Detail Modal
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null)

  const loadAuditLogs = useCallback(async () => {
    if (!isAdmin) return
    setLoading(true)
    try {
      const qs = new URLSearchParams({
        page: String(page),
        page_size: '25',
        since_days: sinceDays,
      })
      if (search) qs.set('search', search)
      if (categoryFilter !== 'all') qs.set('category', categoryFilter)
      if (resultFilter !== 'all') qs.set('result', resultFilter)

      const res = await api.get<{ items: AuditLogEntry[]; total: number; pages: number }>(
        `/admin/audit-logs?${qs.toString()}`
      )
      setItems(res.items || [])
      setTotal(res.total || 0)
      setPages(res.pages || 1)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [isAdmin, page, search, categoryFilter, resultFilter, sinceDays])

  useEffect(() => {
    loadAuditLogs()
  }, [loadAuditLogs])

  if (!isAdmin) {
    return (
      <div className="p-8">
        <InlineAlert variant="error" title="Access Denied">
          Audit logs are restricted to administrators.
        </InlineAlert>
      </div>
    )
  }

  return (
    <>
      <PageHeader
        title="Audit & Compliance Logs"
        subtitle="Immutable security trail of administrative actions, user authentication events, network state changes, and configuration mutations."
        icon={History}
        actions={
          <Button variant="outline" size="sm" onClick={loadAuditLogs} disabled={loading}>
            <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
            Refresh Logs
          </Button>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Audit Log Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {/* Filters */}
      <Card className="mb-4">
        <CardContent className="p-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[220px]">
                <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search action, resource, IP..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="pl-8 text-xs"
                />
              </div>

              <Select
                value={categoryFilter}
                onChange={(e) => {
                  setCategoryFilter(e.target.value)
                  setPage(1)
                }}
                className="w-[140px] text-xs"
              >
                <option value="all">All Categories</option>
                <option value="auth">Auth & Login</option>
                <option value="network">Network State</option>
                <option value="config">Configuration</option>
                <option value="user">User Admin</option>
                <option value="investigation">Investigation</option>
                <option value="alert">Alerts</option>
              </Select>

              <Select
                value={resultFilter}
                onChange={(e) => {
                  setResultFilter(e.target.value)
                  setPage(1)
                }}
                className="w-[140px] text-xs"
              >
                <option value="all">All Results</option>
                <option value="success">Success</option>
                <option value="denied">Access Denied</option>
                <option value="error">Error</option>
              </Select>

              <Select
                value={sinceDays}
                onChange={(e) => {
                  setSinceDays(e.target.value)
                  setPage(1)
                }}
                className="w-[130px] text-xs"
              >
                <option value="1">Last 24 Hours</option>
                <option value="7">Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
              </Select>
            </div>

            <div className="text-xs text-muted-foreground font-mono">
              Total {formatNumber(total)} records
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {loading && !items.length ? (
            <Loading label="Loading audit logs..." />
          ) : items.length === 0 ? (
            <div className="text-center py-12 text-xs text-muted-foreground">
              No audit logs recorded for the selected parameters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>User / Role</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="text-right">Diff</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((log) => (
                    <TableRow key={log.id} className="hover:bg-muted/30">
                      <TableCell className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                        {formatDateTime(log.timestamp)}
                      </TableCell>
                      <TableCell className="text-xs font-semibold text-foreground font-mono">
                        {log.action}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground font-mono max-w-xs truncate" title={log.resource}>
                        {log.resource}
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="font-medium text-foreground">{log.user_name || log.user_id || 'System'}</div>
                        {log.user_role && (
                          <div className="text-[10px] text-muted-foreground font-mono uppercase">{log.user_role}</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] uppercase font-mono">
                          {log.category}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground">
                        {log.ip_address || '—'}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            log.result === 'success'
                              ? 'success'
                              : log.result === 'denied'
                              ? 'destructive'
                              : 'warning'
                          }
                          className="text-[10px] uppercase font-mono tracking-wider"
                        >
                          {log.result}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-xs h-7 gap-1"
                          onClick={() => setSelectedLog(log)}
                        >
                          <Eye className="h-3 w-3" />
                          View
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

      {/* Diff Inspection Dialog */}
      <Dialog open={!!selectedLog} onOpenChange={(open) => !open && setSelectedLog(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          {selectedLog && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-primary">{selectedLog.action}</span>
                  <Badge
                    variant={selectedLog.result === 'success' ? 'success' : 'destructive'}
                    className="text-[10px] uppercase"
                  >
                    {selectedLog.result}
                  </Badge>
                </div>
                <DialogDescription className="text-xs">
                  Recorded at {formatDateTime(selectedLog.timestamp)} on resource <code>{selectedLog.resource}</code>
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3 py-2 text-xs">
                <div className="grid grid-cols-2 gap-2 rounded-md border border-border bg-muted/20 p-2.5 font-mono text-[11px]">
                  <div>Actor: <span className="text-foreground font-semibold">{selectedLog.user_name || selectedLog.user_id || 'System'}</span></div>
                  <div>Role: <span className="text-foreground uppercase">{selectedLog.user_role || 'system'}</span></div>
                  <div>Category: <span className="text-foreground uppercase">{selectedLog.category}</span></div>
                  <div>IP Address: <span className="text-foreground">{selectedLog.ip_address || '127.0.0.1'}</span></div>
                </div>

                {selectedLog.detail && Object.keys(selectedLog.detail).length > 0 && (
                  <div>
                    <span className="font-semibold text-foreground">Action Detail:</span>
                    <pre className="mt-1 rounded-md border border-border bg-background p-2.5 font-mono text-[11px] overflow-x-auto text-muted-foreground">
                      {JSON.stringify(selectedLog.detail, null, 2)}
                    </pre>
                  </div>
                )}

                {(selectedLog.previous_value || selectedLog.new_value) && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="font-semibold text-red-400">Previous Value:</span>
                      <pre className="mt-1 rounded-md border border-red-500/20 bg-red-500/5 p-2 font-mono text-[11px] overflow-x-auto text-muted-foreground">
                        {selectedLog.previous_value ? JSON.stringify(selectedLog.previous_value, null, 2) : 'null'}
                      </pre>
                    </div>

                    <div>
                      <span className="font-semibold text-green-400">New Value:</span>
                      <pre className="mt-1 rounded-md border border-green-500/20 bg-green-500/5 p-2 font-mono text-[11px] overflow-x-auto text-muted-foreground">
                        {selectedLog.new_value ? JSON.stringify(selectedLog.new_value, null, 2) : 'null'}
                      </pre>
                    </div>
                  </div>
                )}
              </div>

              <DialogFooter>
                <Button variant="outline" size="sm" onClick={() => setSelectedLog(null)}>
                  Close
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
