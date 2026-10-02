import { useCallback, useEffect, useState } from 'react'
import {
  AlertOctagon,
  AlertTriangle,
  Bell,
  Check,
  CheckCheck,
  Clock,
  ExternalLink,
  Filter,
  Info,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select } from '@/components/ui/input'
import { Alert as InlineAlert, Loading, PageHeader, StatCard } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatDateTime, relativeTime } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { NotificationItem } from '@/lib/types'

const CATEGORY_MAP: Record<string, { label: string; icon: any }> = {
  critical_alert: { label: 'Critical Threat', icon: AlertOctagon },
  high_alert: { label: 'High Threat', icon: AlertTriangle },
  investigation_update: { label: 'Case Update', icon: Zap },
  system_warning: { label: 'System Warning', icon: ShieldAlert },
  model_update: { label: 'Model Update', icon: Radio },
  configuration_change: { label: 'Config Change', icon: Info },
  system_failure: { label: 'Service Alert', icon: AlertOctagon },
}

export function NotificationsPage() {
  const { user } = useAuth()
  const [items, setItems] = useState<NotificationItem[]>([])
  const [total, setTotal] = useState(0)
  const [unreadCount, setUnreadCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterRead, setFilterRead] = useState<string>('all')
  const [filterCat, setFilterCat] = useState<string>('all')

  const loadNotifications = useCallback(async () => {
    setLoading(true)
    try {
      const qs = new URLSearchParams({ page: '1', page_size: '50' })
      if (filterRead === 'unread') qs.set('is_read', 'false')
      if (filterRead === 'read') qs.set('is_read', 'true')
      if (filterCat !== 'all') qs.set('category', filterCat)

      const res = await api.get<{ items: NotificationItem[]; total: number; unread_count?: number }>(
        `/analyst/notifications?${qs.toString()}`
      )
      setItems(res.items || [])
      setTotal(res.total || 0)
      setUnreadCount(res.unread_count || res.items.filter((i) => !i.is_read).length)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [filterRead, filterCat])

  useEffect(() => {
    loadNotifications()
    const timer = setInterval(loadNotifications, 30_000)
    return () => clearInterval(timer)
  }, [loadNotifications])

  const handleMarkRead = async (id: string) => {
    try {
      await api.post(`/analyst/notifications/${id}/read`)
      setItems((prev) =>
        prev.map((item) => (item.id === id ? { ...item, is_read: true, read_at: new Date().toISOString() } : item))
      )
      setUnreadCount((c) => Math.max(0, c - 1))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const handleMarkAllRead = async () => {
    try {
      const unread = items.filter((i) => !i.is_read)
      await Promise.all(unread.map((i) => api.post(`/analyst/notifications/${i.id}/read`).catch(() => null)))
      setItems((prev) => prev.map((item) => ({ ...item, is_read: true })))
      setUnreadCount(0)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <>
      <PageHeader
        title="Security Notifications"
        subtitle="Real-time alert dispatch feed, critical detections, investigation status changes, and platform audit events."
        icon={Bell}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadNotifications} disabled={loading}>
              <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
              Refresh
            </Button>
            {unreadCount > 0 && (
              <Button size="sm" variant="secondary" onClick={handleMarkAllRead}>
                <CheckCheck className="h-3.5 w-3.5" />
                Mark All Read
              </Button>
            )}
          </div>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Notification Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {/* Counters */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-6">
        <StatCard
          title="Total Notifications"
          value={total}
          hint="All logged events"
          icon={Bell}
        />
        <StatCard
          title="Unread Dispatch"
          value={unreadCount}
          hint="Actionable items"
          icon={AlertTriangle}
        />
        <StatCard
          title="Critical Alerts"
          value={items.filter((i) => i.severity === 'critical').length}
          hint="High priority notice"
          icon={AlertOctagon}
        />
        <StatCard
          title="System Warnings"
          value={items.filter((i) => i.category === 'system_warning').length}
          hint="Operational notices"
          icon={ShieldAlert}
        />
      </div>

      {/* Filters */}
      <Card className="mb-4">
        <CardContent className="p-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={filterRead}
                onChange={(e) => setFilterRead(e.target.value)}
                className="w-[140px] text-xs"
              >
                <option value="all">All Notifications</option>
                <option value="unread">Unread Only</option>
                <option value="read">Read Only</option>
              </Select>

              <Select
                value={filterCat}
                onChange={(e) => setFilterCat(e.target.value)}
                className="w-[180px] text-xs"
              >
                <option value="all">All Categories</option>
                <option value="critical_alert">Critical Alerts</option>
                <option value="high_alert">High Alerts</option>
                <option value="investigation_update">Case Updates</option>
                <option value="system_warning">System Warnings</option>
                <option value="model_update">Model Updates</option>
                <option value="configuration_change">Config Changes</option>
              </Select>
            </div>

            <div className="text-xs text-muted-foreground font-mono">
              Showing {items.length} notifications
            </div>
          </div>
        </CardContent>
      </Card>

      {/* List */}
      <Card>
        <CardContent className="p-0">
          {loading && !items.length ? (
            <Loading label="Loading notification feed..." />
          ) : items.length === 0 ? (
            <div className="text-center py-12 text-xs text-muted-foreground">
              No notifications matching the selected criteria.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {items.map((item) => {
                const cat = CATEGORY_MAP[item.category] || { label: item.category, icon: Info }
                const CatIcon = cat.icon
                return (
                  <div
                    key={item.id}
                    className={`flex items-start justify-between p-4 transition-colors hover:bg-muted/30 ${
                      !item.is_read ? 'bg-primary/5' : ''
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`h-8 w-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                          item.severity === 'critical'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : item.severity === 'high'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-primary/10 text-primary border border-primary/20'
                        }`}
                      >
                        <CatIcon className="h-4 w-4" />
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-xs text-foreground">{item.title}</span>
                          <Badge variant="outline" className="text-[10px]">
                            {cat.label}
                          </Badge>
                          <Badge
                            variant={
                              item.severity === 'critical'
                                ? 'destructive'
                                : item.severity === 'high'
                                ? 'warning'
                                : 'outline'
                            }
                            className="text-[9px] uppercase tracking-wide"
                          >
                            {item.severity}
                          </Badge>
                          {!item.is_read && (
                            <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                          )}
                        </div>

                        <p className="text-xs text-muted-foreground leading-relaxed">{item.message}</p>

                        <div className="flex items-center gap-3 text-[11px] text-muted-foreground pt-1">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" /> {relativeTime(item.timestamp)}
                          </span>
                          <span>•</span>
                          <span>{formatDateTime(item.timestamp)}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 ml-4">
                      {!item.is_read && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-xs h-7 gap-1"
                          onClick={() => handleMarkRead(item.id)}
                          title="Mark as read"
                        >
                          <Check className="h-3 w-3" />
                          Read
                        </Button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </>
  )
}
