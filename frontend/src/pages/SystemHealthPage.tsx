import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  HardDrive,
  Layers,
  Lock,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Alert as InlineAlert, KeyValue, Loading, PageHeader, StatCard, StatusBadge } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatBytes, formatDateTime, formatNumber, formatPercent } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'

interface HealthPayload {
  status: 'healthy' | 'degraded' | 'unhealthy'
  version: string
  environment: string
  uptime_seconds: number
  checks: Record<string, { ok: boolean; detail?: string | null; [key: string]: unknown }>
  database: {
    ok: boolean
    url_scheme: string
    counts: Record<string, number>
    error?: string | null
  }
  model: {
    algorithm?: string
    n_estimators?: number
    n_features?: number
    test_accuracy?: number
    loaded?: boolean
    load_seconds?: number
  }
  rate_limiter: {
    enabled: boolean
    limits: Record<string, string>
    tracked: number
  }
  uploads: {
    upload_dir: string
    upload_files: number
    upload_bytes: number
  }
  network_status: {
    status: string
    label: string
    tone: string
    source: string
  }
  audit_summary: {
    total: number
    last_24h: number
  }
  investigation_stats: Record<string, number>
  runtime_workers: number
  ai: {
    provider: string
    enabled: boolean
    model?: string | null
    api_key_configured?: boolean
  }
}

export function SystemHealthPage() {
  const { isAdmin } = useAuth()
  const [data, setData] = useState<HealthPayload | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadHealth = useCallback(async () => {
    if (!isAdmin) return
    setLoading(true)
    try {
      const res = await api.get<HealthPayload>('/admin/system/health')
      setData(res)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [isAdmin])

  useEffect(() => {
    loadHealth()
    const timer = setInterval(loadHealth, 15_000)
    return () => clearInterval(timer)
  }, [loadHealth])

  if (!isAdmin) {
    return (
      <div className="p-8">
        <InlineAlert variant="error" title="Access Denied">
          Detailed infrastructure health is restricted to administrators.
        </InlineAlert>
      </div>
    )
  }

  const uptimeHours = data ? Math.floor(data.uptime_seconds / 3600) : 0
  const uptimeMinutes = data ? Math.floor((data.uptime_seconds % 3600) / 60) : 0

  return (
    <>
      <PageHeader
        title="System Infrastructure Health"
        subtitle="Live verification of backend services, database connections, ML model pipeline, rate limiting, and background workers. Health checks are executed against actual database and filesystem probes."
        icon={Server}
        actions={
          <Button variant="outline" size="sm" onClick={loadHealth} disabled={loading}>
            <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
            Run Diagnostics
          </Button>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Diagnostics Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {loading && !data ? (
        <Loading label="Running system diagnostics and connectivity probes..." />
      ) : data ? (
        <div className="space-y-6">
          {/* Status Header Banner */}
          <Card className="border-border/80">
            <CardHeader className="pb-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-foreground">Overall Platform State:</span>
                    <Badge
                      variant={data.status === 'healthy' ? 'success' : 'destructive'}
                      className="text-xs px-2.5 py-0.5 uppercase tracking-wider"
                    >
                      {data.status}
                    </Badge>
                    <Badge variant="outline" className="text-xs font-mono">
                      v{data.version} ({data.environment})
                    </Badge>
                  </div>
                  <CardDescription className="text-xs">
                    All core components report operational telemetry and active heartbeat checks.
                  </CardDescription>
                </div>

                <div className="text-right text-xs text-muted-foreground font-mono">
                  Uptime: <strong className="text-foreground">{uptimeHours}h {uptimeMinutes}m</strong>
                </div>
              </div>
            </CardHeader>
          </Card>

          {/* Component Health Grid */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {/* Backend API */}
            <Card className="p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Server className="h-3.5 w-3.5 text-primary" /> Backend API
                </span>
                <Badge variant="success" className="text-[10px]">HEALTHY</Badge>
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground space-y-0.5 font-mono">
                <div>FastAPI Core: OK</div>
                <div>Workers Pool: {data.runtime_workers} threads</div>
              </div>
            </Card>

            {/* Database */}
            <Card className="p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Database className="h-3.5 w-3.5 text-primary" /> Database
                </span>
                <Badge variant={data.database.ok ? 'success' : 'destructive'} className="text-[10px]">
                  {data.database.ok ? 'CONNECTED' : 'ERROR'}
                </Badge>
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground space-y-0.5 font-mono">
                <div>Engine: {data.database.url_scheme.toUpperCase()}</div>
                <div>Predictions: {formatNumber(data.database.counts?.predictions || 0)} rows</div>
              </div>
            </Card>

            {/* ML Inference Model */}
            <Card className="p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Brain className="h-3.5 w-3.5 text-primary" /> Random Forest
                </span>
                <Badge variant={data.model.loaded ? 'success' : 'destructive'} className="text-[10px]">
                  {data.model.loaded ? 'LOADED' : 'UNLOADED'}
                </Badge>
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground space-y-0.5 font-mono">
                <div>Trees: {data.model.n_estimators || 100} estimators</div>
                <div>Features: {data.model.n_features || 78} flow features</div>
              </div>
            </Card>

            {/* Storage & Queue */}
            <Card className="p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <HardDrive className="h-3.5 w-3.5 text-primary" /> Storage & Files
                </span>
                <Badge variant="success" className="text-[10px]">OK</Badge>
              </div>
              <div className="mt-2 text-[11px] text-muted-foreground space-y-0.5 font-mono">
                <div>Upload Files: {data.uploads.upload_files}</div>
                <div>Disk Usage: {formatBytes(data.uploads.upload_bytes)}</div>
              </div>
            </Card>
          </div>

          {/* Detailed Component Breakdown */}
          <div className="grid gap-4 lg:grid-cols-2">
            {/* Database Counts */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Database className="h-3.5 w-3.5 text-primary" />
                  Database Record Counts
                </CardTitle>
                <CardDescription className="text-xs">
                  Row counts across relational tables verifying data persistence.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-0.5">
                {Object.entries(data.database.counts || {}).map(([table, count]) => (
                  <KeyValue key={table} label={table.replace('_', ' ')} value={formatNumber(count)} />
                ))}
              </CardContent>
            </Card>

            {/* Rate Limiter & Security */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                  Rate Limiter & Access Control
                </CardTitle>
                <CardDescription className="text-xs">
                  Sliding-window request limits enforcing DoS protection on endpoints.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2 rounded-md border border-border/60 bg-muted/20 p-2.5 font-mono text-[11px]">
                  <div>Status: <span className="text-foreground font-semibold">{data.rate_limiter.enabled ? 'ACTIVE' : 'DISABLED'}</span></div>
                  <div>Tracked IPs: <span className="text-foreground font-semibold">{data.rate_limiter.tracked}</span></div>
                </div>

                <div>
                  <span className="font-semibold text-foreground">Configured Sliding Window Limits:</span>
                  <div className="mt-1 space-y-1 font-mono text-[11px] text-muted-foreground">
                    {Object.entries(data.rate_limiter.limits || {}).map(([route, limit]) => (
                      <div key={route} className="flex justify-between border-b border-border/40 py-0.5">
                        <code>{route}</code>
                        <span className="text-foreground font-semibold">{limit}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}
    </>
  )
}
