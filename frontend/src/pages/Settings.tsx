import { useCallback, useEffect, useState } from 'react'
import { Database, HardDrive, KeyRound, LogOut, Server, UserCog, UserPlus, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Select } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Alert, KeyValue, Loading, PageHeader, StatusBadge } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatBytes, formatDateTime, formatNumber, formatPercent } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { HealthResponse, Role, User } from '@/lib/types'

interface SystemInfo {
  status: string
  uptime_seconds: number
  database: {
    ok: boolean
    error?: string | null
    url_scheme: string
    counts: Record<string, number>
  }
  model: {
    algorithm?: string
    n_estimators?: number
    n_features?: number
    test_accuracy?: number
    loaded?: boolean
  }
  rate_limiter: {
    enabled: boolean
    limits: Record<string, string>
    tracked: number
  }
  uploads: { upload_dir: string; upload_files: number; upload_bytes: number }
  environment: Record<string, string | number>
  ai: { provider: string; enabled: boolean; model?: string | null; api_key_configured?: boolean }
}

export function Settings() {
  const { user, isAdmin, logout } = useAuth()
  const [users, setUsers] = useState<User[]>([])
  const [usersError, setUsersError] = useState<string | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [system, setSystem] = useState<SystemInfo | null>(null)
  const [created, setCreated] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'analyst' as Role })

  const loadUsers = useCallback(async () => {
    if (!isAdmin) return
    try {
      const data = await api.get<{ items: User[]; total: number }>('/auth/users')
      setUsers(Array.isArray(data) ? data : data.items)
      setUsersError(null)
    } catch (err) {
      setUsersError(errorMessage(err))
    }
  }, [isAdmin])

  useEffect(() => {
    api.get<HealthResponse>('/health').then(setHealth).catch(() => setHealth(null))
    if (isAdmin) {
      api.get<SystemInfo>('/health/system').then(setSystem).catch(() => setSystem(null))
    }
    loadUsers()
  }, [isAdmin, loadUsers])

  const createUser = async (event: React.FormEvent) => {
    event.preventDefault()
    setCreating(true)
    setCreated(null)
    setUsersError(null)
    try {
      const created = await api.post<User>('/auth/users', {
        name: form.name,
        email: form.email,
        password: form.password,
        role: form.role,
      })
      setCreated(`User ${created.email} created with role ${created.role}.`)
      setForm({ name: '', email: '', password: '', role: 'analyst' })
      loadUsers()
    } catch (err) {
      setUsersError(errorMessage(err))
    } finally {
      setCreating(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Settings & System"
        subtitle={
          <>
            Account information, user administration (admins), and the live status of the backend services
            this console depends on.
          </>
        }
        actions={
          <Button variant="outline" size="sm" onClick={logout}>
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </Button>
        }
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserCog className="h-4 w-4 text-primary" />
              My account
            </CardTitle>
            <CardDescription>From GET /api/auth/me</CardDescription>
          </CardHeader>
          <CardContent className="space-y-0.5">
            <KeyValue label="Name" value={user?.name ?? '—'} />
            <KeyValue label="Email" value={user?.email ?? '—'} />
            <KeyValue label="Role" value={<Badge variant={isAdmin ? 'default' : 'secondary'}>{user?.role}</Badge>} />
            <KeyValue label="Account active" value={user?.is_active ? 'yes' : 'no'} />
            <KeyValue label="Created" value={formatDateTime(user?.created_at)} />
            <KeyValue label="Last sign-in" value={formatDateTime(user?.last_login_at)} />
            <p className="pt-2 text-[10px] leading-relaxed text-muted-foreground">
              Sessions use short-lived signed JWTs; signing out also revokes the token server-side. Passwords
              are stored only as bcrypt hashes.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Backend health
            </CardTitle>
            <CardDescription>From GET /api/health (public readiness summary)</CardDescription>
          </CardHeader>
          <CardContent>
            {!health ? (
              <Loading label="Checking backend…" />
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <StatusBadge status={health.status === 'healthy' ? 'completed' : health.status === 'degraded' ? 'running' : 'failed'} />
                  <span className="text-xs text-muted-foreground">
                    uptime {formatNumber(Math.round(health.uptime_seconds))} s · v{health.version} ·{' '}
                    {health.environment}
                  </span>
                </div>
                <div className="space-y-0.5">
                  <KeyValue
                    label="Database"
                    value={health.checks?.database?.ok ? 'connected' : 'unavailable'}
                  />
                  <KeyValue label="Model loaded" value={health.model?.loaded ? 'yes' : 'no'} />
                  <KeyValue label="Model accuracy (test split)" value={formatPercent(health.model?.test_accuracy, 4)} />
                  <KeyValue label="Model load time" value={`${health.model?.load_seconds ?? '—'} s`} />
                  <KeyValue
                    label="AI explanation"
                    value={`${health.ai?.provider} · ${health.ai?.enabled ? 'external LLM' : 'local engine'}`}
                  />
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {isAdmin && (
          <>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-4 w-4 text-primary" />
                  User administration
                </CardTitle>
                <CardDescription>
                  {formatNumber(users.length)} user(s) · admin only (GET/POST /api/auth/users)
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {usersError && <Alert variant="error" title="User operation failed">{usersError}</Alert>}
                {created && <Alert variant="success" title="User created">{created}</Alert>}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Active</TableHead>
                      <TableHead>Last login</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.map((item) => (
                      <TableRow key={item.id}>
                        <TableCell className="text-xs">{item.name}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{item.email}</TableCell>
                        <TableCell>
                          <Badge variant={item.role === 'admin' ? 'default' : 'secondary'}>{item.role}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{item.is_active ? 'yes' : 'no'}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {item.last_login_at ? formatDateTime(item.last_login_at) : '—'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <UserPlus className="h-4 w-4 text-primary" />
                  Create user
                </CardTitle>
                <CardDescription>
                  Passwords must satisfy the backend policy (minimum length enforced server-side).
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form className="space-y-3" onSubmit={createUser}>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="new-name">Full name</Label>
                      <Input
                        id="new-name"
                        required
                        value={form.name}
                        onChange={(event) => setForm({ ...form, name: event.target.value })}
                        placeholder="Analyst Name"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="new-email">Email</Label>
                      <Input
                        id="new-email"
                        type="email"
                        required
                        value={form.email}
                        onChange={(event) => setForm({ ...form, email: event.target.value })}
                        placeholder="name@ainids.dev"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="new-password">Password</Label>
                      <Input
                        id="new-password"
                        type="password"
                        required
                        value={form.password}
                        onChange={(event) => setForm({ ...form, password: event.target.value })}
                        placeholder="Minimum 10 characters"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="new-role">Role</Label>
                      <Select
                        id="new-role"
                        value={form.role}
                        onChange={(event) => setForm({ ...form, role: event.target.value as Role })}
                      >
                        <option value="analyst">analyst — analyse traffic, manage alerts</option>
                        <option value="admin">admin — plus user administration</option>
                      </Select>
                    </div>
                  </div>
                  <Button type="submit" disabled={creating}>
                    <KeyRound className="h-3.5 w-3.5" />
                    {creating ? 'Creating…' : 'Create user'}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-primary" />
                  System information
                </CardTitle>
                <CardDescription>Admin only · GET /api/health/system</CardDescription>
              </CardHeader>
              <CardContent>
                {!system ? (
                  <Loading label="Loading system information…" />
                ) : (
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-0.5">
                      <div className="label-xs mb-1.5">Database</div>
                      <KeyValue label="Engine" value={system.database.url_scheme} />
                      <KeyValue label="Connected" value={system.database.ok ? 'yes' : 'no'} />
                      {Object.entries(system.database.counts ?? {}).map(([key, value]) => (
                        <KeyValue key={key} label={key} value={formatNumber(value)} />
                      ))}
                    </div>
                    <div className="space-y-0.5">
                      <div className="label-xs mb-1.5">Rate limiting</div>
                      <KeyValue label="Enabled" value={system.rate_limiter.enabled ? 'yes' : 'no'} />
                      {Object.entries(system.rate_limiter.limits ?? {}).map(([key, value]) => (
                        <KeyValue key={key} label={key} value={value} mono />
                      ))}
                      <KeyValue label="Tracked clients" value={formatNumber(system.rate_limiter.tracked)} />
                    </div>
                    <div className="space-y-0.5">
                      <div className="label-xs mb-1.5">
                        <HardDrive className="mr-1 inline h-3 w-3" />
                        Storage &amp; runtime
                      </div>
                      <KeyValue label="Upload files" value={formatNumber(system.uploads.upload_files)} />
                      <KeyValue label="Upload bytes" value={formatBytes(system.uploads.upload_bytes)} />
                      <KeyValue label="Max upload" value={`${system.environment.max_upload_mb} MB`} />
                      <KeyValue label="Max rows / job" value={formatNumber(Number(system.environment.max_rows_per_job))} />
                      <KeyValue label="Job workers" value={String(system.environment.job_workers)} />
                      <KeyValue label="Python" value={String(system.environment.python)} />
                      <KeyValue
                        label="AI provider"
                        value={`${system.ai.provider}${system.ai.api_key_configured ? '' : ' (no key)'}`}
                      />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}

        {!isAdmin && (
          <Card className="xl:col-span-2">
            <CardContent className="p-4 text-[11px] leading-relaxed text-muted-foreground">
              Signed in as an <span className="text-foreground">analyst</span>: you can upload and analyse
              traffic, triage alerts and read every dashboard. User administration and system internals are
              restricted to admin accounts — sign in as <span className="font-mono">admin@ainids.dev</span> to
              manage users.
            </CardContent>
          </Card>
        )}
      </div>
    </>
  )
}
