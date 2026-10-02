import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  UserCheck,
  UserCog,
  UserPlus,
  Users,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, Select } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert as InlineAlert, Loading, PageHeader, StatCard } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { formatDateTime, relativeTime } from '@/lib/format'
import { useAuth } from '@/context/AuthContext'
import type { Role, User } from '@/lib/types'

interface ExtendedUser extends User {
  audit_events?: number
  permissions?: string[]
}

interface RoleCatalogueItem {
  permission: string
  description: string
  group: string
}

interface RoleItem {
  name: string
  description: string
  permissions: string[]
  protected: string[]
  is_system: boolean
  user_count: number
}

export function UsersPage() {
  const { user: currentUser, isAdmin } = useAuth()
  const [users, setUsers] = useState<ExtendedUser[]>([])
  const [rolesData, setRolesData] = useState<{ roles: RoleItem[]; catalogue: RoleCatalogueItem[] } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')

  // Create User Modal
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState({ name: '', email: '', password: '', role: 'analyst' as Role })
  const [creating, setCreating] = useState(false)

  // Edit / Action Modals
  const [selectedUser, setSelectedUser] = useState<ExtendedUser | null>(null)
  const [editAction, setEditAction] = useState<'role' | 'password' | 'toggle_active' | 'delete' | 'permissions' | null>(null)
  const [newRole, setNewRole] = useState<Role>('analyst')
  const [newPassword, setNewPassword] = useState('')
  const [submittingAction, setSubmittingAction] = useState(false)

  const loadData = useCallback(async () => {
    if (!isAdmin) return
    setLoading(true)
    try {
      const qs = new URLSearchParams()
      if (search) qs.set('search', search)
      if (roleFilter !== 'all') qs.set('role', roleFilter)

      const [usersRes, rolesRes] = await Promise.all([
        api.get<{ items: ExtendedUser[]; total: number }>(`/admin/users?${qs.toString()}`),
        api.get<{ roles: RoleItem[]; catalogue: RoleCatalogueItem[] }>('/admin/roles'),
      ])
      setUsers(usersRes.items || [])
      setRolesData(rolesRes)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [isAdmin, search, roleFilter])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreating(true)
    setError(null)
    try {
      await api.post('/admin/users', {
        name: createForm.name,
        email: createForm.email,
        password: createForm.password,
        role: createForm.role,
      })
      setNotice(`User account ${createForm.email} successfully created.`)
      setCreateForm({ name: '', email: '', password: '', role: 'analyst' })
      setCreateOpen(false)
      loadData()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setCreating(false)
    }
  }

  const handleApplyAction = async () => {
    if (!selectedUser || !editAction) return
    setSubmittingAction(true)
    setError(null)
    try {
      if (editAction === 'role') {
        await api.patch(`/admin/users/${selectedUser.id}`, { role: newRole })
        setNotice(`Role for ${selectedUser.email} changed to ${newRole.toUpperCase()}.`)
      } else if (editAction === 'password') {
        await api.patch(`/admin/users/${selectedUser.id}`, { password: newPassword })
        setNotice(`Password reset for ${selectedUser.email}. All prior sessions have been invalidated.`)
      } else if (editAction === 'toggle_active') {
        const nextState = !selectedUser.is_active
        await api.patch(`/admin/users/${selectedUser.id}`, { is_active: nextState })
        setNotice(`Account ${selectedUser.email} ${nextState ? 'enabled' : 'disabled'}.`)
      } else if (editAction === 'delete') {
        await api.del(`/admin/users/${selectedUser.id}`)
        setNotice(`Account ${selectedUser.email} deactivated.`)
      }
      setEditAction(null)
      setSelectedUser(null)
      loadData()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSubmittingAction(false)
    }
  }

  if (!isAdmin) {
    return (
      <div className="p-8">
        <InlineAlert variant="error" title="Access Denied">
          User administration is restricted to administrators.
        </InlineAlert>
      </div>
    )
  }

  return (
    <>
      <PageHeader
        title="User & Access Management"
        subtitle="Manage platform accounts, role-based access control (RBAC), and session security. All modifications are permanently recorded in the audit log."
        icon={Users}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
              <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <UserPlus className="h-3.5 w-3.5" />
              Add User
            </Button>
          </div>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="User Management Error">
            {error}
          </InlineAlert>
        </div>
      )}

      {notice && (
        <div className="mb-4">
          <InlineAlert variant="info" title="Success">
            {notice}
          </InlineAlert>
        </div>
      )}

      {/* Counters */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-6">
        <StatCard
          title="Total Accounts"
          value={users.length}
          hint="Registered users"
          icon={Users}
        />
        <StatCard
          title="Administrators"
          value={users.filter((u) => u.role === 'admin').length}
          hint="Full platform control"
          icon={ShieldAlert}
        />
        <StatCard
          title="Security Analysts"
          value={users.filter((u) => u.role === 'analyst').length}
          hint="Triage & investigation"
          icon={UserCheck}
        />
        <StatCard
          title="Active Accounts"
          value={users.filter((u) => u.is_active).length}
          hint="Authorized sessions"
          icon={CheckCircle2}
        />
      </div>

      <Tabs defaultValue="users" className="space-y-4">
        <TabsList>
          <TabsTrigger value="users">User Accounts</TabsTrigger>
          <TabsTrigger value="matrix">Role Permissions Matrix</TabsTrigger>
        </TabsList>

        <TabsContent value="users">
          {/* Filter Bar */}
          <Card className="mb-4">
            <CardContent className="p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative min-w-[220px]">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                      placeholder="Search name, email..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="pl-8 text-xs"
                    />
                  </div>

                  <Select
                    value={roleFilter}
                    onChange={(e) => setRoleFilter(e.target.value)}
                    className="w-[140px] text-xs"
                  >
                    <option value="all">All Roles</option>
                    <option value="admin">Admin</option>
                    <option value="analyst">Analyst</option>
                  </Select>
                </div>

                <div className="text-xs text-muted-foreground font-mono">
                  {users.length} user accounts loaded
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Users Table */}
          <Card>
            <CardContent className="p-0">
              {loading && !users.length ? (
                <Loading label="Loading user accounts..." />
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>User</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Account Status</TableHead>
                        <TableHead>Last Sign-In</TableHead>
                        <TableHead>Audit Events</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {users.map((u) => {
                        const isSelf = u.id === currentUser?.id
                        return (
                          <TableRow key={u.id} className="hover:bg-muted/30">
                            <TableCell>
                              <div className="font-semibold text-xs text-foreground flex items-center gap-1.5">
                                {u.name}
                                {isSelf && (
                                  <Badge variant="outline" className="text-[9px] py-0 px-1 text-primary border-primary/40">
                                    You
                                  </Badge>
                                )}
                              </div>
                              <div className="text-[11px] text-muted-foreground font-mono">{u.email}</div>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={u.role === 'admin' ? 'destructive' : 'default'}
                                className="text-[10px] uppercase font-mono tracking-wider"
                              >
                                {u.role}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {u.is_active ? (
                                <Badge variant="success" className="text-[10px] gap-1">
                                  <CheckCircle2 className="h-3 w-3" /> Active
                                </Badge>
                              ) : (
                                <Badge variant="secondary" className="text-[10px] gap-1 text-muted-foreground">
                                  <XCircle className="h-3 w-3" /> Disabled
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {u.last_login_at ? relativeTime(u.last_login_at) : 'Never'}
                            </TableCell>
                            <TableCell className="text-xs font-mono text-muted-foreground">
                              {u.audit_events || 0}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {formatDateTime(u.created_at)}
                            </TableCell>
                            <TableCell className="text-right">
                              <div className="flex items-center justify-end gap-1.5">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="text-xs h-7"
                                  onClick={() => {
                                    setSelectedUser(u)
                                    setEditAction('permissions')
                                  }}
                                  title="View effective permissions"
                                >
                                  Permissions
                                </Button>

                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="text-xs h-7"
                                  disabled={isSelf}
                                  onClick={() => {
                                    setSelectedUser(u)
                                    setNewRole(u.role)
                                    setEditAction('role')
                                  }}
                                  title="Change account role"
                                >
                                  Role
                                </Button>

                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="text-xs h-7"
                                  onClick={() => {
                                    setSelectedUser(u)
                                    setNewPassword('')
                                    setEditAction('password')
                                  }}
                                  title="Reset password"
                                >
                                  <KeyRound className="h-3 w-3" />
                                </Button>

                                <Button
                                  variant={u.is_active ? 'outline' : 'default'}
                                  size="sm"
                                  className="text-xs h-7"
                                  disabled={isSelf}
                                  onClick={() => {
                                    setSelectedUser(u)
                                    setEditAction('toggle_active')
                                  }}
                                  title={u.is_active ? 'Disable account' : 'Enable account'}
                                >
                                  {u.is_active ? 'Disable' : 'Enable'}
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="matrix">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Role Permissions Catalogue & Hardened Boundaries
              </CardTitle>
              <CardDescription className="text-xs">
                Backend-enforced capability matrix. Administrative privileges inherit all Analyst monitoring and investigation features.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {rolesData && (
                <div className="space-y-6">
                  {/* Summary of Roles */}
                  <div className="grid gap-3 md:grid-cols-2">
                    {rolesData.roles.map((r) => (
                      <div key={r.name} className="rounded-lg border border-border p-4 space-y-2 bg-muted/10">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-sm uppercase text-foreground">{r.name}</span>
                          <Badge variant="outline" className="font-mono text-xs">
                            {r.permissions.length} capabilities
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{r.description}</p>
                        <div className="pt-2 border-t border-border/60 text-[11px] text-muted-foreground">
                          Protected capabilities: <code>{r.protected.join(', ')}</code>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Capabilities Table */}
                  <div className="overflow-x-auto rounded-md border border-border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Capability</TableHead>
                          <TableHead>Category</TableHead>
                          <TableHead>Description</TableHead>
                          <TableHead className="text-center">Analyst</TableHead>
                          <TableHead className="text-center">Admin</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {rolesData.catalogue.map((cap) => {
                          const analystRole = rolesData.roles.find((r) => r.name === 'analyst')
                          const adminRole = rolesData.roles.find((r) => r.name === 'admin')
                          const hasAnalyst = analystRole?.permissions.includes(cap.permission)
                          const hasAdmin = adminRole?.permissions.includes(cap.permission)

                          return (
                            <TableRow key={cap.permission}>
                              <TableCell className="font-mono text-xs font-semibold text-foreground">
                                {cap.permission}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                <Badge variant="outline" className="text-[10px]">
                                  {cap.group}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {cap.description}
                              </TableCell>
                              <TableCell className="text-center">
                                {hasAnalyst ? (
                                  <CheckCircle2 className="h-4 w-4 text-emerald-400 mx-auto" />
                                ) : (
                                  <span className="text-muted-foreground/40 font-mono text-xs">—</span>
                                )}
                              </TableCell>
                              <TableCell className="text-center">
                                {hasAdmin ? (
                                  <CheckCircle2 className="h-4 w-4 text-emerald-400 mx-auto" />
                                ) : (
                                  <span className="text-muted-foreground/40 font-mono text-xs">—</span>
                                )}
                              </TableCell>
                            </TableRow>
                          )
                        })}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create User Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <form onSubmit={handleCreate}>
            <DialogHeader>
              <DialogTitle>Create User Account</DialogTitle>
              <DialogDescription>
                Provision a new operator account. Passwords are encrypted using bcrypt cost-factor 12.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-3">
              <div className="space-y-1">
                <Label htmlFor="c-name" className="text-xs">Full Name</Label>
                <Input
                  id="c-name"
                  placeholder="e.g., Alex Mercer"
                  value={createForm.name}
                  onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                  className="text-xs"
                  required
                />
              </div>

              <div className="space-y-1">
                <Label htmlFor="c-email" className="text-xs">Email Address</Label>
                <Input
                  id="c-email"
                  type="email"
                  placeholder="alex@corp.sec"
                  value={createForm.email}
                  onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
                  className="text-xs"
                  required
                />
              </div>

              <div className="space-y-1">
                <Label htmlFor="c-pwd" className="text-xs">Temporary Password</Label>
                <Input
                  id="c-pwd"
                  type="password"
                  value={createForm.password}
                  onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                  className="text-xs"
                  required
                />
              </div>

              <div className="space-y-1">
                <Label htmlFor="c-role" className="text-xs">Platform Role</Label>
                <Select
                  id="c-role"
                  value={createForm.role}
                  onChange={(e) => setCreateForm({ ...createForm, role: e.target.value as Role })}
                  className="text-xs"
                >
                  <option value="analyst">Analyst (Monitoring, Investigation, AI Copilot)</option>
                  <option value="admin">Admin (Full System, Configuration, Oversight)</option>
                </Select>
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" size="sm" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={creating || !createForm.email || !createForm.password}>
                {creating ? 'Creating...' : 'Provision User'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Action Dialog */}
      <Dialog open={!!editAction} onOpenChange={(open) => !open && setEditAction(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editAction === 'role' && 'Change User Role'}
              {editAction === 'password' && 'Reset Account Password'}
              {editAction === 'toggle_active' && (selectedUser?.is_active ? 'Disable Account' : 'Enable Account')}
              {editAction === 'permissions' && 'Effective Account Permissions'}
            </DialogTitle>
            <DialogDescription>
              Modifications apply immediately upon commit and create a permanent audit log entry.
            </DialogDescription>
          </DialogHeader>

          {selectedUser && (
            <div className="space-y-3 py-2 text-xs">
              <div className="rounded-md border border-border bg-muted/30 p-2.5 space-y-0.5">
                <div className="text-muted-foreground">User: <strong className="text-foreground">{selectedUser.name}</strong></div>
                <div className="text-muted-foreground">Email: <strong className="text-foreground font-mono">{selectedUser.email}</strong></div>
                <div className="text-muted-foreground">Current Role: <strong className="text-foreground uppercase">{selectedUser.role}</strong></div>
              </div>

              {editAction === 'role' && (
                <div className="space-y-1">
                  <Label htmlFor="edit-role">New Assigned Role</Label>
                  <Select
                    id="edit-role"
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as Role)}
                    className="text-xs"
                  >
                    <option value="analyst">Analyst (Monitor & Investigate)</option>
                    <option value="admin">Admin (Full Control)</option>
                  </Select>
                </div>
              )}

              {editAction === 'password' && (
                <div className="space-y-1">
                  <Label htmlFor="edit-pwd">New Password</Label>
                  <Input
                    id="edit-pwd"
                    type="password"
                    placeholder="Enter new strong password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="text-xs"
                  />
                  <p className="text-[11px] text-muted-foreground pt-1">
                    Resetting password will revoke all active access tokens for this user.
                  </p>
                </div>
              )}

              {editAction === 'toggle_active' && (
                <p className="text-muted-foreground leading-relaxed">
                  Are you sure you want to {selectedUser.is_active ? 'disable' : 'enable'} access for{' '}
                  <strong className="text-foreground">{selectedUser.email}</strong>?
                </p>
              )}

              {editAction === 'permissions' && (
                <div className="space-y-2">
                  <span className="font-semibold text-foreground">Assigned Capabilities ({selectedUser.permissions?.length || 0}):</span>
                  <div className="max-h-60 overflow-y-auto rounded border border-border p-2 space-y-1">
                    {selectedUser.permissions?.map((p) => (
                      <div key={p} className="font-mono text-[11px] text-foreground bg-muted/40 px-2 py-0.5 rounded">
                        {p}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setEditAction(null)}>
              {editAction === 'permissions' ? 'Close' : 'Cancel'}
            </Button>
            {editAction !== 'permissions' && (
              <Button
                size="sm"
                variant={editAction === 'toggle_active' && selectedUser?.is_active ? 'destructive' : 'default'}
                onClick={handleApplyAction}
                disabled={submittingAction || (editAction === 'password' && !newPassword)}
              >
                {submittingAction ? 'Saving...' : 'Confirm Update'}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
