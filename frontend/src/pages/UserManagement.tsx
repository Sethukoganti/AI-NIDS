import { useState, useEffect, useCallback } from 'react'
import { Users, ShieldCheck, Search, Plus, Trash2, UserX, UserCheck, KeyRound } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input, Select } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { useAuth } from '@/context/AuthContext'
import { api, errorMessage } from '@/lib/api'

export default function UserManagement() {
  const { user } = useAuth()
  const [users, setUsers] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [selected, setSelected] = useState<any>(null)
  const [form, setForm] = useState({ name: '', email: '', role: 'analyst', password: '', is_active: true })

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get<{ items: any[]; total: number }>(
        `/admin/users?search=${encodeURIComponent(search)}&role=${roleFilter === 'all' ? '' : roleFilter}`,
      )
      setUsers(res.items ?? [])
      setTotal(res.total ?? 0)
    } catch (e: any) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }, [search, roleFilter])

  useEffect(() => { if (user?.role === 'admin') load() }, [user, load])

  const handleCreate = async () => {
    try {
      await api.post('/admin/users', { name: form.name, email: form.email, role: form.role, password: form.password })
      setCreateOpen(false)
      setForm({ name: '', email: '', role: 'analyst', password: '', is_active: true })
      load()
    } catch (e: any) {
      setError(errorMessage(e))
    }
  }

  const handleUpdate = async () => {
    if (!selected) return
    try {
      const payload: any = {}
      if (form.name !== selected.name) payload.name = form.name
      if (form.role !== selected.role) payload.role = form.role
      if (form.is_active !== selected.is_active) payload.is_active = form.is_active
      if (form.password) payload.password = form.password
      await api.patch(`/admin/users/${selected.id}`, payload)
      setEditOpen(false)
      setSelected(null)
      load()
    } catch (e: any) {
      setError(errorMessage(e))
    }
  }

  const openEdit = (u: any) => { setSelected(u); setForm({ name: u.name, email: u.email, role: u.role, password: '', is_active: u.is_active }); setEditOpen(true) }

  if (user?.role !== 'admin') return <div className="p-8 text-center"><h2 className="text-xl font-semibold mb-2">Access denied</h2><p className="text-muted-foreground">Admin only.</p></div>
  if (loading) return <div className="p-8"><Skeleton className="h-32 w-full" /><Skeleton className="h-32 w-full" /></div>
  if (error) return <div className="p-8"><div className="rounded-lg border border-destructive bg-destructive/10 p-4 text-destructive">{error}</div></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-2"><div className="rounded-lg bg-rose-500/10 p-2"><Users className="h-5 w-5 text-rose-400" /></div><div><h1 className="text-2xl font-bold tracking-tight">User Management</h1><p className="text-sm text-muted-foreground">Create, edit, disable and audit accounts.</p></div></div>

      <div className="flex flex-wrap gap-2 items-center">
        <div className="flex gap-2 flex-1 min-w-[240px]"><Input placeholder="Search name/email" value={search} onChange={e => setSearch(e.target.value)} className="max-w-xs" /><Button size="sm" onClick={load}><Search className="h-3 w-3 mr-1" />Search</Button></div>
          <Select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value)} className="w-28 text-xs"><option value="all">All</option><option value="admin">Admin</option><option value="analyst">Analyst</option></Select>
        <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-3 w-3 mr-1" />Create User</Button>
      </div>

      <Card>
        <CardContent className="p-0 overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-muted"><tr><th className="text-left px-3 py-2 font-medium">Name</th><th>Email</th><th>Role</th><th>Active</th><th>Audit events</th><th>Permissions</th><th className="text-right px-3 py-2">Actions</th></tr></thead>
            <tbody>{users.map((u: any) => (
              <tr key={u.id} className="border-b border-border/40 hover:bg-muted/40">
                <td className="px-3 py-2 font-medium">{u.name}</td>
                <td className="px-3 py-2">{u.email}</td>
                <td className="px-3 py-2"><Badge variant={u.role==='admin'?'default':'secondary'} className="text-[10px]">{u.role}</Badge></td>
                <td className="px-3 py-2">{u.is_active ? <Badge variant="outline" className="text-emerald-600 text-[10px]">Active</Badge> : <Badge variant="destructive" className="text-[10px]">Disabled</Badge>}</td>
                <td className="px-3 py-2">{u.audit_events ?? 0}</td>
                <td className="px-3 py-2 max-w-[200px] truncate">{(u.permissions ?? []).slice(0,3).join(', ')}{(u.permissions ?? []).length>3?'...':''}</td>
                <td className="px-3 py-2 text-right"><div className="flex gap-1 justify-end"><Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openEdit(u)}><KeyRound className="h-3 w-3" /></Button><Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => api.patch(`/admin/users/${u.id}`, { is_active: !u.is_active }).then(load)}>{u.is_active?<UserX className="h-3 w-3" />:<UserCheck className="h-3 w-3" />}</Button></div></td>
              </tr>
            ))}</tbody>
          </table>
          <div className="px-3 py-2 text-xs text-muted-foreground">Total: {total} users.</div>
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent><DialogHeader><DialogTitle>Create User</DialogTitle></DialogHeader>
                    <div className="space-y-3"><div><Label>Name</Label><Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div><div><Label>Email</Label><Input type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></div><div><Label>Role</Label><Select value={form.role} onChange={event => setForm({ ...form, role: event.target.value })}><option value="admin">Admin</option><option value="analyst">Analyst</option></Select></div><div><Label>Password</Label><Input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></div></div>
          <DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={handleCreate} disabled={!form.name || !form.email || !form.password}>Create</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent><DialogHeader><DialogTitle>Edit User</DialogTitle></DialogHeader>
          <div className="space-y-3"><div><Label>Name</Label><Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div><div><Label>Role</Label><Select value={form.role} onChange={event => setForm({ ...form, role: event.target.value })}><option value="admin">Admin</option><option value="analyst">Analyst</option></Select></div><div><Label>Active</Label><Select value={form.is_active ? 'yes' : 'no'} onChange={event => setForm({ ...form, is_active: event.target.value === 'yes' })}><option value="yes">Yes</option><option value="no">No</option></Select></div><div><Label>Reset Password (leave blank to keep)</Label><Input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></div></div>
          <DialogFooter><Button variant="outline" onClick={() => setEditOpen(false)}>Cancel</Button><Button onClick={handleUpdate}>Save</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
