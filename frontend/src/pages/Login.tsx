import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, KeyRound, Loader2, Lock, Mail, ShieldCheck, UserCog } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert } from '@/components/common'
import { NetworkBackground } from '@/components/NetworkBackground'
import { useAuth } from '@/context/AuthContext'
import { errorMessage } from '@/lib/api'

export function Login() {
  const { login, user, config } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const expired = new URLSearchParams(location.search).get('expired') === '1'

  useEffect(() => {
    if (user) {
      const from = (location.state as { from?: string } | null)?.from ?? '/dashboard'
      navigate(from, { replace: true })
    }
  }, [user, navigate, location.state])

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(email.trim(), password)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const fillDemo = (role: 'analyst' | 'admin') => {
    setEmail(role === 'analyst' ? 'analyst@ainids.dev' : 'admin@ainids.dev')
    setPassword(role === 'analyst' ? 'Analyst@123' : 'Admin@1234')
    setError(null)
  }

  return (
    <div className="relative grid min-h-screen place-items-center overflow-hidden px-4 py-10">
      <div className="pointer-events-none absolute inset-0 grid-line opacity-30" />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-[360px] opacity-40">
        <NetworkBackground className="mx-auto h-full w-full max-w-5xl opacity-60" />
      </div>

      <div className="relative z-10 w-full max-w-md animate-fade-up">
        <Link
          to="/"
          className="mb-4 inline-flex items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to overview
        </Link>

        <Card className="glass p-6">
          <div className="mb-5 flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-lg border border-primary/30 bg-primary/10">
              <ShieldCheck className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-base font-semibold tracking-tight">Sign in to AI-NIDS</h1>
              <p className="text-[11px] text-muted-foreground">
                Security Operations Console · JWT protected
              </p>
            </div>
          </div>

          {expired && (
            <div className="mb-4">
              <Alert variant="warn" title="Session expired">
                Please sign in again to continue.
              </Alert>
            </div>
          )}
          {error && (
            <div className="mb-4">
              <Alert variant="error" title="Sign-in failed">
                {error}
              </Alert>
            </div>
          )}

          <form onSubmit={submit} className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@ainids.dev"
                  className="pl-8"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pl-8"
                />
              </div>
            </div>
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              {busy ? 'Signing in…' : 'Sign In'}
            </Button>
          </form>

          {config?.demo_accounts_enabled && (
            <div className="mt-5 rounded-lg border border-border/70 bg-background/40 p-3">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
                <UserCog className="h-3.5 w-3.5" />
                Demo accounts (seeded on first start)
              </div>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <Button variant="outline" size="sm" onClick={() => fillDemo('analyst')} type="button">
                  Analyst
                </Button>
                <Button variant="outline" size="sm" onClick={() => fillDemo('admin')} type="button">
                  Admin
                </Button>
              </div>
              <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground">
                Analyst: analyst@ainids.dev / Analyst@123 · Admin: admin@ainids.dev / Admin@1234
              </p>
            </div>
          )}

          <p className="mt-4 text-[10px] leading-relaxed text-muted-foreground">
            Passwords are stored as bcrypt hashes and sessions use signed JWTs. Failed sign-ins are rate
            limited and audit logged.
          </p>
        </Card>
      </div>
    </div>
  )
}
