import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { api, clearSession, getStoredUser, getToken, setSession } from '@/lib/api'
import type { AuthConfig, LoginResponse, User } from '@/lib/types'

interface AuthContextValue {
  user: User | null
  token: string | null
  loading: boolean
  config: AuthConfig | null
  login: (email: string, password: string) => Promise<User>
  logout: () => Promise<void>
  refresh: () => Promise<void>
  isAdmin: boolean
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getStoredUser<User>())
  const [token, setToken] = useState<string | null>(() => getToken())
  const [loading, setLoading] = useState<boolean>(true)
  const [config, setConfig] = useState<AuthConfig | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const cfg = await api.get<AuthConfig>('/auth/config')
        if (!cancelled) setConfig(cfg)
      } catch {
        /* non-fatal: the login page simply hides the demo hints */
      }
      if (getToken()) {
        try {
          const me = await api.get<User>('/auth/me')
          if (!cancelled) setUser(me)
        } catch {
          if (!cancelled) {
            clearSession()
            setUser(null)
            setToken(null)
          }
        }
      }
      if (!cancelled) setLoading(false)
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const response = await api.post<LoginResponse>('/auth/login', { email, password })
    setSession(response.access_token, response.user)
    setUser(response.user)
    setToken(response.access_token)
    return response.user
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* the client-side session is cleared regardless */
    }
    clearSession()
    setUser(null)
    setToken(null)
  }, [])

  const refresh = useCallback(async () => {
    const me = await api.get<User>('/auth/me')
    setUser(me)
    setSession(getToken() ?? '', me)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ user, token, loading, config, login, logout, refresh, isAdmin: user?.role === 'admin' }),
    [user, token, loading, config, login, logout, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
