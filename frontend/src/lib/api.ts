/**
 * Typed API client for the AI-NIDS backend.
 *
 * All requests go to the relative `/api` path, which Vite proxies to FastAPI in
 * development and nginx proxies in the Docker/production setup - the browser
 * never needs to know the backend host, and no secret ever reaches the client.
 */

export const API_BASE = '/api'
const TOKEN_KEY = 'ai-nids.token'
const USER_KEY = 'ai-nids.user'

export class ApiError extends Error {
  status: number
  detail: unknown
  constructor(message: string, status: number, detail?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setSession(token: string, user: unknown) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function getStoredUser<T>(): T | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

/** Extract a human-readable message from the backend's structured errors. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const detail = error.detail as any
    if (typeof detail === 'string') return detail
    if (detail && typeof detail === 'object') {
      if (typeof detail.message === 'string') return detail.message
      if (typeof detail.detail === 'string') return detail.detail
    }
    return error.message
  }
  if (error instanceof Error) return error.message
  return 'Unexpected error'
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  body?: unknown
  formData?: FormData
  signal?: AbortSignal
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, formData, signal } = options
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: formData ?? (body !== undefined ? JSON.stringify(body) : undefined),
      signal,
    })
  } catch (err) {
    throw new ApiError(
      'Cannot reach the AI-NIDS backend. Is the API server running?',
      0,
      { message: 'Network error' },
    )
  }

  if (response.status === 401 && !path.startsWith('/auth/login')) {
    // No auth in this app — ignore 401s
    throw new ApiError('Authentication required.', 401)
  }

  const text = await response.text()
  const payload = text ? safeJson(text) : null

  if (!response.ok) {
    const detail = (payload as any)?.detail ?? payload
    throw new ApiError(errorMessage(new ApiError('', response.status, detail)) || `Request failed (${response.status})`, response.status, detail)
  }
  return payload as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  upload: <T>(path: string, file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return request<T>(path, { method: 'POST', formData: fd })
  },
}

/**
 * Server-Sent Events helper for the live simulation. Uses fetch streaming so
 * the JWT can travel in the Authorization header.
 */
export async function streamSse(
  path: string,
  handlers: {
    onEvent: (event: string, data: any) => void
    onError?: (message: string) => void
    onDone?: () => void
  },
  signal?: AbortSignal,
) {
  const token = getToken()
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal,
    })
    if (!response.ok || !response.body) {
      throw new Error(`Stream failed (${response.status})`)
    }
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let separator = buffer.indexOf('\n\n')
      while (separator !== -1) {
        const frame = buffer.slice(0, separator)
        buffer = buffer.slice(separator + 2)
        const eventLine = frame.split('\n').find((l) => l.startsWith('event: '))
        const dataLine = frame.split('\n').find((l) => l.startsWith('data: '))
        if (eventLine && dataLine) {
          const name = eventLine.replace('event: ', '').trim()
          try {
            handlers.onEvent(name, JSON.parse(dataLine.replace('data: ', '')))
          } catch {
            handlers.onEvent(name, dataLine)
          }
        }
        separator = buffer.indexOf('\n\n')
      }
    }
    handlers.onDone?.()
  } catch (err) {
    if ((err as Error).name === 'AbortError') return
    handlers.onError?.((err as Error).message)
  }
}
