import { Route, Routes, Navigate, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, Bot, Brain, Info, LayoutDashboard, LogOut, Radio, Send, Settings, ShieldAlert, ShieldCheck, Sparkles, Wifi, X, Zap } from 'lucide-react'
import { About } from '@/pages/About'
import { Dashboard } from '@/pages/Dashboard'
import { Detections } from '@/pages/Detections'
import { LiveCapture } from '@/pages/LiveCapture'
import { Login } from '@/pages/Login'
import { NotificationsPage } from '@/pages/NotificationsPage'
import SettingsCenter from '@/pages/SettingsCenter'
import { Simulation } from '@/pages/Simulation'
import { useAuth } from '@/context/AuthContext'
import { cn } from '@/lib/format'
import { useEffect, useRef, useState } from 'react'
import { api, errorMessage } from '@/lib/api'

// ── Mini AI Assistant (floating) ────────────────────────────────────────── //
interface ChatMsg { role: 'user' | 'bot'; text: string }

const QUICK_QUESTIONS = [
  'What is this system?',
  'How does it detect threats?',
  'What is a Random Forest?',
  'What should I do if a threat is found?',
]

function localAnswer(question: string): string {
  const q = question.toLowerCase()
  if (q.includes('what is this') || q.includes('about'))
    return 'This is an AI-powered Network Intrusion Detection System. It captures live network traffic, extracts 70 flow features, and uses a Random Forest model (trained on CICIDS2017) to classify each connection as Safe or a specific attack type.'
  if (q.includes('how does it detect') || q.includes('how it work'))
    return 'Packets are captured via Npcap, grouped into flows, and 70 statistical features (packet rate, flow duration, byte counts, TCP flags, etc.) are computed. These features are fed into a 100-tree Random Forest that outputs a classification with a confidence score.'
  if (q.includes('random forest'))
    return 'A Random Forest is an ensemble of 100 decision trees. Each tree votes on a classification, and the majority vote becomes the final prediction. This makes it robust and resistant to overfitting compared to a single decision tree.'
  if (q.includes('what should i do') || q.includes('precaution'))
    return 'When a threat is detected, the dashboard shows a specific explanation of the attack type and concrete precaution steps — e.g. blocking the source IP, enabling 2FA, or disabling an unused service. Check the Live Capture or Simulation page for examples.'
  if (q.includes('accuracy') || q.includes('how accurate'))
    return 'The model achieves 99.6% accuracy on the held-out CICIDS2017 test split. It can detect 8 attack classes: DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Botnet, Infiltration, and Heartbleed.'
  if (q.includes('live capture'))
    return 'Live Capture monitors your actual Wi-Fi/LAN adapter in real time using Npcap. Every completed network flow is scored by the model and shown as Safe or a Threat with explanation.'
  if (q.includes('simulation'))
    return 'Attack Simulation replays real CICIDS2017 attack flows through the same production model — useful for demonstrating detections on demand without needing a live attack.'
  return 'I can answer questions about this NIDS project: how it works, the model, detected attack types, or what to do about a threat. Try one of the suggested questions!'
}

function MiniAssistant() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMsg[]>([
    { role: 'bot', text: 'Hi! I can explain how this intrusion detection system works. Ask me anything.' },
  ])
  const [input, setInput] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, open])

  const ask = (text: string) => {
    const q = text.trim()
    if (!q) return
    setMessages((m) => [...m, { role: 'user', text: q }])
    setInput('')
    setTimeout(() => {
      setMessages((m) => [...m, { role: 'bot', text: localAnswer(q) }])
    }, 300)
  }
  const askedQuestions = new Set(
    messages
      .filter((message) => message.role === 'user')
      .map((message) => message.text.toLocaleLowerCase()),
  )
  const followUpQuestions = QUICK_QUESTIONS
    .filter((question) => !askedQuestions.has(question.toLocaleLowerCase()))
    .slice(0, 3)

  return (
    <>
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-5 right-5 z-50 flex h-12 w-12 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-[0_0_24px_rgba(34,211,238,0.4)] transition-transform hover:scale-105"
          title="Ask the AI assistant"
        >
          <Sparkles className="h-5 w-5" />
        </button>
      )}

      {open && (
        <div className="fixed bottom-5 right-5 z-50 flex h-[460px] w-[340px] flex-col overflow-hidden rounded-2xl border border-border/70 bg-panel/95 shadow-2xl backdrop-blur">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-3">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              <span className="text-sm font-semibold">NIDS Assistant</span>
            </div>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div ref={scrollRef} className="flex-1 space-y-2.5 overflow-y-auto p-3">
            {messages.map((m, i) => {
              const isLastBotMessage = m.role === 'bot' && i === messages.length - 1
              return (
                <div key={i} className={cn('flex flex-col', m.role === 'user' ? 'items-end' : 'items-start')}>
                  <div className={cn(
                    'max-w-[85%] rounded-lg px-3 py-2 text-[12px] leading-relaxed',
                    m.role === 'user'
                      ? 'bg-primary/15 border border-primary/30 text-foreground'
                      : 'bg-background/50 border border-border/60 text-foreground/90',
                  )}>
                    {m.text}
                  </div>
                  {isLastBotMessage && (
                    <div className="mt-2 space-y-1.5">
                      <p className="text-[10px] text-muted-foreground">You can ask next:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {followUpQuestions.map((question) => (
                          <button
                            key={question}
                            onClick={() => ask(question)}
                            className="rounded-md border border-border/60 bg-background/40 px-2 py-1 text-left text-[10px] text-muted-foreground hover:border-primary/40 hover:text-foreground"
                          >
                            {question}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          <form
            onSubmit={(e) => { e.preventDefault(); ask(input) }}
            className="flex items-center gap-2 border-t border-border/60 p-2.5"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about this project..."
              className="flex-1 rounded-lg border border-border/60 bg-background/50 px-3 py-1.5 text-xs outline-none focus:border-primary/50"
            />
            <button type="submit" className="rounded-lg bg-primary p-1.5 text-primary-foreground">
              <Send className="h-3.5 w-3.5" />
            </button>
          </form>
        </div>
      )}
    </>
  )
}

// ── Live clock ───────────────────────────────────────────────────────────── //
function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
      {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
    </span>
  )
}

// ── Shell ────────────────────────────────────────────────────────────────── //
function Shell() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuth()

  const signOut = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      {/* ══ Header ══════════════════════════════════════════════════════════ */}
      <header className="relative shrink-0 border-b border-border/60 bg-panel/80 backdrop-blur-md">
        {/* Subtle glow line at top */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/60 to-transparent" />

        <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4 px-6 py-3">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="relative grid h-10 w-10 place-items-center rounded-xl border border-primary/40 bg-primary/10 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
              <ShieldCheck className="h-5 w-5 text-primary" />
              {/* Pulsing ring */}
              <span className="absolute inset-0 rounded-xl border border-primary/20 animate-ping opacity-30" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-wide text-foreground">AI-NIDS</span>
                <span className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-primary">
                  LIVE
                </span>
              </div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground/70">
                Network Intrusion Detection
              </div>
            </div>
          </div>

          {/* Navigation tabs */}
          <nav className="flex max-w-[58vw] items-center gap-1 overflow-x-auto rounded-xl border border-border/60 bg-background/40 p-1 print:hidden">
            <NavLink
              to="/dashboard"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <LayoutDashboard className="h-3.5 w-3.5" />
              Dashboard
            </NavLink>
            <NavLink
              to="/detections"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Detections
            </NavLink>
            <NavLink
              to="/notifications"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <Bell className="h-3.5 w-3.5" />
              Alerts
            </NavLink>
            {user?.role === 'admin' && (
              <NavLink
                to="/settings"
                className={({ isActive }) => cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-200',
                  isActive
                    ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                    : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
                )}
              >
                <Settings className="h-3.5 w-3.5" />
                Settings
              </NavLink>
            )}
            <NavLink
              to="/about"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <Info className="h-3.5 w-3.5" />
              Overview
            </NavLink>
            <NavLink
              to="/capture"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <Wifi className="h-3.5 w-3.5" />
              Live Capture
            </NavLink>
            <NavLink
              to="/simulation"
              className={({ isActive }) => cn(
                'flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-[0_0_16px_rgba(34,211,238,0.3)]'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
              )}
            >
              <Radio className="h-3.5 w-3.5" />
              Attack Simulation
            </NavLink>
          </nav>

          {/* Right side — status indicators */}
          <div className="flex items-center gap-3">
            {/* Clock */}
            <LiveClock />

            <div className="h-4 w-px bg-border/60" />

            {/* Model badge */}
            <div className="flex items-center gap-1.5 rounded-lg border border-border/60 bg-background/40 px-2.5 py-1.5 text-[10px]">
              <Brain className="h-3 w-3 text-primary" />
              <span className="text-muted-foreground">Random Forest</span>
              <span className="font-semibold text-emerald-400">99.6%</span>
            </div>

            {/* Live indicator */}
            <div className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1.5 text-[10px]">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </span>
              <span className="font-semibold text-emerald-400">MONITORING</span>
            </div>
            {user && (
              <button
                type="button"
                onClick={() => void signOut()}
                className="flex items-center gap-1.5 rounded-lg border border-border/60 bg-background/40 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:border-destructive/40 hover:text-foreground"
                aria-label="Sign out"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span>Sign out</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {/* ══ Page content ════════════════════════════════════════════════════ */}
      <main className="flex-1 overflow-y-auto">
        {/* Grid background lines */}
        <div className="pointer-events-none fixed inset-0 grid-line opacity-20" />
        <div className="relative mx-auto max-w-[1500px] p-4 lg:p-6">
          <Routes>
            <Route path="/about"      element={<About />} />
            <Route path="/dashboard"  element={<Dashboard />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="/settings" element={<SettingsCenter />} />
            <Route path="/capture"    element={<LiveCapture />} />
            <Route path="/simulation" element={<Simulation />} />
            <Route path="*"           element={<Navigate to="/about" replace />} />
          </Routes>
        </div>
      </main>

      <MiniAssistant />
    </div>
  )
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/login" element={<Login />} />
      <Route path="/*" element={<Shell />} />
    </Routes>
  )
}
