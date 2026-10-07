import { useEffect, useRef, useState } from 'react'
import {
  Bot,
  Check,
  Copy,
  Cpu,
  Database,
  FileText,
  HelpCircle,
  Lock,
  MessageSquare,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  User,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert as InlineAlert, Loading, PageHeader } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { useAuth } from '@/context/AuthContext'
import type { AssistantResponse } from '@/lib/types'

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  mode?: 'analyst' | 'admin'
  provider?: string
  sources?: string[]
  facts?: Record<string, unknown>
  evidence?: Record<string, unknown>
  timestamp: string
  error?: boolean
}

const ANALYST_SUGGESTIONS = [
  'Why was this traffic classified as suspicious?',
  'Explain how Port Scanning is detected',
  'What is the difference between DoS and DDoS in the model?',
  'Summarize today’s detected traffic and attack classes',
  'Show the most recent detections',
  'Break down detections by risk level',
  'Which source IPs appear most often?',
  'How often did predictions match dataset labels?',
  'How does the risk scoring engine work?',
  'Summarize active investigations and unresolved alerts',
]

const ADMIN_SUGGESTIONS = [
  'Explain the current operational network state',
  'Summarize system health and component status',
  'Explain active detection and alert thresholds',
  'Show recent administrative actions and audit logs',
  'Summarize Random Forest model accuracy and training dataset',
  'Explain duplicate alert suppression and auto-incident policies',
  'Show the most recent detections',
  'Break down detections by risk level',
  'How often did predictions match dataset labels?',
]

export function AssistantPage() {
  const { user, isAdmin } = useAuth()
  const [mode, setMode] = useState<'analyst' | 'admin'>(isAdmin ? 'admin' : 'analyst')
  const [technicalLevel, setTechnicalLevel] = useState<'simple' | 'technical'>('technical')
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content:
        `Welcome to the **AI-NIDS Security Copilot**. I am an evidence-grounded AI assistant trained to interpret ` +
        `Random Forest intrusion detections, feature importances, TreeSHAP values, network operational states, ` +
        `and incident cases. All answers are strictly grounded in stored application telemetry.\n\n` +
        `How can I assist your security analysis today?`,
      timestamp: new Date().toLocaleTimeString(),
      sources: ['CICIDS2017 Random Forest Model', 'Telemetry Database'],
    },
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [assistantStatus, setAssistantStatus] = useState<any>(null)
  const messagesEndRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    api.get('/assistant/status').then(setAssistantStatus).catch(() => null)
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, busy])

  const handleSend = async (questionText?: string) => {
    const q = (questionText || input).trim()
    if (!q || busy) return

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: q,
      mode,
      timestamp: new Date().toLocaleTimeString(),
    }

    setMessages((prev) => [...prev, userMsg])
    if (!questionText) setInput('')
    setBusy(true)

    try {
      const response = await api.post<AssistantResponse>('/assistant/ask', {
        question: q + (technicalLevel === 'simple' ? ' (in simple plain terms)' : ''),
        include_evidence: true,
      })

      const assistantMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: response.answer,
        mode,
        provider: response.provider,
        sources: response.sources,
        facts: response.facts,
        evidence: response.evidence,
        timestamp: new Date().toLocaleTimeString(),
      }

      setMessages((prev) => [...prev, assistantMsg])
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: 'assistant',
          content: errorMessage(err),
          error: true,
          timestamp: new Date().toLocaleTimeString(),
        },
      ])
    } finally {
      setBusy(false)
    }
  }

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleClear = () => {
    setMessages([
      {
        id: 'welcome',
        role: 'assistant',
        content: 'Conversation cleared. How can I assist your security analysis today?',
        timestamp: new Date().toLocaleTimeString(),
      },
    ])
  }

  const activeSuggestions = mode === 'admin' ? ADMIN_SUGGESTIONS : ANALYST_SUGGESTIONS

  return (
    <>
      <PageHeader
        title="AI Security Copilot"
        subtitle="Grounded security intelligence assistant. Answers are derived directly from model features, TreeSHAP drivers, telemetry aggregates, and operational configuration."
        icon={Sparkles}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleClear}>
              <Trash2 className="h-3.5 w-3.5" />
              Clear Conversation
            </Button>
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-4">
        {/* Main Chat Area */}
        <div className="lg:col-span-3 flex flex-col h-[75vh] rounded-xl border border-border bg-panel overflow-hidden shadow-sm">
          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between border-b border-border px-4 py-2.5 bg-muted/20 gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-muted-foreground">Mode:</span>
              <Tabs
                value={mode}
                onValueChange={(v) => {
                  if (v === 'admin' && !isAdmin) return
                  setMode(v as 'analyst' | 'admin')
                }}
              >
                <TabsList className="h-7 text-xs">
                  <TabsTrigger value="analyst" className="text-xs px-2.5">
                    Analyst Mode
                  </TabsTrigger>
                  <TabsTrigger value="admin" disabled={!isAdmin} className="text-xs px-2.5">
                    {!isAdmin && <Lock className="h-2.5 w-2.5 mr-1" />}
                    Admin Mode
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-muted-foreground">Detail:</span>
              <Tabs value={technicalLevel} onValueChange={(v) => setTechnicalLevel(v as 'simple' | 'technical')}>
                <TabsList className="h-7 text-xs">
                  <TabsTrigger value="simple" className="text-xs px-2">Simple</TabsTrigger>
                  <TabsTrigger value="technical" className="text-xs px-2">Technical</TabsTrigger>
                </TabsList>
              </Tabs>

              {assistantStatus && (
                <Badge variant="outline" className="text-[10px] font-mono ml-2">
                  Engine: {assistantStatus.provider === 'none' ? 'Local Deterministic' : assistantStatus.provider}
                </Badge>
              )}
            </div>
          </div>

          {/* Messages Stream */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg, index) => (
              <div
                key={msg.id}
                className={`flex gap-3 text-xs leading-relaxed ${
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {msg.role === 'assistant' && (
                  <div className="h-7 w-7 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5 text-primary">
                    <Bot className="h-4 w-4" />
                  </div>
                )}

                <div
                  className={`relative max-w-2xl rounded-xl p-3.5 shadow-sm space-y-2 ${
                    msg.role === 'user'
                      ? 'bg-primary text-primary-foreground font-medium'
                      : msg.error
                      ? 'bg-destructive/10 border border-destructive/30 text-destructive'
                      : 'bg-card border border-border/80 text-foreground'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3 text-[10px] opacity-70 mb-1">
                    <span className="font-semibold uppercase tracking-wider">
                      {msg.role === 'user' ? user?.name || 'Operator' : 'Security Copilot'}
                    </span>
                    <div className="flex items-center gap-2 font-mono">
                      <span>{msg.timestamp}</span>
                      {msg.role === 'assistant' && (
                        <button
                          onClick={() => handleCopy(msg.id, msg.content)}
                          className="hover:text-primary transition-colors p-0.5"
                          title="Copy text"
                        >
                          {copiedId === msg.id ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="whitespace-pre-line leading-relaxed text-xs">
                    {msg.content}
                  </div>

                  {msg.sources && msg.sources.length > 0 && (
                    <div className="pt-2 border-t border-border/40 text-[10px] text-muted-foreground flex flex-wrap items-center gap-1.5 font-mono">
                      <span className="font-semibold">Sources:</span>
                      {msg.sources.map((s, idx) => (
                        <Badge key={idx} variant="outline" className="text-[9px] px-1.5 py-0">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  )}

                  {msg.role === 'assistant' &&
                    !busy &&
                    !messages.slice(index + 1).some((message) => message.role === 'assistant') && (
                      <div className="border-t border-border/40 pt-2">
                        <p className="mb-1.5 text-[10px] font-semibold text-muted-foreground">Ask a follow-up:</p>
                        <div className="flex flex-wrap gap-1.5">
                          {activeSuggestions
                            .filter((question) => !messages.some(
                              (message) =>
                                message.role === 'user' &&
                                message.content.toLocaleLowerCase() === question.toLocaleLowerCase(),
                            ))
                            .slice(0, 3)
                            .map((question) => (
                              <button
                                key={question}
                                type="button"
                                onClick={() => handleSend(question)}
                                className="rounded-md border border-border/60 bg-background/40 px-2 py-1 text-left text-[10px] text-muted-foreground hover:border-primary/40 hover:text-foreground"
                              >
                                {question}
                              </button>
                            ))}
                        </div>
                      </div>
                    )}
                </div>

                {msg.role === 'user' && (
                  <div className="h-7 w-7 rounded-lg bg-muted border border-border flex items-center justify-center shrink-0 mt-0.5 text-muted-foreground font-semibold">
                    <User className="h-4 w-4" />
                  </div>
                )}
              </div>
            ))}

            {busy && (
              <div className="flex gap-3 text-xs justify-start">
                <div className="h-7 w-7 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5 text-primary">
                  <Bot className="h-4 w-4 animate-pulse" />
                </div>
                <div className="bg-card border border-border rounded-xl p-3 text-muted-foreground flex items-center gap-2">
                  <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  <span className="text-xs">Analyzing application telemetry and building evidence package...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Box */}
          <div className="border-t border-border p-3 bg-muted/10">
            <form
              onSubmit={(e) => {
                e.preventDefault()
                handleSend()
              }}
              className="flex gap-2"
            >
              <Input
                placeholder={
                  mode === 'admin'
                    ? 'Ask about network state, system health, audit logs, or configuration...'
                    : 'Ask about flagged traffic, alert causes, attack classes, or investigations...'
                }
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="text-xs"
                disabled={busy}
              />
              <Button type="submit" size="sm" disabled={busy || !input.trim()} className="gap-1.5">
                <Send className="h-3.5 w-3.5" />
                Ask
              </Button>
            </form>
          </div>
        </div>

        {/* Sidebar Suggestions & Grounding Panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <HelpCircle className="h-3.5 w-3.5 text-primary" />
                Suggested Questions ({mode.toUpperCase()})
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {activeSuggestions.map((q, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSend(q)}
                  disabled={busy}
                  className="w-full text-left text-[11px] p-2 rounded-lg border border-border/60 hover:border-primary/40 hover:bg-muted/40 transition-colors text-muted-foreground hover:text-foreground leading-snug"
                >
                  {q}
                </button>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-primary" />
                Grounding Principles
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-[11px] text-muted-foreground leading-relaxed">
              <p>
                <strong>No Hallucinations:</strong> The assistant only uses real SQL records, model features, and class statistics.
              </p>
              <p>
                <strong>Role Isolation:</strong> Analysts cannot access sensitive administrative audit trails or configuration secrets.
              </p>
              <p>
                <strong>Probabilistic Honesty:</strong> A detection is explained as a model probability, never as simulated certainty.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
