import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bot, BrainCircuit, Info, Loader2, Send, ShieldCheck, Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { KeyValue, PageHeader } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { cn } from '@/lib/format'
import type { AssistantResponse } from '@/lib/types'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  provider?: string
  sources?: string[]
  evidence?: Record<string, unknown>
  error?: boolean
}

interface AssistantStatus {
  provider: string
  enabled: boolean
  mode: string
  model?: string | null
  api_key_configured?: boolean
  note?: string
}

const SUGGESTIONS = [
  { label: 'Summarise the current detection data', hint: 'aggregates from the database' },
  { label: 'Which attack type appears most frequently?', hint: 'top_attack intent' },
  { label: 'What do the current alerts say?', hint: 'alert queue' },
  { label: 'Explain how the Random Forest detects intrusions', hint: 'model explanation' },
  { label: 'What are the documented risk rules?', hint: 'risk engine' },
  { label: 'How accurate is the model?', hint: 'measured test-split metrics' },
]

export function Insights() {
  const [status, setStatus] = useState<AssistantStatus | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [showEvidence, setShowEvidence] = useState<string | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    api
      .get<AssistantStatus>('/assistant/status')
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages, busy])

  const ask = async (question: string) => {
    const text = question.trim()
    if (!text || busy) return
    setMessages((current) => [...current, { role: 'user', content: text }])
    setInput('')
    setBusy(true)
    try {
      const response = await api.post<AssistantResponse>('/assistant/ask', {
        question: text,
        include_evidence: true,
      })
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: response.answer,
          provider: response.provider,
          sources: response.sources,
          evidence: (response as { evidence?: Record<string, unknown> }).evidence,
        },
      ])
    } catch (err) {
      setMessages((current) => [...current, { role: 'assistant', content: errorMessage(err), error: true }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        title="AI Security Assistant"
        subtitle={
          <>
            The assistant answers questions about this deployment from real, structured data only: model
            output, risk scores, alert rows and database aggregates. It cannot browse, and it is instructed to
            refuse to invent evidence — if nothing has been analysed it says so.
          </>
        }
        actions={
          <Badge variant="secondary">
            <BrainCircuit className="mr-1 h-3 w-3" />
            {status ? status.mode : 'checking provider…'}
          </Badge>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Card className="flex h-[640px] flex-col">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-primary" />
              Conversation
            </CardTitle>
            <CardDescription>
              Ask about detections, alerts, the risk rules or how the model works.
            </CardDescription>
          </CardHeader>

          <CardContent ref={scrollRef as never} className="flex-1 space-y-3 overflow-y-auto">
            {messages.length === 0 && (
              <div className="space-y-3">
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Try one of these — each maps to a different intent on the backend so you can see the answers
                  come from different parts of the real data:
                </p>
                <div className="grid gap-2 sm:grid-cols-2">
                  {SUGGESTIONS.map((suggestion) => (
                    <button
                      key={suggestion.label}
                      type="button"
                      onClick={() => ask(suggestion.label)}
                      className="rounded-lg border border-border/70 bg-background/40 p-2.5 text-left transition-colors hover:border-primary/40"
                    >
                      <div className="text-[11px] font-medium text-foreground/90">{suggestion.label}</div>
                      <div className="mt-0.5 text-[10px] text-muted-foreground">{suggestion.hint}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((message, index) => (
              <div key={index} className={cn('flex', message.role === 'user' ? 'justify-end' : 'justify-start')}>
                <div
                  className={cn(
                    'max-w-[88%] rounded-lg border px-3.5 py-2.5 text-xs leading-relaxed',
                    message.role === 'user'
                      ? 'border-primary/30 bg-primary/10'
                      : message.error
                        ? 'border-red-500/30 bg-red-500/5 text-red-200'
                        : 'border-border/70 bg-background/50',
                  )}
                >
                  {message.role === 'assistant' && (
                    <div className="mb-1.5 flex items-center gap-2">
                      {message.provider && <Badge variant="secondary">{message.provider}</Badge>}
                      {message.sources && message.sources.length > 0 && (
                        <span className="text-[10px] text-muted-foreground">
                          grounded on: {message.sources.join(' · ')}
                        </span>
                      )}
                    </div>
                  )}
                  <div className="whitespace-pre-wrap text-foreground/90">{message.content}</div>

                  {message.evidence && Object.keys(message.evidence).length > 0 && (
                    <div className="mt-2">
                      <button
                        type="button"
                        className="text-[10px] text-primary underline-offset-2 hover:underline"
                        onClick={() => setShowEvidence(showEvidence === String(index) ? null : String(index))}
                      >
                        {showEvidence === String(index) ? 'hide' : 'view'} structured evidence
                      </button>
                      {showEvidence === String(index) && (
                        <pre className="mt-1.5 max-h-56 overflow-auto rounded-md border border-border/60 bg-background/70 p-2 text-[10px] leading-relaxed text-muted-foreground">
                          {JSON.stringify(message.evidence, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {busy && (
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Querying the detection data…
              </div>
            )}
          </CardContent>

          <form
            className="flex items-center gap-2 border-t border-border/70 p-3"
            onSubmit={(event) => {
              event.preventDefault()
              ask(input)
            }}
          >
            <Input
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="Ask about detections, alerts, risk rules or the model…"
              disabled={busy}
            />
            <Button type="submit" disabled={busy || !input.trim()}>
              <Send className="h-3.5 w-3.5" />
              Ask
            </Button>
          </form>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bot className="h-4 w-4 text-primary" />
                Provider status
              </CardTitle>
              <CardDescription>From GET /api/assistant/status</CardDescription>
            </CardHeader>
            <CardContent className="space-y-0.5">
              <KeyValue label="Provider" value={status?.provider ?? '—'} />
              <KeyValue
                label="Mode"
                value={
                  status?.enabled ? (
                    <span className="text-emerald-400">external LLM</span>
                  ) : (
                    'local explanation engine'
                  )
                }
              />
              <KeyValue label="Model" value={status?.model ?? 'n/a'} />
              <KeyValue
                label="API key configured"
                value={status?.api_key_configured ? 'yes' : 'no (server-side env only)'}
              />
              {status?.note && (
                <p className="pt-2 text-[10px] leading-relaxed text-muted-foreground">{status.note}</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-primary" />
                How answers stay grounded
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-[11px] leading-relaxed text-muted-foreground">
              <p>
                Each question is answered from a structured evidence package assembled server-side:
              </p>
              <ul className="list-disc space-y-1 pl-4">
                <li>database aggregates (counts, distributions, timelines)</li>
                <li>stored predictions with model confidence and risk scores</li>
                <li>alert rows with severity, status and port context</li>
                <li>SHAP / feature-importance drivers when a specific record is discussed</li>
                <li>measured evaluation metrics from the held-out test split</li>
              </ul>
              <p>
                The LLM layer (when configured) receives only that package and is instructed not to add
                outside facts; with no provider configured the deterministic local engine produces the answer
                instead, so the feature works out of the box.
              </p>
              <p className="text-[10px]">
                The API key is read from the backend environment and is never sent to this browser.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="space-y-2 p-4 text-[11px] leading-relaxed text-muted-foreground">
              <p className="flex items-start gap-1.5">
                <Info className="mt-0.5 h-3 w-3 shrink-0" />
                Answers describe the model's behaviour on benchmark data. They are analyst aids, not evidence
                of activity on a production network.
              </p>
              <p>
                For per-record explanations, open a flow on{' '}
                <Link className="text-primary underline" to="/detections">
                  Prediction Results
                </Link>{' '}
                and use the “Why this prediction?” tab.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
