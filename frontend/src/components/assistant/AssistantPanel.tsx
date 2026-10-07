import { useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Bot, Loader2, Send, Sparkles, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { api, errorMessage } from '@/lib/api'
import { cn } from '@/lib/format'
import type { AssistantResponse } from '@/lib/types'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  provider?: string
  sources?: string[]
  error?: boolean
}

interface AssistantStatus {
  provider?: string
  provider_label?: string
  enabled?: boolean
  mode?: string
}

const SUGGESTIONS = [
  'Summarise the current detection data',
  'Which attack type appears most frequently?',
  'What do the current alerts say?',
  'Explain how the Random Forest detects intrusions',
  'What are the documented risk rules?',
  'How accurate is the model?',
]

/**
 * Floating AI Security Assistant. Answers come from POST /api/assistant/ask,
 * which reads the real detection data server-side - the panel never fabricates
 * an answer and shows which provider produced it.
 */
export function AssistantPanel() {
  const location = useLocation()
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<AssistantStatus | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // Don't render on the full assistant page — it has its own chat UI
  const isAssistantPage = location.pathname === '/assistant'

  useEffect(() => {
    api
      .get<AssistantStatus>('/assistant/status')
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  useEffect(() => {
    if (open && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, open, busy])

  if (isAssistantPage) return null

  const ask = async (question: string) => {
    const text = question.trim()
    if (!text || busy) return
    setMessages((current) => [...current, { role: 'user', content: text }])
    setInput('')
    setBusy(true)
    try {
      const response = await api.post<AssistantResponse>('/assistant/ask', { question: text })
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          content: response.answer,
          provider: response.provider,
          sources: response.sources,
        },
      ])
    } catch (err) {
      setMessages((current) => [
        ...current,
        { role: 'assistant', content: errorMessage(err), error: true },
      ])
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {!open && (
        <Button
          onClick={() => setOpen(true)}
          className="fixed bottom-5 right-5 z-40 h-12 gap-2 rounded-full px-4 shadow-lg shadow-primary/20"
        >
          <Sparkles className="h-4 w-4" />
          AI Assistant
        </Button>
      )}

      {open && (
        <div className="fixed bottom-5 right-5 z-40 flex h-[560px] w-[calc(100vw-2.5rem)] max-w-[400px] flex-col overflow-hidden rounded-xl border border-border bg-panel/95 shadow-2xl backdrop-blur">
          <div className="flex items-center justify-between border-b border-border/70 px-4 py-3">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              <div className="leading-tight">
                <div className="text-sm font-semibold">AI Security Assistant</div>
                <div className="text-[10px] text-muted-foreground">
                  {status?.provider_label ?? status?.provider ?? 'local engine'} · answers only from stored
                  detections
                </div>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={() => setOpen(false)} aria-label="Close assistant">
              <X className="h-4 w-4" />
            </Button>
          </div>

          <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
            {messages.length === 0 && (
              <div className="space-y-3">
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Ask about the detections in this deployment. The assistant receives only structured output
                  from the model, the risk engine and the database - it is instructed not to invent evidence.
                  If nothing has been analysed yet it will say so instead of guessing.
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {SUGGESTIONS.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      onClick={() => ask(suggestion)}
                      className="rounded-md border border-border/70 bg-background/50 px-2 py-1 text-left text-[11px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((message, index) => (
              <div key={index} className={cn('flex', message.role === 'user' ? 'justify-end' : 'justify-start')}>
                <div
                  className={cn(
                    'max-w-[85%] whitespace-pre-wrap rounded-lg border px-3 py-2 text-xs leading-relaxed',
                    message.role === 'user'
                      ? 'border-primary/30 bg-primary/10 text-foreground'
                      : message.error
                        ? 'border-red-500/30 bg-red-500/5 text-red-200'
                        : 'border-border/70 bg-background/50 text-foreground/90',
                  )}
                >
                  {message.role === 'assistant' && message.provider && (
                    <div className="mb-1.5">
                      <Badge variant="secondary">{message.provider}</Badge>
                    </div>
                  )}
                  {message.content}
                  {message.sources && message.sources.length > 0 && (
                    <div className="mt-2 border-t border-border/50 pt-1.5 text-[10px] text-muted-foreground">
                      grounded on: {message.sources.join(' · ')}
                    </div>
                  )}
                  {message.role === 'assistant' &&
                    !busy &&
                    !messages.slice(index + 1).some((item) => item.role === 'assistant') && (
                      <div className="mt-2 border-t border-border/50 pt-2">
                        <p className="mb-1.5 text-[10px] font-semibold text-muted-foreground">Ask a follow-up:</p>
                        <div className="flex flex-wrap gap-1.5">
                          {SUGGESTIONS
                            .filter((suggestion) => !messages.some(
                              (item) =>
                                item.role === 'user' &&
                                item.content.toLocaleLowerCase() === suggestion.toLocaleLowerCase(),
                            ))
                            .slice(0, 3)
                            .map((suggestion) => (
                              <button
                                key={suggestion}
                                type="button"
                                onClick={() => ask(suggestion)}
                                className="rounded-md border border-border/70 bg-background/50 px-2 py-1 text-left text-[10px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                              >
                                {suggestion}
                              </button>
                            ))}
                        </div>
                      </div>
                    )}
                </div>
              </div>
            ))}

            {busy && (
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Reading the detection data…
              </div>
            )}
          </div>

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
              placeholder="e.g. what are the risk rules?"
              disabled={busy}
            />
            <Button type="submit" size="icon" disabled={busy || !input.trim()} aria-label="Send question">
              <Send className="h-3.5 w-3.5" />
            </Button>
          </form>
        </div>
      )}
    </>
  )
}
