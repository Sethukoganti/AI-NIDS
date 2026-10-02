import { useEffect, useState } from 'react'
import { AlertTriangle, Brain, Compass, Info, Loader2, Sparkles, Wand2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import { Alert, KeyValue, RiskBadge, VerdictBadge } from '@/components/common'
import { ShapWaterfall } from '@/components/charts/Charts'
import { api, errorMessage } from '@/lib/api'
import { formatNumber, formatPercent, relativeTime } from '@/lib/format'
import type { ExplanationResponse, Prediction } from '@/lib/types'

export function PredictionDetailDialog({
  predictionId,
  onClose,
}: {
  predictionId: string | null
  onClose: () => void
}) {
  const [detail, setDetail] = useState<Prediction | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [explanation, setExplanation] = useState<ExplanationResponse | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState<string | null>(null)

  useEffect(() => {
    if (!predictionId) {
      setDetail(null)
      setExplanation(null)
      setExplainError(null)
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    ;(async () => {
      try {
        const data = await api.get<Prediction>(`/predictions/${predictionId}?with_shap=true`)
        if (!cancelled) setDetail(data)
      } catch (err) {
        if (!cancelled) setError(errorMessage(err))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [predictionId])

  const requestExplanation = async (forceLocal: boolean) => {
    if (!predictionId) return
    setExplaining(true)
    setExplainError(null)
    try {
      const data = await api.get<ExplanationResponse>(
        `/predictions/${predictionId}/explain?force_local=${forceLocal}`,
      )
      setExplanation(data)
    } catch (err) {
      setExplainError(errorMessage(err))
    } finally {
      setExplaining(false)
    }
  }

  const shap = detail?.explanation
  const factors = detail?.top_factors ?? []
  const features = detail?.features ?? {}

  return (
    <Dialog open={Boolean(predictionId)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Compass className="h-4 w-4 text-primary" />
            Record inspection
            {detail && <span className="font-mono text-xs text-muted-foreground">#{detail.record_index}</span>}
          </DialogTitle>
          <DialogDescription>
            The stored prediction, the exact features that were fed to the model, and why the forest reached
            this verdict.
          </DialogDescription>
        </DialogHeader>

        {loading && (
          <div className="flex items-center gap-2 p-6 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Loading record and computing attribution…
          </div>
        )}

        {error && <Alert variant="error" title="Could not load record">{error}</Alert>}

        {detail && !loading && (
          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="why">Why this prediction?</TabsTrigger>
              <TabsTrigger value="features">Flow features</TabsTrigger>
              <TabsTrigger value="ai">AI explanation</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <VerdictBadge isAttack={detail.is_attack} label={detail.prediction} />
                <RiskBadge level={detail.risk_level} />
                <Badge variant="secondary">source: {detail.source}</Badge>
                {detail.blocklist_network && (
                  <Badge variant="danger">Blocklist policy match: {detail.blocklist_network}</Badge>
                )}
                {detail.ground_truth && (
                  <Badge variant={detail.ground_truth === detail.prediction ? 'success' : 'warning'}>
                    ground truth: {detail.ground_truth}
                  </Badge>
                )}
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                  <div className="label-xs mb-1">Model confidence</div>
                  <div className="text-lg font-semibold tabular-nums">{formatPercent(detail.confidence, 2)}</div>
                  <Progress value={detail.confidence * 100} className="mt-2 h-1.5" />
                  <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground">
                    Highest class probability from <span className="font-mono">predict_proba</span> over the 100
                    trees.
                  </p>
                </div>
                <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                  <div className="label-xs mb-1">Risk score</div>
                  <div className="text-lg font-semibold tabular-nums">{detail.risk_score.toFixed(4)}</div>
                  <Progress value={detail.risk_score * 100} className="mt-2 h-1.5" />
                  <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground">
                    Rules engine: attack severity weight × confidence, plus a small bonus for sensitive
                    destination ports. Displayed, not re-used as a model input.
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                <div className="space-y-0.5">
                  <KeyValue label="Source port" value={detail.source_port ?? '—'} mono />
                  <KeyValue label="Destination port" value={detail.destination_port ?? '—'} mono />
                  <KeyValue label="Source IP" value={detail.source_ip ?? 'not in dataset'} mono />
                  {detail.blocklist_network && (
                    <p className="pt-1 text-[10px] text-muted-foreground">
                      Matched the application-side analysis policy. This does not indicate that a firewall blocked the traffic.
                    </p>
                  )}
                  <KeyValue label="Destination IP" value={detail.destination_ip ?? 'not in dataset'} mono />
                  <KeyValue label="Protocol" value={detail.protocol ?? '—'} mono />
                  <KeyValue
                    label="Flow duration"
                    value={detail.flow_duration ? `${formatNumber(detail.flow_duration, 0)} µs` : '—'}
                    mono
                  />
                  <KeyValue
                    label="Packet rate"
                    value={detail.packet_rate ? `${formatNumber(detail.packet_rate, 2)} pkt/s` : '—'}
                    mono
                  />
                  <KeyValue label="Timestamp" value={relativeTime(detail.timestamp ?? detail.created_at)} />
                </div>
              </div>

              {detail.alerts && detail.alerts.length > 0 && (
                <div>
                  <div className="label-xs mb-2">Alerts raised for this record</div>
                  <div className="space-y-2">
                    {detail.alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="flex items-start gap-2 rounded-lg border border-border/70 bg-background/40 p-2.5"
                      >
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-400" />
                        <div className="text-xs">
                          <div className="flex items-center gap-2">
                            <RiskBadge level={alert.severity} />
                            <span className="font-medium">{alert.attack_type}</span>
                          </div>
                          <p className="mt-1 text-muted-foreground">{alert.message}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="why" className="space-y-3">
              {shap ? (
                <>
                  <Alert variant="info" title={`Attribution method: ${shap.method_label}`}>
                    These are real SHAP values computed with the model's TreeExplainer for{' '}
                    <span className="font-semibold">{shap.explained_class}</span> on this exact feature row.
                    Positive bars push the prediction towards the attack class; negative bars pull it back
                    towards normal traffic. Values are local to this record and add up to
                    predicted_value − base_value.
                  </Alert>
                  <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
                    <span>base value (expected model output): {shap.base_value.toFixed(5)}</span>
                    <span>this record: {shap.predicted_value.toFixed(5)}</span>
                  </div>
                  <ShapWaterfall contributions={shap.contributions} limit={10} />
                </>
              ) : (
                <>
                  {detail.fallback_explanation ? (
                    <Alert variant="warn" title="Per-record SHAP unavailable for this record">
                      The console is showing{' '}
                      <span className="font-semibold">global feature importance</span> instead. This describes
                      the model as a whole, not this individual verdict - it is labelled this way deliberately
                      so a per-record explanation is never implied where none exists.
                    </Alert>
                  ) : (
                    <Alert variant="warn" title="No explanation available">
                      The stored record does not carry attribution data.
                    </Alert>
                  )}
                  {factors.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="label-xs">Stored top factors (importance × deviation heuristic)</div>
                      {factors.map((factor) => (
                        <div
                          key={factor.feature}
                          className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-xs"
                        >
                          <span className="truncate">{factor.feature}</span>
                          <span className="font-mono text-[11px] text-muted-foreground">
                            value {factor.value?.toLocaleString(undefined, { maximumFractionDigits: 3 })} · score{' '}
                            {factor.score?.toFixed(4)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {detail.fallback_explanation && (
                    <div className="space-y-2">
                      <div className="label-xs">Global feature importance (top 8)</div>
                      {detail.fallback_explanation.importances.slice(0, 8).map((item) => (
                        <div key={item.feature} className="space-y-1">
                          <div className="flex justify-between text-xs">
                            <span className="truncate text-foreground/90">{item.feature}</span>
                            <span className="font-mono text-muted-foreground">{item.importance.toFixed(4)}</span>
                          </div>
                          <Progress value={item.importance * 100 * 2} className="h-1" />
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </TabsContent>

            <TabsContent value="features" className="space-y-3">
              <p className="text-xs text-muted-foreground">
                The feature vector that was actually scored, in the model's training column order (after
                preprocessing, imputation and alignment).
              </p>
              {Object.keys(features).length === 0 ? (
                <p className="text-xs text-muted-foreground">Feature vector not stored for this record.</p>
              ) : (
                <div className="max-h-[380px] overflow-y-auto rounded-lg border border-border/70">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-panel">
                      <tr>
                        <th className="px-3 py-2 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                          Feature
                        </th>
                        <th className="px-3 py-2 text-right text-[11px] uppercase tracking-wider text-muted-foreground">
                          Value
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(features).map(([name, value]) => (
                        <tr key={name} className="border-t border-border/50">
                          <td className="px-3 py-1.5 text-foreground/85">{name}</td>
                          <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                            {typeof value === 'number'
                              ? value.toLocaleString(undefined, { maximumFractionDigits: 4 })
                              : String(value ?? '—')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </TabsContent>

            <TabsContent value="ai" className="space-y-3">
              {!explanation && !explaining && (
                <>
                  <Alert variant="info" title="Evidence-grounded explanation">
                    The AI layer receives only the structured facts shown in this dialog - the flow features,
                    model output, risk score, SHAP drivers and (if present) the dataset ground truth - and is
                    instructed not to invent anything beyond them. Ask it for a narrative explanation, or read
                    the deterministic version generated locally.
                  </Alert>
                  <div className="flex gap-2">
                    <Button onClick={() => requestExplanation(true)} size="sm">
                      <Sparkles className="h-3.5 w-3.5" />
                      Generate explanation
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => requestExplanation(true)}>
                      <Wand2 className="h-3.5 w-3.5" />
                      Use local engine
                    </Button>
                  </div>
                </>
              )}

              {explaining && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Building explanation from evidence…
                </div>
              )}

              {explainError && <Alert variant="error" title="Explanation failed">{explainError}</Alert>}

              {explanation && (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <Badge variant="secondary">
                      <Brain className="mr-1 h-3 w-3" />
                      {explanation.provider_label}
                    </Badge>
                    <span className="text-muted-foreground">grounded on: {explanation.grounded_on}</span>
                  </div>
                  <div className="whitespace-pre-wrap rounded-lg border border-border/70 bg-background/40 p-4 text-xs leading-relaxed text-foreground/90">
                    {explanation.explanation}
                  </div>
                  <p className="flex items-start gap-1.5 text-[10px] leading-relaxed text-muted-foreground">
                    <Info className="mt-0.5 h-3 w-3 shrink-0" />
                    Treat this as an analyst aid, not evidence: it describes model behaviour on benchmark
                    data, not verified activity on a live network.
                  </p>
                </div>
              )}
            </TabsContent>
          </Tabs>
        )}
      </DialogContent>
    </Dialog>
  )
}
