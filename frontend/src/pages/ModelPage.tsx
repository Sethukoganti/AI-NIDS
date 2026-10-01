import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  BrainCircuit,
  GitBranch,
  Layers,
  RefreshCw,
  Target,
  TrendingUp,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Alert, KeyValue, Loading, PageHeader, StatCard } from '@/components/common'
import { ClassPerformanceChart, FeatureImportanceChart } from '@/components/charts/Charts'
import { api, errorMessage } from '@/lib/api'
import { formatNumber, formatPercent } from '@/lib/format'
import type { FeatureImportanceResponse, ModelInfo } from '@/lib/types'

interface ArchitecturePayload {
  stages: { id: string; name: string; detail: string; metrics: Record<string, unknown> }[]
  algorithm?: string
  dataset?: string
  limitations?: string[]
  evaluation_disclaimer?: string
}

interface ClassProfileFeature {
  median: number
  mean: number
  p95: number
  max: number
  normal_median: number
  ratio_vs_normal_median: number | null
}

interface ClassProfilesPayload {
  source: string
  note: string
  features_ranked: string[]
  profiles: Record<string, { rows_in_training_table: number; features: Record<string, ClassProfileFeature> }>
}

export function ModelPage() {
  const [info, setInfo] = useState<ModelInfo | null>(null)
  const [architecture, setArchitecture] = useState<ArchitecturePayload | null>(null)
  const [profiles, setProfiles] = useState<ClassProfilesPayload | null>(null)
  const [profileClass, setProfileClass] = useState<string>('')
  const [topFeatures, setTopFeatures] = useState(20)
  const [importance, setImportance] = useState<FeatureImportanceResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [infoData, archData, profileData] = await Promise.all([
        api.get<ModelInfo>('/model/info'),
        api.get<ArchitecturePayload>('/model/architecture'),
        api.get<ClassProfilesPayload>('/model/class-profiles').catch(() => null),
      ])
      setInfo(infoData)
      setArchitecture(archData)
      setProfiles(profileData)
      if (profileData?.profiles) {
        const first = Object.keys(profileData.profiles).sort()[0] ?? ''
        setProfileClass((current) => current || first)
      }
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    api
      .get<FeatureImportanceResponse>(`/model/features?top=${topFeatures}`)
      .then(setImportance)
      .catch(() => setImportance(null))
  }, [topFeatures])

  const evaluation = (info?.evaluation ?? {}) as NonNullable<ModelInfo['evaluation']>
  const confusion = evaluation.confusion_matrix
  const maxCell = confusion
    ? Math.max(...confusion.matrix.flat().map((value) => value), 1)
    : 1

  return (
    <>
      <PageHeader
        title="AI Model"
        subtitle={
          <>
            The classifier driving every detection: a Random Forest trained on CICIDS2017. Metrics shown here
            are measured on the held-out test split recorded in the exported artifacts — never typed in by
            hand.
          </>
        }
        actions={
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
            Refresh
          </Button>
        }
      />

      {error && (
        <div className="mb-4">
          <Alert variant="error" title="Could not load model artifacts">
            {error}
          </Alert>
        </div>
      )}

      {loading && !info ? (
        <Loading label="Loading model card…" />
      ) : info ? (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Algorithm"
              value={info.algorithm ?? '—'}
              hint={`${info.n_estimators ?? '—'} trees · ${info.n_features ?? '—'} features`}
              icon={<BrainCircuit className="h-4 w-4" />}
              tone="info"
            />
            <StatCard
              label="Model test accuracy"
              value={evaluation.accuracy ? formatPercent(evaluation.accuracy, 2) : '—'}
              hint={`${formatNumber(evaluation.n_test)} held-out CICIDS2017 flows`}
              icon={<TrendingUp className="h-4 w-4" />}
              tone="good"
            />
            <StatCard
              label="Macro F1"
              value={evaluation.macro_f1 ? evaluation.macro_f1.toFixed(4) : '—'}
              hint="mean across all 9 traffic classes"
              icon={<Target className="h-4 w-4" />}
            />
            <StatCard
              label="Classes"
              value={info.classes?.length ?? info.n_classes ?? '—'}
              hint={`normal + ${(info.classes?.length ?? 9) - 1} attack families`}
              icon={<Layers className="h-4 w-4" />}
            />
          </div>

          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="features">Top features</TabsTrigger>
              <TabsTrigger value="evaluation">Evaluation</TabsTrigger>
              <TabsTrigger value="architecture">Architecture</TabsTrigger>
              <TabsTrigger value="profiles">Class profiles</TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <div className="grid gap-3 lg:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Model card</CardTitle>
                    <CardDescription>From model_metadata.json (exported by ml/train_model.py)</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-0.5">
                    <KeyValue label="Name" value={info.name ?? '—'} />
                    <KeyValue label="Version" value={info.version ?? '—'} />
                    <KeyValue label="Algorithm detail" value={info.algorithm_detail ?? info.algorithm ?? '—'} />
                    <KeyValue label="Trees" value={info.n_estimators ?? '—'} />
                    <KeyValue label="max_depth" value={info.max_depth ?? 'None (fully grown)'} />
                    <KeyValue
                      label="min_samples_leaf"
                      value={info.min_samples_leaf ?? '—'}
                    />
                    <KeyValue label="Random state" value={info.random_state ?? 42} />
                    <KeyValue label="Dataset" value={info.dataset ?? '—'} />
                    <KeyValue
                      label="Training table"
                      value={`${formatNumber(info.training_table?.rows)} flows × ${
                        info.training_table?.features ?? '—'
                      } features`}
                    />
                    <KeyValue
                      label="Split"
                      value={`${Math.round((info.train_split ?? 0.7) * 100)}% train / ${Math.round(
                        (info.test_split ?? 0.3) * 100,
                      )}% test`}
                    />
                    <KeyValue label="Model size" value={info.model_size_mb ? `${info.model_size_mb} MB` : '—'} />
                    <KeyValue label="Serialization" value={info.serialization ?? 'joblib'} />
                    <KeyValue label="Trained at" value={info.trained_at ?? '—'} />
                    <KeyValue
                      label="Loaded in API"
                      value={info.loaded ? 'yes' : info.load_error ? `no — ${info.load_error}` : 'no'}
                    />
                  </CardContent>
                </Card>

                <div className="space-y-3">
                  <Card>
                    <CardHeader>
                      <CardTitle>Classes detected</CardTitle>
                      <CardDescription>
                        Multi-class classifier — “Normal Traffic” plus the attack families present in the
                        training table.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-wrap gap-1.5">
                      {(info.classes ?? []).map((name) => (
                        <Badge key={name} variant={name === 'Normal Traffic' ? 'success' : 'danger'}>
                          {name}
                        </Badge>
                      ))}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Accuracy claim — read carefully</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-[11px] leading-relaxed text-muted-foreground">
                      <p className="text-foreground/90">
                        “{formatPercent(evaluation.accuracy ?? 0, 2)} accuracy on the current CICIDS2017 test
                        split ({formatNumber(evaluation.n_test)} flows).”
                      </p>
                      <p>{evaluation.disclaimer ?? 'Measured on a held-out split of a benchmark dataset.'}</p>
                      <p>
                        This is a result on a 2017 benchmark capture, not a guarantee of real-world detection.
                        No system can honestly claim to catch every possible attack.
                      </p>
                    </CardContent>
                  </Card>

                  {info.limitations && info.limitations.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Known limitations (from the artifacts)</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="list-disc space-y-1.5 pl-4 text-[11px] leading-relaxed text-muted-foreground">
                          {info.limitations.map((item, index) => (
                            <li key={index}>{item}</li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="features">
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <div>
                    <CardTitle>Top model features</CardTitle>
                    <CardDescription>
                      {importance?.source ?? 'model.feature_importances_'} ·{' '}
                      {importance?.method ?? 'mean decrease in impurity across all trees'}. Global importance
                      describes the model as a whole — per-record reasons come from the “Why?” view on a
                      prediction.
                    </CardDescription>
                  </div>
                  <Select
                    className="w-[130px]"
                    value={String(topFeatures)}
                    onChange={(event) => setTopFeatures(Number(event.target.value))}
                  >
                    {[10, 20, 30, 50].map((value) => (
                      <option key={value} value={value}>
                        Top {value}
                      </option>
                    ))}
                  </Select>
                </CardHeader>
                <CardContent>
                  {importance ? (
                    <FeatureImportanceChart
                      data={importance.importances}
                      height={Math.max(300, importance.importances.length * 22)}
                    />
                  ) : (
                    <p className="py-8 text-center text-xs text-muted-foreground">
                      Feature importances unavailable.
                    </p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="evaluation">
              <div className="space-y-3">
                <Card>
                  <CardHeader>
                    <CardTitle>Per-class performance on the held-out split</CardTitle>
                    <CardDescription>
                      {formatNumber(evaluation.n_train)} training flows · {formatNumber(evaluation.n_test)}{' '}
                      test flows · evaluated {evaluation.evaluated_at ?? ''}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {evaluation.per_class ? (
                      <ClassPerformanceChart perClass={evaluation.per_class} />
                    ) : (
                      <p className="py-8 text-center text-xs text-muted-foreground">
                        Evaluation artifact not available. Run <span className="font-mono">python ml/train_model.py</span>.
                      </p>
                    )}
                  </CardContent>
                </Card>

                {confusion && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Confusion matrix</CardTitle>
                      <CardDescription>
                        Rows are the true label, columns the predicted label. The diagonal is correct
                        classifications; darkness is scaled per matrix.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="overflow-x-auto">
                      <table className="w-full min-w-[620px] text-[10px]">
                        <thead>
                          <tr>
                            <th className="p-1.5 text-left text-muted-foreground">true ↓ / pred →</th>
                            {confusion.labels.map((label) => (
                              <th key={label} className="p-1.5 text-center text-muted-foreground">
                                {label.length > 9 ? `${label.slice(0, 8)}…` : label}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {confusion.matrix.map((row, rowIndex) => (
                            <tr key={rowIndex}>
                              <td className="whitespace-nowrap p-1.5 text-muted-foreground">
                                {confusion.labels[rowIndex]}
                              </td>
                              {row.map((value, columnIndex) => {
                                const isDiagonal = rowIndex === columnIndex
                                const intensity = value / maxCell
                                return (
                                  <td
                                    key={columnIndex}
                                    className="p-1.5 text-center font-mono"
                                    style={{
                                      background: isDiagonal
                                        ? `rgba(34, 211, 238, ${0.08 + intensity * 0.5})`
                                        : value > 0
                                          ? 'rgba(239, 68, 68, 0.18)'
                                          : 'transparent',
                                      color: value === 0 ? '#475569' : '#e2e8f0',
                                    }}
                                  >
                                    {value}
                                  </td>
                                )
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <p className="mt-3 text-[10px] leading-relaxed text-muted-foreground">
                        Non-diagonal cells are misclassifications. With heavily imbalanced benchmark traffic,
                        per-class recall (above) is the more meaningful number than overall accuracy.
                      </p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </TabsContent>

            <TabsContent value="architecture">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-primary" />
                    Detection pipeline
                  </CardTitle>
                  <CardDescription>
                    Rendered from GET /api/model/architecture with the real hyper-parameters and counts.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {(architecture?.stages ?? []).map((stage, index) => (
                    <div
                      key={stage.id}
                      className="flex flex-col gap-2 rounded-lg border border-border/70 bg-background/40 p-3 sm:flex-row sm:items-center sm:justify-between"
                    >
                      <div className="flex items-start gap-3">
                        <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md border border-primary/30 bg-primary/10 text-[10px] font-mono text-primary">
                          {index + 1}
                        </span>
                        <div>
                          <div className="text-xs font-medium">{stage.name}</div>
                          <div className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">
                            {stage.detail}
                          </div>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1.5 sm:justify-end">
                        {Object.entries(stage.metrics ?? {})
                          .filter(([, value]) => value !== null && value !== undefined)
                          .slice(0, 4)
                          .map(([key, value]) => (
                            <Badge key={key} variant="outline">
                              {key}: {typeof value === 'number' ? formatNumber(value) : String(value)}
                            </Badge>
                          ))}
                      </div>
                    </div>
                  ))}
                  {architecture?.evaluation_disclaimer && (
                    <p className="pt-1 text-[10px] leading-relaxed text-muted-foreground">
                      {architecture.evaluation_disclaimer}
                    </p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="profiles">
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-4 w-4 text-primary" />
                      Class profiles — feature medians per traffic class
                    </CardTitle>
                    <CardDescription>
                      {profiles?.note ??
                        'Computed from the cleaned training table; the AI layer uses these to compare a flow against its predicted class.'}
                    </CardDescription>
                  </div>
                  <Select
                    className="w-[180px]"
                    value={profileClass}
                    onChange={(event) => setProfileClass(event.target.value)}
                  >
                    {Object.keys(profiles?.profiles ?? {}).map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </Select>
                </CardHeader>
                <CardContent>
                  {!profiles || !profiles.profiles[profileClass] ? (
                    <p className="py-8 text-center text-xs text-muted-foreground">
                      class_profiles.json not available — run{' '}
                      <span className="font-mono">python ml/build_profiles.py</span>.
                    </p>
                  ) : (
                    <>
                      <p className="mb-3 text-[11px] text-muted-foreground">
                        {formatNumber(profiles.profiles[profileClass].rows_in_training_table)} training flows in
                        this class · {profiles.source}
                      </p>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Feature</TableHead>
                            <TableHead className="text-right">Class median</TableHead>
                            <TableHead className="text-right">Class p95</TableHead>
                            <TableHead className="text-right">Normal median</TableHead>
                            <TableHead className="text-right">Ratio vs normal</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Object.entries(profiles.profiles[profileClass].features).map(([feature, stats]) => (
                            <TableRow key={feature}>
                              <TableCell className="text-xs text-foreground/90">{feature}</TableCell>
                              <TableCell className="text-right font-mono text-xs">
                                {stats.median.toLocaleString(undefined, { maximumFractionDigits: 2 })}
                              </TableCell>
                              <TableCell className="text-right font-mono text-xs">
                                {stats.p95.toLocaleString(undefined, { maximumFractionDigits: 2 })}
                              </TableCell>
                              <TableCell className="text-right font-mono text-xs text-muted-foreground">
                                {stats.normal_median.toLocaleString(undefined, { maximumFractionDigits: 2 })}
                              </TableCell>
                              <TableCell className="text-right font-mono text-xs">
                                {stats.ratio_vs_normal_median === null
                                  ? '—'
                                  : `${stats.ratio_vs_normal_median.toFixed(2)}×`}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                      <p className="mt-3 text-[10px] leading-relaxed text-muted-foreground">
                        Ratios show how this class typically differs from normal traffic on each feature — the
                        same comparison the explanation layer quotes when it says a value is “elevated for this
                        attack family”.
                      </p>
                    </>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      ) : null}
    </>
  )
}
