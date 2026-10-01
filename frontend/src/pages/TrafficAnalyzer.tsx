import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  CheckCircle2,
  Database,
  FileSpreadsheet,
  FlaskConical,
  Loader2,
  Sparkles,
  Upload,
  UploadCloud,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Alert, KeyValue, PageHeader, StatusBadge } from '@/components/common'
import { api, errorMessage } from '@/lib/api'
import { api as apiClient } from '@/lib/api'
import { formatBytes, formatNumber, formatPercent } from '@/lib/format'
import type { AnalysisJob, AnalysisSummary, DatasetSummary } from '@/lib/types'
import { cn } from '@/lib/format'

const STEPS = [
  'Upload CSV',
  'Validate file',
  'Preprocess',
  'Feature alignment',
  'Random Forest',
  'Predictions',
  'Risk analysis',
  'Results',
]

export function TrafficAnalyzer() {
  const [file, setFile] = useState<File | null>(null)
  const [dataset, setDataset] = useState<DatasetSummary | null>(null)
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [job, setJob] = useState<AnalysisJob | null>(null)
  const [summary, setSummary] = useState<AnalysisSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [datasets, setDatasets] = useState<DatasetSummary[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const pollRef = useRef<number | null>(null)

  const loadDatasets = useCallback(async () => {
    try {
      const page = await api.get<{ items: DatasetSummary[] }>('/datasets?page=1&page_size=50')
      setDatasets(page.items)
    } catch {
      /* the list is a convenience only */
    }
  }, [])

  useEffect(() => {
    loadDatasets()
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [loadDatasets])

  const handleFiles = (files: FileList | null) => {
    if (!files || !files.length) return
    setFile(files[0])
    setError(null)
    setNotice(null)
    setSummary(null)
    setDataset(null)
    setJob(null)
  }

  const upload = async () => {
    if (!file) return
    setUploading(true)
    setError(null)
    try {
      const result = await api.upload<DatasetSummary>('/datasets/upload', file)
      setDataset(result)
      setNotice(result.message ?? 'File uploaded and profiled.')
      loadDatasets()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setUploading(false)
    }
  }

  const useSample = async (sample: 'sample_traffic' | 'simulation_stream') => {
    setUploading(true)
    setError(null)
    try {
      const result = await api.post<DatasetSummary>('/datasets/sample', { sample })
      setDataset(result)
      setNotice(result.message ?? 'Sample dataset ready.')
      setFile(null)
      loadDatasets()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setUploading(false)
    }
  }

  const analyze = async (target?: DatasetSummary) => {
    const active = target ?? dataset
    if (!active) return
    setAnalyzing(true)
    setError(null)
    setSummary(null)
    setJob(null)
    try {
      const response = await api.post<{ mode: string; job: AnalysisJob; summary?: AnalysisSummary }>(
        '/predictions/analyze',
        { dataset_id: active.id, force_sync: active.rows <= 20_000 },
      )
      setJob(response.job)
      if (response.summary) {
        setSummary(response.summary)
        setAnalyzing(false)
      } else {
        startPolling(response.job.id)
      }
    } catch (err) {
      setError(errorMessage(err))
      setAnalyzing(false)
    }
  }

  const startPolling = (jobId: string) => {
    if (pollRef.current) window.clearInterval(pollRef.current)
    pollRef.current = window.setInterval(async () => {
      try {
        const current = await api.get<AnalysisJob>(`/predictions/jobs/${jobId}`)
        setJob(current)
        if (current.status === 'completed' || current.status === 'failed') {
          if (pollRef.current) window.clearInterval(pollRef.current)
          setAnalyzing(false)
          if (current.status === 'completed') setSummary(current.summary as AnalysisSummary)
          else setError(current.error ?? 'Analysis failed.')
        }
      } catch {
        /* keep polling */
      }
    }, 900)
  }

  const activeStep = analyzing ? 4 : summary ? 7 : dataset ? 2 : file ? 1 : 0

  return (
    <>
      <PageHeader
        title="Traffic Analyzer"
        subtitle={
          <>
            Upload CICIDS2017-compatible network-flow CSV data. The file is profiled, validated against the
            model's trained feature schema, preprocessed, and scored by the Random Forest - then stored so
            every flow can be inspected, filtered and explained.
          </>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
        {STEPS.map((step, index) => (
          <div key={step} className="flex items-center gap-1.5">
            <span
              className={cn(
                'rounded-md border px-2 py-0.5',
                index <= activeStep
                  ? 'border-primary/40 bg-primary/10 text-primary'
                  : 'border-border/70 bg-background/40',
              )}
            >
              {step}
            </span>
            {index < STEPS.length - 1 && <ArrowRight className="h-3 w-3 opacity-50" />}
          </div>
        ))}
      </div>

      {error && (
        <div className="mb-4">
          <Alert variant="error" title="Analysis error">
            {error}
          </Alert>
        </div>
      )}
      {notice && !error && (
        <div className="mb-4">
          <Alert variant="success" title="Ready">
            {notice}
          </Alert>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[1.15fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>1 · Provide traffic data</CardTitle>
            <CardDescription>
              CSV or parquet flow exports. Maximum {formatBytes(25 * 1024 * 1024)} per upload; up to
              200,000 rows are analysed per job.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <label
              onDragOver={(e) => {
                e.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragging(false)
                handleFiles(e.dataTransfer.files)
              }}
              className={cn(
                'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-8 text-center transition-colors',
                dragging ? 'border-primary/60 bg-primary/5' : 'border-border/80 hover:border-primary/40 hover:bg-muted/20',
              )}
            >
              <input
                ref={inputRef}
                type="file"
                accept=".csv,.txt,.tsv,.parquet,.pq"
                className="hidden"
                onChange={(e) => handleFiles(e.target.files)}
              />
              <UploadCloud className="h-7 w-7 text-primary" />
              <div className="text-sm font-medium">Drag &amp; drop a network-flow CSV here</div>
              <div className="text-[11px] text-muted-foreground">or click to browse · .csv .txt .tsv .parquet</div>
            </label>

            {file && (
              <div className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-background/40 p-3">
                <div className="flex min-w-0 items-center gap-2">
                  <FileSpreadsheet className="h-4 w-4 shrink-0 text-primary" />
                  <div className="min-w-0">
                    <div className="truncate text-xs font-medium">{file.name}</div>
                    <div className="text-[10px] text-muted-foreground">{formatBytes(file.size)}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" onClick={upload} disabled={uploading}>
                    {uploading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
                    Upload
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setFile(null)
                      setDataset(null)
                      setSummary(null)
                    }}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            )}

            <Separator />

            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
                <FlaskConical className="h-3.5 w-3.5" />
                Or use the bundled held-out CICIDS2017 samples (never used for training)
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <Button variant="outline" size="sm" onClick={() => useSample('sample_traffic')} disabled={uploading}>
                  1,500 mixed flows
                </Button>
                <Button variant="outline" size="sm" onClick={() => useSample('simulation_stream')} disabled={uploading}>
                  800-flow stream
                </Button>
              </div>
            </div>

            {datasets.length > 0 && (
              <>
                <Separator />
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
                    <Database className="h-3.5 w-3.5" />
                    Previously uploaded datasets
                  </div>
                  <div className="max-h-52 space-y-1.5 overflow-y-auto pr-1">
                    {datasets.map((item) => (
                      <div
                        key={item.id}
                        className="flex items-center justify-between gap-2 rounded-lg border border-border/70 bg-background/30 p-2"
                      >
                        <div className="min-w-0">
                          <div className="truncate text-[11px] font-medium">{item.filename}</div>
                          <div className="text-[10px] text-muted-foreground">
                            {formatNumber(item.rows)} rows × {item.columns} cols ·{' '}
                            {formatPercent(item.feature_coverage ?? 0, 0)} schema coverage
                          </div>
                        </div>
                        <Button size="sm" variant="secondary" onClick={() => analyze(item)} disabled={analyzing}>
                          Analyze
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>2 · Dataset profile</CardTitle>
              <CardDescription>
                Profiled server-side; the browser only ever receives a bounded preview.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!dataset ? (
                <p className="py-6 text-center text-xs text-muted-foreground">
                  Upload a file (or pick a sample) to see its profile.
                </p>
              ) : (
                <div className="space-y-0.5">
                  <KeyValue label="File name" value={dataset.filename} />
                  <KeyValue label="Rows" value={formatNumber(dataset.rows)} />
                  <KeyValue label="Columns" value={dataset.columns} />
                  <KeyValue label="Size" value={formatBytes(dataset.size_bytes)} />
                  <KeyValue
                    label="Model schema coverage"
                    value={
                      <span className={cn((dataset.feature_coverage ?? 0) >= 0.8 ? 'text-emerald-400' : 'text-yellow-400')}>
                        {formatPercent(dataset.feature_coverage ?? 0, 1)}
                      </span>
                    }
                  />
                  <KeyValue label="Missing values" value={formatNumber(dataset.missing_values)} />
                  <KeyValue label="Duplicate rows" value={formatNumber(dataset.duplicate_rows)} />
                  <KeyValue label="Numeric / categorical" value={`${dataset.numerical_columns} / ${dataset.categorical_columns}`} />
                  <KeyValue label="Label column" value={dataset.target_column ?? 'not present'} />
                  <KeyValue label="Status" value={<StatusBadge status={dataset.status} />} />
                  {dataset.attack_categories.length > 0 && (
                    <div className="pt-2">
                      <div className="label-xs mb-1.5">Ground-truth categories in file</div>
                      <div className="flex flex-wrap gap-1.5">
                        {dataset.attack_categories.slice(0, 12).map((category) => (
                          <Badge key={category} variant="secondary">
                            {category}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="pt-3">
                    <Button className="w-full" onClick={() => analyze()} disabled={analyzing}>
                      {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                      {analyzing ? 'Running Random Forest…' : 'Analyze Traffic'}
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {(job || summary) && (
            <Card>
              <CardHeader>
                <CardTitle>3 · Processing</CardTitle>
                <CardDescription>
                  {job?.status === 'completed'
                    ? `Completed in ${job.duration_ms ?? 0} ms`
                    : 'The pipeline reports progress as it runs'}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {job && (
                  <>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">{job.stage}</span>
                      <span className="font-mono text-primary">{job.progress.toFixed(0)}%</span>
                    </div>
                    <Progress value={job.progress} />
                    <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>
                        {formatNumber(job.processed_rows)} / {formatNumber(job.total_rows)} rows
                      </span>
                      <StatusBadge status={job.status} />
                    </div>
                  </>
                )}

                {summary && (
                  <div className="space-y-3 animate-fade-up">
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                      {[
                        { label: 'Total records', value: formatNumber(summary.total_records) },
                        { label: 'Normal', value: formatNumber(summary.normal_records) },
                        { label: 'Suspicious', value: formatNumber(summary.suspicious_records) },
                        { label: 'High risk', value: formatNumber(summary.high_risk_records) },
                        { label: 'Critical', value: formatNumber(summary.critical_records) },
                        { label: 'Alerts', value: formatNumber(summary.alerts_generated) },
                      ].map((tile) => (
                        <div key={tile.label} className="rounded-lg border border-border/70 bg-background/40 p-2.5">
                          <div className="label-xs">{tile.label}</div>
                          <div className="mt-1 text-base font-semibold tabular-nums">{tile.value}</div>
                        </div>
                      ))}
                    </div>

                    {summary.ground_truth && (
                      <Alert variant="info" title="Ground truth detected in the uploaded file">
                        The file shipped a Label column, so the console compared predictions against it:{' '}
                        <span className="font-semibold">
                          {formatPercent(summary.ground_truth.match_rate, 2)} exact match
                        </span>{' '}
                        on {formatNumber(summary.ground_truth.labelled_rows)} labelled flows (binary precision{' '}
                        {formatPercent(summary.ground_truth.binary.precision, 1)}, recall{' '}
                        {formatPercent(summary.ground_truth.binary.recall, 1)}). The label column was never used
                        as a model input.
                      </Alert>
                    )}

                    {summary.warnings?.length ? (
                      <Alert variant="warn" title="Preprocessing notes">
                        <ul className="list-disc space-y-1 pl-4">
                          {summary.warnings.map((warning, index) => (
                            <li key={index}>{warning}</li>
                          ))}
                        </ul>
                      </Alert>
                    ) : null}

                    <div className="flex gap-2">
                      <Button size="sm" asChild className="flex-1">
                        <Link to={`/predictions?job=${job?.id ?? ''}`}>
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Open results
                        </Link>
                      </Button>
                      <Button size="sm" variant="outline" asChild className="flex-1">
                        <Link to="/detections?tab=alerts">View alerts</Link>
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          <Alert variant="info" title="What the model expects">
            The Random Forest was trained on the 70 numeric CICIDS2017 MachineLearningCVE flow features.
            Uploads are matched case-insensitively against that schema; any expected-but-absent feature is
            filled with the training-split median and listed in the response. A file that matches fewer than
            80% of the expected features is rejected with a clear incompatibility message instead of being
            silently mis-scored.
          </Alert>
        </div>
      </div>
    </>
  )
}
