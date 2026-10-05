import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Eye, Filter, Search, SlidersHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input, Select } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Alert, Loading, PageHeader, RiskBadge, VerdictBadge } from '@/components/common'
import { PredictionDetailDialog } from '@/components/PredictionDetail'
import { api, errorMessage } from '@/lib/api'
import { formatNumber, formatPercent } from '@/lib/format'
import type { Prediction, PredictionPage, RiskLevel } from '@/lib/types'

const VERDICTS = [
  { value: 'all', label: 'All flows' },
  { value: 'attack', label: 'Attack only' },
  { value: 'normal', label: 'Normal only' },
  { value: 'high_risk', label: 'High risk' },
  { value: 'critical', label: 'Critical' },
]

export function Predictions() {
  const [params, setParams] = useSearchParams()
  const jobId = params.get('job') ?? undefined

  const [verdict, setVerdict] = useState(params.get('verdict') ?? 'all')
  const [risk, setRisk] = useState('all')
  const [attackType, setAttackType] = useState('all')
  const [minConfidence, setMinConfidence] = useState('')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [sortBy, setSortBy] = useState('risk_score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  const [data, setData] = useState<PredictionPage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  const query = useMemo(() => {
    const qs = new URLSearchParams()
    if (jobId) qs.set('job_id', jobId)
    qs.set('verdict', verdict)
    if (risk !== 'all') qs.set('risk_level', risk)
    if (attackType !== 'all') qs.set('attack_type', attackType)
    if (minConfidence) qs.set('min_confidence', String(Number(minConfidence) / 100))
    if (search) qs.set('search', search)
    qs.set('sort_by', sortBy)
    qs.set('sort_dir', sortDir)
    qs.set('page', String(page))
    qs.set('page_size', String(pageSize))
    return qs.toString()
  }, [jobId, verdict, risk, attackType, minConfidence, search, sortBy, sortDir, page, pageSize])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await api.get<PredictionPage>(`/predictions?${query}`)
      setData(result)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [query])

  useEffect(() => {
    load()
  }, [load])

  const attackTypes = useMemo(() => {
    const items = data?.items ?? []
    const unique = new Set(items.map((item) => item.prediction))
    return ['all', ...Array.from(unique)]
  }, [data])

  const toggleSort = (column: string) => {
    if (sortBy === column) setSortDir(sortDir === 'desc' ? 'asc' : 'desc')
    else {
      setSortBy(column)
      setSortDir('desc')
    }
  }

  const rows = data?.items ?? []

  return (
    <>
      <PageHeader
        title="Prediction Results"
        subtitle={
          <>
            Every analysed flow with its predicted class, model confidence and risk level. Search, filter and
            sort run as SQL queries on the backend - the browser only receives one page at a time.
          </>
        }
        actions={
          <>
            <Select
              value={String(pageSize)}
              onChange={(e) => {
                setPageSize(Number(e.target.value))
                setPage(1)
              }}
              className="w-[110px]"
            >
              {[10, 25, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size} / page
                </option>
              ))}
            </Select>
            <Button variant="outline" size="sm" onClick={load}>
              Refresh
            </Button>
          </>
        }
      />

      {jobId && (
        <div className="mb-3 flex items-center gap-2 text-[11px] text-muted-foreground">
          <Badge variant="secondary">filtered to analysis job</Badge>
          <button className="underline hover:text-foreground" onClick={() => setParams({})}>
            clear job filter
          </button>
        </div>
      )}

      {error && (
        <div className="mb-4">
          <Alert variant="error" title="Could not load predictions">
            {error}
          </Alert>
        </div>
      )}

      <Card className="mb-4">
        <CardContent className="flex flex-wrap items-end gap-3 p-4">
          <div className="min-w-[140px] flex-1">
            <label className="label-xs mb-1 block">
              <Filter className="mr-1 inline h-3 w-3" />
              Verdict
            </label>
            <Select
              value={verdict}
              onChange={(e) => {
                setVerdict(e.target.value)
                setPage(1)
              }}
            >
              {VERDICTS.map((v) => (
                <option key={v.value} value={v.value}>
                  {v.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="min-w-[130px] flex-1">
            <label className="label-xs mb-1 block">Risk level</label>
            <Select
              value={risk}
              onChange={(e) => {
                setRisk(e.target.value)
                setPage(1)
              }}
            >
              {['all', 'low', 'medium', 'high', 'critical'].map((level) => (
                <option key={level} value={level}>
                  {level === 'all' ? 'All levels' : level}
                </option>
              ))}
            </Select>
          </div>
          <div className="min-w-[150px] flex-1">
            <label className="label-xs mb-1 block">Attack type</label>
            <Select
              value={attackType}
              onChange={(e) => {
                setAttackType(e.target.value)
                setPage(1)
              }}
            >
              {attackTypes.map((type) => (
                <option key={type} value={type}>
                  {type === 'all' ? 'All types' : type}
                </option>
              ))}
            </Select>
          </div>
          <div className="w-[130px]">
            <label className="label-xs mb-1 block">Min confidence %</label>
            <Input
              type="number"
              min={0}
              max={100}
              value={minConfidence}
              onChange={(e) => {
                setMinConfidence(e.target.value)
                setPage(1)
              }}
              placeholder="0"
            />
          </div>
          <form
            className="min-w-[200px] flex-[1.4]"
            onSubmit={(e) => {
              e.preventDefault()
              setSearch(searchInput.trim())
              setPage(1)
            }}
          >
            <label className="label-xs mb-1 block">Search (port / record / class)</label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="pl-8"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="e.g. 22 or Port Scanning"
              />
            </div>
          </form>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setVerdict('all')
              setRisk('all')
              setAttackType('all')
              setMinConfidence('')
              setSearch('')
              setSearchInput('')
              setPage(1)
            }}
          >
            <SlidersHorizontal className="h-3.5 w-3.5" />
            Reset
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {loading && !data ? (
            <Loading label="Loading predictions…" />
          ) : rows.length === 0 ? (
            <p className="p-8 text-center text-xs text-muted-foreground">
              No flows match the current filters. Try “All flows”, or analyse a dataset on the Traffic
              Analyzer page first.
            </p>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort('record_index')}
                    >
                      Record
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('prediction')}>
                      Prediction
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('confidence')}>
                      Confidence
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('risk_level')}>
                      Risk
                    </TableHead>
                    <TableHead>Source Port</TableHead>
                    <TableHead>Dest Port</TableHead>
                    <TableHead>Flow Duration</TableHead>
                    <TableHead>Packet Rate</TableHead>
                    <TableHead>Pkt Length</TableHead>
                    <TableHead>Ground truth</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row: Prediction) => (
                    <TableRow key={row.id} className="cursor-pointer" onClick={() => setSelected(row.id)}>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        #{row.record_index}
                      </TableCell>
                      <TableCell>
                        <VerdictBadge isAttack={row.is_attack} label={row.prediction} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{formatPercent(row.confidence, 2)}</TableCell>
                      <TableCell>
                        <RiskBadge level={row.risk_level as RiskLevel} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.source_port ?? '—'}</TableCell>
                      <TableCell className="font-mono text-xs">{row.destination_port ?? '—'}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.flow_duration !== null && row.flow_duration !== undefined
                          ? `${formatNumber(row.flow_duration, 0)} µs`
                          : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.packet_rate !== null && row.packet_rate !== undefined
                          ? formatNumber(row.packet_rate, 1)
                          : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.packet_length_mean !== null && row.packet_length_mean !== undefined
                          ? formatNumber(row.packet_length_mean, 1)
                          : '—'}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{row.ground_truth ?? '—'}</TableCell>
                      <TableCell>
                        <Button variant="ghost" size="sm" onClick={() => setSelected(row.id)}>
                          <Eye className="h-3.5 w-3.5" />
                          Inspect
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border/60 p-3 text-xs text-muted-foreground">
                <span>
                  {formatNumber(data?.total ?? 0)} matching flow(s) · page {data?.page} of {data?.pages}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={(data?.page ?? 1) <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={(data?.page ?? 1) >= (data?.pages ?? 1)}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                    <ChevronRight className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <PredictionDetailDialog
        predictionId={selected}
        onClose={() => setSelected(null)}
      />
    </>
  )
}
