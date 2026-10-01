import { useCallback, useEffect, useState } from 'react'
import {
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  Eye,
  FileSpreadsheet,
  Layers,
  RefreshCw,
  Trash2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select } from '@/components/ui/input'
import { Alert as InlineAlert, KeyValue, Loading, PageHeader, StatusBadge } from '@/components/common'
import { api, errorMessage, getToken } from '@/lib/api'
import { formatBytes, formatNumber, formatPercent, relativeTime } from '@/lib/format'
import type { DatasetDetail, DatasetSummary } from '@/lib/types'
import { useAuth } from '@/context/AuthContext'

export function Datasets() {
  const { isAdmin } = useAuth()
  const [items, setItems] = useState<DatasetSummary[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [detail, setDetail] = useState<DatasetDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [rowsPage, setRowsPage] = useState(1)
  const [rowsData, setRowsData] = useState<{
    columns: string[]
    items: Record<string, unknown>[]
    source?: string
    note?: string | null
    total: number
    page: number
    pages: number
  } | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.get<{ items: DatasetSummary[]; total: number; pages: number }>(
        `/datasets?page=${page}&page_size=10`,
      )
      setItems(data.items)
      setTotal(data.total)
      setPages(data.pages)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    load()
  }, [load])

  const openDetail = async (dataset: DatasetSummary, rowsPageNumber = 1) => {
    setDetailLoading(true)
    setRowsPage(rowsPageNumber)
    try {
      const [info, rows] = await Promise.all([
        api.get<DatasetDetail>(`/datasets/${dataset.id}`),
        api.get<{
          columns: string[]
          items: Record<string, unknown>[]
          total: number
          page: number
          pages: number
          source?: string
          note?: string | null
        }>(
          `/datasets/${dataset.id}/rows?page=${rowsPageNumber}&page_size=25`,
        ),
      ])
      setDetail(info)
      setRowsData(rows)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setDetailLoading(false)
    }
  }

  const changeRowsPage = async (next: number) => {
    if (!detail) return
    setRowsPage(next)
    const rows = await api.get<{
      columns: string[]
      items: Record<string, unknown>[]
      total: number
      page: number
      pages: number
    }>(`/datasets/${detail.id}/rows?page=${next}&page_size=25`)
    setRowsData(rows)
  }

  const download = async (dataset: DatasetSummary) => {
    try {
      const response = await fetch(`/api/datasets/${dataset.id}/download`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      })
      if (!response.ok) throw new Error(`Download failed (${response.status})`)
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = dataset.filename
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const remove = async (dataset: DatasetSummary) => {
    if (!window.confirm(`Delete ${dataset.filename}? Stored predictions and alerts remain.`)) return
    try {
      await api.del(`/datasets/${dataset.id}`)
      load()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <>
      <PageHeader
        title="Dataset Explorer"
        subtitle={
          <>
            Every dataset registered with AI-NIDS, including the built-in CICIDS2017 reference sample. Row
            previews are paginated server-side and capped - the full dataset is never shipped to the browser.
          </>
        }
        actions={
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
        }
      />

      {error && (
        <div className="mb-4">
          <InlineAlert variant="error" title="Dataset error">
            {error}
          </InlineAlert>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Registered datasets</CardTitle>
            <CardDescription>
              {formatNumber(total)} dataset(s) · uploaded files are stored server-side under the upload
              directory
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading && items.length === 0 ? (
              <Loading label="Loading datasets…" />
            ) : items.length === 0 ? (
              <p className="p-8 text-center text-xs text-muted-foreground">No datasets registered yet.</p>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>File</TableHead>
                      <TableHead>Rows</TableHead>
                      <TableHead>Columns</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Schema match</TableHead>
                      <TableHead>Uploaded</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((dataset) => (
                      <TableRow key={dataset.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <FileSpreadsheet className="h-3.5 w-3.5 shrink-0 text-primary" />
                            <div className="min-w-0">
                              <div className="truncate text-xs font-medium">{dataset.filename}</div>
                              <div className="text-[10px] text-muted-foreground">
                                {formatBytes(dataset.size_bytes)}
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{formatNumber(dataset.rows)}</TableCell>
                        <TableCell className="font-mono text-xs">{dataset.columns}</TableCell>
                        <TableCell>
                          <StatusBadge status={dataset.source === 'built_in_sample' ? 'reference' : 'ready'} />
                        </TableCell>
                        <TableCell>
                          <span
                            className={
                              (dataset.feature_coverage ?? 0) >= 0.8
                                ? 'font-mono text-xs text-emerald-400'
                                : 'font-mono text-xs text-yellow-400'
                            }
                          >
                            {formatPercent(dataset.feature_coverage ?? 0, 0)}
                          </span>
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                          {relativeTime(dataset.upload_time)}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <Button variant="ghost" size="sm" onClick={() => openDetail(dataset)}>
                              <Eye className="h-3.5 w-3.5" />
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => download(dataset)}>
                              <Download className="h-3.5 w-3.5" />
                            </Button>
                            {isAdmin && dataset.source !== 'built_in_sample' && (
                              <Button variant="ghost" size="sm" onClick={() => remove(dataset)}>
                                <Trash2 className="h-3.5 w-3.5 text-red-400" />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <div className="flex items-center justify-between border-t border-border/60 p-3 text-xs text-muted-foreground">
                  <span>
                    page {page} of {pages}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                    >
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page >= pages}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-4 w-4 text-primary" />
                {detail ? detail.filename : 'Dataset detail'}
              </CardTitle>
              <CardDescription>
                {detail
                  ? 'Profiled server-side: dtypes, missing values, label distribution.'
                  : 'Select a dataset to inspect its profile and preview rows.'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {detailLoading ? (
                <Loading label="Loading dataset profile…" />
              ) : !detail ? (
                <p className="py-8 text-center text-xs text-muted-foreground">
                  Nothing selected yet. Click the eye icon on a dataset.
                </p>
              ) : (
                <div className="space-y-3">
                  <div className="space-y-0.5">
                    <KeyValue label="Rows" value={formatNumber(detail.rows)} />
                    <KeyValue label="Columns" value={detail.columns} />
                    <KeyValue label="Size" value={formatBytes(detail.size_bytes)} />
                    <KeyValue label="Missing values" value={formatNumber(detail.missing_values)} />
                    <KeyValue label="Duplicate rows" value={formatNumber(detail.duplicate_rows)} />
                    <KeyValue label="Numeric features" value={detail.numerical_columns} />
                    <KeyValue label="Categorical" value={detail.categorical_columns} />
                    <KeyValue label="Label column" value={detail.target_column ?? 'none'} />
                    <KeyValue
                      label="Schema coverage"
                      value={formatPercent(detail.feature_coverage ?? 0, 1)}
                      mono
                    />
                  </div>

                  {Object.keys(detail.class_distribution ?? {}).length > 0 && (
                    <div>
                      <div className="label-xs mb-1.5">Label distribution in file</div>
                      <div className="max-h-40 space-y-1 overflow-y-auto pr-1">
                        {Object.entries(detail.class_distribution)
                          .sort(([, a], [, b]) => b - a)
                          .map(([label, count]) => (
                            <div key={label} className="flex items-center justify-between gap-2 text-[11px]">
                              <span className="truncate text-muted-foreground">{label}</span>
                              <span className="font-mono text-foreground/85">{formatNumber(count)}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {detail && rowsData && (
            <Card>
              <CardHeader className="flex-row items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-primary" />
                    Row preview
                  </CardTitle>
                  <CardDescription>
                    Page {rowsData.page} of {rowsData.pages} · showing up to 25 rows per page
                    {rowsData.source === 'reference_sample' ? ' · held-out sample rows' : ''}
                  </CardDescription>
                </div>
                <Select
                  value="25"
                  onChange={() => undefined}
                  className="w-[90px]"
                  aria-label="Rows per page"
                >
                  <option value="25">25 / page</option>
                </Select>
              </CardHeader>
              <CardContent className="p-0">
                {rowsData.note && (
                  <p className="m-3 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-xs text-muted-foreground">
                    {rowsData.note}
                  </p>
                )}
                <div className="overflow-x-auto">
                  <table className="w-full text-[11px]">
                    <thead className="bg-muted/30">
                      <tr>
                        {rowsData.columns.map((column) => (
                          <th
                            key={column}
                            className="whitespace-nowrap px-2.5 py-2 text-left text-[10px] uppercase tracking-wider text-muted-foreground"
                          >
                            {column}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rowsData.items.map((row, index) => (
                        <tr key={index} className="border-t border-border/50">
                          {rowsData.columns.map((column) => (
                            <td key={column} className="whitespace-nowrap px-2.5 py-1.5 font-mono">
                              {typeof row[column] === 'number'
                                ? (row[column] as number).toLocaleString(undefined, {
                                    maximumFractionDigits: 4,
                                  })
                                : String(row[column] ?? '')}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-center justify-between border-t border-border/60 p-3 text-[11px] text-muted-foreground">
                  <span>{formatNumber(rowsData.total)} row(s) available</span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={rowsPage <= 1}
                      onClick={() => changeRowsPage(rowsPage - 1)}
                    >
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={rowsPage >= (rowsData.pages || 1)}
                      onClick={() => changeRowsPage(rowsPage + 1)}
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          <InlineAlert variant="info" title="Why previews are capped">
            Preview endpoints return at most 5,000 rows per dataset and page them server-side. Aggregate
            statistics used by the dashboard are computed in the database, so no full scan needs to reach the
            browser.
          </InlineAlert>
        </div>
      </div>
    </>
  )
}
