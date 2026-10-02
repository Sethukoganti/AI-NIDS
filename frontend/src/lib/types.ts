export type Role = 'admin' | 'analyst'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed'
export type AlertStatus = 'new' | 'reviewed' | 'resolved'

export interface User {
  id: string
  name: string
  email: string
  role: Role
  is_active: boolean
  created_at?: string | null
  last_login_at?: string | null
}

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: User
}

export interface AuthConfig {
  app_name: string
  demo_accounts_enabled: boolean
  demo_accounts: { role: Role; email: string }[]
  password_min_length: number
}

export interface Metrics {
  total_traffic: number
  normal_traffic: number
  suspicious_traffic: number
  detection_rate: number
  active_alerts: number
  alerts_total: number
  average_confidence: number
  window_hours: number | null
}

export interface ModelBlock {
  algorithm?: string
  n_estimators?: number
  dataset?: string
  test_accuracy?: number | null
  macro_f1?: number | null
  n_test?: number | null
  n_features?: number
  classes?: string[]
  loaded?: boolean
  trained_at?: string
  accuracy_label?: string
}

export interface TimelinePoint {
  bucket: string
  label: string
  total: number
  normal: number
  suspicious: number
  alerts: number
}

export interface DashboardStats {
  metrics: Metrics
  verdict_share: { normal_pct: number; suspicious_pct: number }
  risk_distribution: Record<RiskLevel, number>
  attack_distribution: Record<string, number>
  timeline: TimelinePoint[]
  recent_alerts: Alert[]
  model: ModelBlock
  datasets: number
  jobs: number
  last_job: AnalysisJob | null
  ai: { provider: string; enabled: boolean; mode: string }
  reference_dataset: {
    name: string
    full_rows?: number | null
    full_columns?: number | null
    training_rows?: number | null
  }
}

export interface Alert {
  id: string
  prediction_id?: string | null
  job_id?: string | null
  dataset_id?: string | null
  alert_type: string
  attack_type: string
  severity: RiskLevel
  status: AlertStatus
  message: string
  confidence: number
  risk_score: number
  source_ip?: string | null
  destination_port?: number | null
  record_index?: number | null
  created_at?: string | null
  resolved_at?: string | null
  notes?: string | null
}

export interface DatasetSummary {
  id: string
  filename: string
  rows: number
  columns: number
  size_bytes: number
  status: string
  source: string
  upload_time?: string | null
  target_column?: string | null
  attack_categories: string[]
  missing_values: number
  duplicate_rows: number
  numerical_columns: number
  categorical_columns: number
  feature_coverage?: number | null
  schema_matched?: boolean | null
  class_distribution: Record<string, number>
  message?: string
  analysis_ready?: boolean
}

export interface DatasetDetail extends DatasetSummary {
  columns_meta: ColumnMeta[]
  sample_rows: Record<string, unknown>[]
}

export interface ColumnMeta {
  name: string
  dtype: string
  role: 'feature' | 'target' | 'auxiliary'
  missing: number
  unique: number
  type: 'numeric' | 'categorical'
  min?: number | null
  max?: number | null
  mean?: number | null
  std?: number | null
  top_values?: Record<string, number>
}

export interface Prediction {
  id: string
  dataset_id?: string | null
  job_id?: string | null
  record_index: number
  prediction: string
  is_attack: boolean
  confidence: number
  risk_level: RiskLevel
  risk_score: number
  source_port?: number | null
  destination_port?: number | null
  source_ip?: string | null
  destination_ip?: string | null
  protocol?: string | null
  flow_duration?: number | null
  packet_rate?: number | null
  packet_length_mean?: number | null
  total_fwd_packets?: number | null
  total_bwd_packets?: number | null
  flow_bytes_per_s?: number | null
  timestamp?: string | null
  ground_truth?: string | null
  source: string
  top_factors: Factor[]
  created_at?: string | null
  features?: Record<string, number | null>
  alerts?: Alert[]
  explanation?: ShapExplanation | null
  explanation_method?: 'tree_shap' | 'global_feature_importance'
  explanation_label?: string
  fallback_explanation?: FeatureImportanceResponse
}

export interface Factor {
  feature: string
  value?: number
  importance?: number
  deviation_from_median?: number
  score?: number
}

export interface ShapContribution {
  feature: string
  value: number
  shap_value: number
  direction: 'attack' | 'normal'
  impact_pct: number
}

export interface ShapExplanation {
  method: string
  method_label: string
  explained_class: string
  base_value: number
  predicted_value: number
  contributions: ShapContribution[]
}

export interface FeatureImportance {
  feature: string
  importance: number
}

export interface FeatureImportanceResponse {
  method: string
  source: string
  total_features: number
  importances: FeatureImportance[]
}

export interface AnalysisJob {
  id: string
  dataset_id: string
  dataset_filename?: string | null
  status: JobStatus
  progress: number
  stage: string
  total_rows: number
  processed_rows: number
  error?: string | null
  warnings: string[]
  summary: AnalysisSummary | Record<string, never>
  model_version?: string | null
  duration_ms?: number | null
  created_at?: string | null
  started_at?: string | null
  finished_at?: string | null
  alert_count?: number
}

export interface AnalysisSummary {
  total_records: number
  normal_records: number
  suspicious_records: number
  detection_rate: number
  average_confidence: number
  attack_distribution: Record<string, number>
  risk_distribution: Record<RiskLevel, number>
  high_risk_records: number
  critical_records: number
  alerts_generated: number
  stored_predictions: number
  average_confidence_by_class: Record<string, number>
  ground_truth?: {
    labelled_rows: number
    match_rate: number
    binary: {
      true_positive: number
      true_negative: number
      false_positive: number
      false_negative: number
      precision: number
      recall: number
      f1: number
    }
    note: string
  } | null
  preprocessing: PreprocessingDiagnostics
  model: { algorithm?: string; n_estimators?: number; version?: string; test_accuracy?: number }
  warnings?: string[]
  job_id?: string
  duration_ms?: number
}

export interface PreprocessingDiagnostics {
  rows_in_file: number
  rows_usable: number
  rows_dropped_missing_values: number
  infinite_values_replaced: number
  matched_features: number
  expected_features: number
  feature_coverage: number
  missing_features: string[]
  imputed_features: string[]
  onehot_features_created: string[]
  expected_but_absent: string[]
  extra_columns_ignored: string[]
  deduplicated: boolean
  feature_order: string[]
}

export interface PredictionPage {
  items: Prediction[]
  total: number
  page: number
  page_size: number
  pages: number
  sort_by: string
  sort_dir: string
}

export interface AlertSummary {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_attack_type: Record<string, number>
  new: number
  open_high_or_critical: number
}

export interface ExplanationResponse {
  provider: string
  provider_label: string
  grounded_on: string
  explanation: string
  evidence?: Record<string, unknown>
  prediction_id?: string
  explanation_method?: string
  explanation_label?: string
}

export interface AssistantResponse {
  provider: string
  answer: string
  facts: Record<string, unknown>
  sources: string[]
  evidence?: Record<string, unknown>
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy'
  version: string
  environment: string
  uptime_seconds: number
  checks: Record<string, { ok: boolean; detail?: string | null; [key: string]: unknown }>
  model: ModelBlock & { load_seconds?: number }
  ai: { provider: string; enabled: boolean }
}

export interface ModelInfo extends ModelBlock {
  name?: string
  version?: string
  algorithm_detail?: string
  random_state?: number
  n_jobs?: number
  max_depth?: number | null
  min_samples_leaf?: number
  n_classes?: number
  train_split?: number
  test_split?: number
  dataset_detail?: string
  risk_rules?: Record<string, unknown>
  demo_samples?: Record<string, unknown>
  dataset_files?: Record<string, unknown>
  full_dataset?: { rows?: number; columns?: number; class_counts?: Record<string, number> }
  training_table?: { rows?: number; features?: number; class_counts?: Record<string, number>; sampling?: Record<string, unknown> }
  attack_classes?: string[]
  normal_class?: string
  model_size_mb?: number
  serialization?: string
  limitations?: string[]
  environment?: Record<string, string>
  evaluation?: {
    accuracy?: number
    macro_f1?: number
    weighted_f1?: number
    n_test?: number
    n_train?: number
    evaluated_at?: string
    per_class?: Record<string, { precision: number; recall: number; f1: number; support: number }>
    confusion_matrix?: { labels: string[]; matrix: number[][] }
    disclaimer?: string
  }
  loaded?: boolean
  load_error?: string | null
  loaded_at?: string | null
  load_seconds?: number
  n_features?: number
}

export interface ArchitectureStage {
  id: string
  name: string
  detail: string
  metrics: Record<string, number | string | null | undefined>
}

export interface LiveFlowEvent {
  index: number
  prediction: string
  confidence: number
  is_attack: boolean
  risk_level: RiskLevel
  risk_score: number
  destination_port?: number | null
  packet_rate?: number | null
  flow_duration?: number | null
  ground_truth?: string | null
  cursor: { total: number; suspicious: number; progress: number }
}

export interface InvestigationNote {
  text: string
  author?: string
  author_name?: string
  timestamp?: string
}

export interface Investigation {
  id: string
  reference: string
  title: string
  status: 'open' | 'in_progress' | 'pending' | 'escalated' | 'closed'
  priority: RiskLevel
  assigned_to?: string | null
  created_by?: string | null
  alert_id?: string | null
  prediction_id?: string | null
  job_id?: string | null
  dataset_id?: string | null
  summary?: string | null
  findings: string[]
  notes: InvestigationNote[]
  evidence?: Record<string, unknown>
  risk_level: RiskLevel
  attack_type?: string | null
  created_at?: string | null
  updated_at?: string | null
  closed_at?: string | null
  resolution?: string | null
}

export interface InvestigationPage {
  items: Investigation[]
  total: number
  page: number
  page_size: number
  pages: number
  statuses: string[]
  priorities: string[]
}

export interface NetworkStatusOverview {
  status: string
  status_key: string
  label: string
  description: string
  tone: 'success' | 'info' | 'warning' | 'danger'
  evaluable: boolean
  source: 'manual' | 'automatic' | 'system'
  reason?: string | null
  changed_by?: string | null
  started_at?: string | null
  indicators: Record<string, number>
  triggers: { metric: string; operator: string; threshold: number; actual: number; trigger_type: string }[]
  recommendation?: { status: string; reason: string; confidence: number; triggers: any[] }
  profile: Record<string, unknown>
  history?: NetworkStatusHistoryEntry[]
}

export interface NetworkStatusHistoryEntry {
  id: string
  status: string
  previous_status?: string | null
  source: string
  reason?: string | null
  changed_by?: string | null
  started_at: string
  ended_at?: string | null
  duration_seconds?: number | null
  indicators?: Record<string, number>
  triggers?: any[]
  configuration_snapshot?: Record<string, unknown>
}

export interface AuditLogEntry {
  id: string
  timestamp: string
  user_id?: string | null
  user_name?: string | null
  user_role?: string | null
  action: string
  category: string
  resource: string
  previous_value?: Record<string, unknown> | null
  new_value?: Record<string, unknown> | null
  detail?: Record<string, unknown> | null
  ip_address?: string | null
  result: string
}

export interface NotificationItem {
  id: string
  timestamp: string
  title: string
  message: string
  category: string
  severity: string
  is_read: boolean
  read_at?: string | null
  link?: string | null
  data?: Record<string, unknown> | null
}

export interface ConfigFieldMeta {
  key: string
  title: string
  type: string
  default: unknown
  current: unknown
  description: string
  recommended?: string | null
  min?: number | null
  max?: number | null
  options?: string[]
  requires_confirmation?: boolean
  section: string
}

export interface ConfigDescribeResponse {
  scope?: string
  sections: { name: string; description: string; fields: ConfigFieldMeta[] }[]
  section_order?: string[]
  section_aliases?: Record<string, string>
  scope_permissions?: Record<string, string>
  effective_configuration?: Record<string, unknown>
  values?: Record<string, unknown>
  fields?: Record<string, ConfigFieldMeta>
}
