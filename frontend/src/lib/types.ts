// Mirrors the backend Pydantic models (see backend/app/models). Timestamps are ISO-8601 UTC strings.

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "investigating" | "resolved" | "benign" | "false_positive";
export type IncidentStatus = "new" | "investigating" | "contained" | "closed";
export type Classification = "undetermined" | "true_positive" | "benign_true_positive" | "false_positive";
export type LogFormat = "auto" | "windows_json" | "linux_ssh" | "normalized_json";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface MitreRef {
  technique_id: string;
  technique: string;
  tactic: string;
}

export interface NormalizedEvent {
  id: string;
  timestamp: string;
  ingested_at: string;
  event_id: string | null;
  event_source: string;
  event_type: string;
  event_action: string;
  outcome: "success" | "failure" | "unknown";
  log_level: "info" | "warning" | "error" | "critical";
  hostname: string | null;
  username: string | null;
  domain: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  logon_type: number | null;
  process_name: string | null;
  command_line: string | null;
  parent_process: string | null;
  target_username: string | null;
  group_name: string | null;
  message: string;
  raw: string;
  dataset: string;
  tags: string[];
  fields: Record<string, unknown>;
}

export interface Evidence {
  label: string;
  value: string;
}

export interface Alert {
  id: string;
  fingerprint: string;
  rule_id: string;
  rule_name: string;
  description: string;
  severity: Severity;
  timestamp: string;
  first_seen: string;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  event_ids: string[];
  event_count: number;
  reason: string;
  evidence: Evidence[];
  mitre: MitreRef[];
  fp_hints: string[];
  status: AlertStatus;
  incident_id: string | null;
  analyst_note: string | null;
  created_at: string;
  updated_at: string;
}

export interface Note {
  id: string;
  author: string;
  body: string;
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  classification: Classification;
  assignee: string | null;
  alert_ids: string[];
  entities: { users?: string[]; hosts?: string[]; ips?: string[] };
  mitre: MitreRef[];
  first_seen: string;
  last_seen: string;
  notes: Note[];
  resolution: string | null;
  personal_data: boolean | null;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  closed_at: string | null;
}

export interface Activity {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  message: string;
  target_type: string | null;
  target_id: string | null;
}

export interface RuleParam {
  name: string;
  label: string;
  value: number;
  min: number;
  max: number;
  unit: string;
}

export interface RuleInfo {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  rule_type: string;
  data_sources: string[];
  mitre: MitreRef[];
  enabled: boolean;
  params: RuleParam[];
  logic: string;
  false_positives: string[];
  response: string[];
  custom: boolean;
  source: string | null;
  alert_count: number;
  last_triggered: string | null;
}

export interface SigmaPreview {
  rule: Pick<RuleInfo, "id" | "name" | "severity" | "rule_type" | "data_sources" | "mitre" | "logic" | "params">;
  matched_events: number;
  alert_count: number;
  sample: { timestamp: string; severity: Severity; hostname: string | null; username: string | null; source_ip: string | null; reason: string }[];
}

export type Verdict = "malicious" | "benign" | "false_positive";

export interface RuleChange {
  enabled?: boolean;
  params?: Record<string, number>;
}

export type RegressionStatus = "detected" | "missed" | "regressed" | "fixed" | "noise_reduced" | "noise_added" | "unchanged";

export interface RegressionReport {
  generated_at: string;
  seeds: number[];
  changes: Record<string, RuleChange>;
  passed: boolean;
  summary: {
    attack_scenarios: number;
    detected_before: number;
    detected_after: number;
    regressions: number;
    fixes: number;
    noise_before: number;
    noise_after: number;
  };
  scenarios: {
    scenario_id: string;
    name: string;
    verdict: Verdict;
    origin: "builtin" | "custom";
    expected_rules: string[];
    missed_before: string[];
    missed_after: string[];
    alerts_before: number;
    alerts_after: number;
    status: RegressionStatus;
  }[];
  baseline: { rule_id: string; before: number; after: number }[];
}

export interface BacktestResult {
  rule_id: string;
  params: Record<string, number>;
  alert_count: number;
  current_alert_count: number;
  sample: { timestamp: string; severity: Severity; hostname: string | null; username: string | null; source_ip: string | null; reason: string; existing: boolean }[];
}

export interface ScenarioSummary {
  id: string;
  name: string;
  summary: string;
  narrative: string;
  category: string;
  level: string;
  expected_severity: Severity;
  expected_rules: string[];
  benign: boolean;
  verdict: Verdict;
  tags: string[];
  origin: "builtin" | "custom";
  mitre: string[];
  hosts: string[];
  learning_objectives: string[];
  investigation_questions: string[];
  event_estimate: number;
  challenge_points: number;
  run_count: number;
  last_run_id: string | null;
}

export interface SimulationRun {
  id: string;
  scenario_id: string;
  scenario_name: string;
  seed: number;
  benign: boolean;
  simulated_start: string;
  simulated_end: string;
  executed_at: string;
  event_count: number;
  event_ids: string[];
  alert_ids: string[];
  incident_ids: string[];
  expected_rules: string[];
  triggered_rules: string[];
  missed_rules: string[];
  unexpected_rules: string[];
  variables: Record<string, unknown>;
}

export interface SimulationDetail {
  run: SimulationRun;
  alerts: Alert[];
  incidents: Incident[];
  events: NormalizedEvent[];
  highest_severity: Severity | null;
  open_alerts: number;
}

export interface ParseIssue {
  line: number | null;
  message: string;
  excerpt: string;
}

export interface ImportReport {
  import_id: string | null;
  filename: string;
  format: LogFormat;
  dry_run: boolean;
  size_bytes: number;
  total_records: number;
  parsed: number;
  added: number;
  duplicates: number;
  skipped: number;
  errors: ParseIssue[];
  error_count: number;
  first_timestamp: string | null;
  last_timestamp: string | null;
  preview: NormalizedEvent[];
  alerts_created: number;
  incidents_touched: string[];
}

export interface ImportRecord {
  id: string;
  filename: string;
  format: LogFormat;
  size_bytes: number;
  total_records: number;
  parsed: number;
  added: number;
  duplicates: number;
  skipped: number;
  error_count: number;
  alerts_created: number;
  created_at: string;
}

export interface SystemStatus {
  version: string;
  mode: string;
  mode_label: string;
  organization: string;
  clock: string;
  timezone: string;
  business_hours: [number, number];
  counts: Record<string, number>;
  storage: { backend: string; recovered_collections: string[] };
  limits: { max_upload_mb: number; max_import_lines: number };
}

export interface EventFacets {
  hostnames: string[];
  usernames: string[];
  source_ips: string[];
  event_sources: string[];
  event_types: string[];
  event_actions: string[];
  datasets: string[];
}

export interface Dashboard {
  clock: string;
  range: string;
  start: string;
  end: string;
  bucket_seconds: number;
  kpis: {
    events_total: number;
    events_in_range: number;
    events_last_24h: number;
    alerts_in_range: number;
    alerts_open: number;
    alerts_unassigned: number;
    critical_open: number;
    incidents_new: number;
    incidents_investigating: number;
    incidents_closed: number;
  };
  timeline: { bucket: string; events: number; failures: number; alerts: number }[];
  severity: { severity: Severity; count: number }[];
  top_rules: { rule_id: string; rule_name: string; count: number }[];
  top_hosts: { hostname: string; events: number; alerts: number; role: string | null }[];
  top_source_ips: { ip: string; events: number; failures: number; internal: boolean; reputation: string }[];
  event_sources: { source: string; count: number }[];
  recent_alerts: Alert[];
  recent_activity: Activity[];
}

export interface Asset {
  hostname: string;
  ip: string;
  os: string;
  role: string;
  criticality: string;
  owner: string | null;
  public_ip: string | null;
  tags: string[];
}

export interface Identity {
  username: string;
  display_name: string;
  department: string;
  title: string;
  type: string;
  privileged: boolean;
  workstation: string | null;
}

export interface EntityProfile {
  kind: "user" | "host" | "ip";
  value: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  auth_success: number;
  auth_failure: number;
  actions: { name: string; count: number }[];
  alerts: Alert[];
  incidents: Incident[];
  recent_events: NormalizedEvent[];
  identity?: Identity | null;
  asset?: Asset | null;
  network?: {
    internal: boolean;
    asset: Asset | null;
    geo: { country: string; city: string; asn: string; organization: string; reputation: string } | null;
    note: string;
  };
  related: Record<string, { value: string; count: number }[]>;
}

export interface TimelineItem {
  timestamp: string;
  kind: "event" | "alert";
  title: string;
  detail?: string;
  severity?: Severity;
  event_id?: string | null;
  host: string | null;
  user: string | null;
  ip: string | null;
  ref: string;
}

export interface IncidentReport {
  generated_at: string;
  analyst: string;
  environment: string;
  incident: Incident;
  classification_label: string;
  executive_summary: string;
  scope: {
    hosts: (Partial<Asset> & { hostname: string })[];
    users: (Partial<Identity> & { username: string })[];
    ips: { ip: string; internal: boolean; reputation: string | null; organization: string | null }[];
  };
  metrics: { event_count: number; alert_count: number; time_to_detect: string | null; time_to_acknowledge: string | null; time_to_close: string | null };
  detections: Alert[];
  timeline: TimelineItem[];
  iocs: { type: string; value: string; context: string }[];
  evidence: { event_ref: string; timestamp: string; source: string; event_id: string | null; raw: string }[];
  recommendations: string[];
  lgpd: {
    personal_data: boolean | null;
    suggested: boolean;
    aware_at: string;
    anpd_deadline: string;
    subjects_deadline: string;
    complement_deadline: string;
    basis: string;
    notes: string[];
  };
  notes: Note[];
}

export interface MitreMatrix {
  source: string;
  tactics: {
    id: string;
    name: string;
    techniques: { id: string; name: string; url: string; rules: string[]; alerts: number; open_alerts: number }[];
  }[];
  summary: { techniques: number; covered: number; detected: number; coverage_pct: number };
}

export interface Metrics {
  overall: {
    alerts: number;
    true_positive: number;
    benign: number;
    false_positive: number;
    open: number;
    precision: number | null;
    false_positive_rate: number | null;
    mean_time_to_detect_seconds: number | null;
    incidents: number;
    incidents_closed: number;
    mean_time_to_acknowledge_seconds: number | null;
    mean_time_to_resolve_seconds: number | null;
  };
  rules: {
    rule_id: string;
    rule_name: string;
    severity: Severity;
    enabled: boolean;
    alerts: number;
    true_positive: number;
    benign: number;
    false_positive: number;
    open: number;
    precision: number | null;
    mean_time_to_detect_seconds: number | null;
  }[];
  alerts_per_day: ({ date: string } & Record<Severity, number>)[];
  classification: { classification: Classification; count: number }[];
  simulation: {
    runs: number;
    fully_detected_runs: number;
    scenarios_executed: number;
    scenarios_total: number;
    scenarios_fully_detected: number;
    challenges_completed: number;
    challenge_average_pct: number | null;
    per_scenario: { scenario_id: string; name: string; runs: number; detected_runs: number; last_missed: string[]; expected_rules: string[] }[];
  };
  mitre: { techniques_covered: number; techniques_in_catalog: number; techniques_detected: number };
  shifts: ({ id: string; started_at: string; alerts: number } & ShiftScore)[];
  last_regression: ({ generated_at: string; passed: boolean; changes: string[] } & RegressionReport["summary"]) | null;
}

export interface ShiftScore {
  total: number;
  accuracy: number;
  speed: number;
  documentation: number;
  decided: number;
  correct: number;
  missed_attacks: number;
  wasted_escalations: number;
}

export interface ShiftQueueItem {
  alert_id: string;
  verdict: Verdict | null;
  note: string | null;
  seconds_to_decide: number | null;
  sla_seconds: number | null;
  alert: Alert;
  // Revealed when the shift has finished.
  truth?: Verdict;
  scenario_id?: string;
  scenario_name?: string;
  run_id?: string;
  accuracy_points?: number;
  speed_points?: number;
  note_points?: number;
  feedback?: string;
}

export interface ShiftView {
  id: string;
  status: "active" | "finished";
  started_at: string;
  ends_at: string;
  finished_at: string | null;
  duration_minutes: number;
  now: string;
  score: ShiftScore | null;
  max_points_per_alert: { accuracy: number; speed: number; note: number };
  queue: ShiftQueueItem[];
}

export interface ShiftSummary {
  id: string;
  status: "active" | "finished";
  started_at: string;
  ends_at: string;
  duration_minutes: number;
  alerts: number;
  score: ShiftScore | null;
}

export interface ScenarioPreview {
  scenario: ScenarioSummary & { expected_rules: string[]; expected_severity: Severity };
  event_count: number;
  duration_seconds: number;
  pseudonyms: { kind: "account" | "host" | "ip"; original: string; pseudonym: string }[];
  sample: Record<string, unknown>[];
}

export interface ChallengeQuestionView {
  id: string;
  question: string;
  kind: "text" | "choice";
  options: string[];
  points: number;
  hint_used: boolean;
  hint: string | null;
  answer?: string;
  correct?: boolean;
  expected?: string;
  explanation?: string;
  earned?: number;
}

export interface ChallengeView {
  run_id: string;
  scenario_id: string;
  submitted: boolean;
  submitted_at: string | null;
  score: number;
  max_score: number;
  questions: ChallengeQuestionView[];
}
