// Type definitions for SafeCadence NetRisk API responses.

export interface Asset {
  id: string;
  hostname: string;
  vendor?: string;
  model?: string;
  ip_address?: string;
  site?: string;
  criticality?: "low" | "medium" | "high" | "critical";
  risk_score?: number;
  last_seen?: string;
  eol?: boolean;
  tags?: string[];
}

export interface Finding {
  id: string;
  asset_id: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description?: string;
  rule_id?: string;
  cve_ids?: string[];
  kev?: boolean;
  epss?: number;
  detected_at?: string;
  remediation?: string;
}

export interface Report {
  id: string;
  name: string;
  preset?: string;
  format?: "html" | "pdf" | "docx" | "pptx" | "json" | "xlsx";
  created_at?: string;
  template_id?: string;
}

export interface Template {
  id: string;
  name: string;
  sections: string[];
  scope?: Record<string, unknown>;
  created_at?: string;
}

export interface ComplianceStatus {
  [framework: string]: number | Record<string, unknown>;
}

export interface GenerateJob {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  status_url?: string;
  result_url?: string;
}

export interface ComposeReportOptions {
  preset?: string;
  format?: "html" | "pdf" | "docx" | "pptx" | "json" | "xlsx";
  sections?: string[];
  scope?: Record<string, unknown>;
  industry_template_id?: string;
  prepared_for?: string;
  filename?: string;
}

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface ListResponse<T> {
  items: T[];
  total?: number;
}
