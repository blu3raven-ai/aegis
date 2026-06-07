import { apiClient } from "./api-client.ts"

const BASE = "/api/v1/reports"

export interface FindingsReportFilters {
  severity?: string[]
  scanner?: string[]
  state?: string[]
  repo?: string
}

export interface GenerateReportPayload {
  report_type: "findings" | "posture"
  format: "json" | "csv"
  title?: string
  filters?: FindingsReportFilters
}

export interface ReportSummary {
  id: number
  org: string
  title: string
  report_type: string
  format: string
  status: string
  row_count: number | null
  file_size_bytes: number | null
  created_by: string
  created_at: string
  expires_at: string
  download_url: string | null
}

export interface ReportDetail extends ReportSummary {
  filters: Record<string, unknown> | null
  error: string | null
}

export interface ReportsListResponse {
  reports: ReportSummary[]
  total: number
}

export async function generateReport(payload: GenerateReportPayload): Promise<ReportDetail> {
  return apiClient<ReportDetail>(BASE, { method: "POST", body: payload })
}

export async function listReports(limit = 50, offset = 0): Promise<ReportsListResponse> {
  const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  return apiClient<ReportsListResponse>(`${BASE}?${qs}`)
}

export async function getReport(reportId: number): Promise<ReportDetail> {
  return apiClient<ReportDetail>(`${BASE}/${reportId}`)
}

export async function deleteReport(reportId: number): Promise<void> {
  await apiClient<void>(`${BASE}/${reportId}`, { method: "DELETE" })
}
