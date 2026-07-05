export interface DependenciesFinding {
  number: number
  current_version?: string | null
  state: "open" | "deferred" | "fixed" | "dismissed"
  dependency: {
    package: {
      ecosystem: string
      name: string
    }
    manifest_path: string
    scope: "development" | "runtime" | null
  }
  security_advisory: {
    ghsa_id: string
    cve_id: string | null
    summary: string
    description: string
    severity: "low" | "medium" | "high" | "critical"
    cvss: {
      score: number | null
      vector_string: string | null
    }
    published_at: string
    updated_at: string
    references: { url: string }[]
  }
  security_vulnerability: {
    package: {
      ecosystem: string
      name: string
    }
    severity: "low" | "medium" | "high" | "critical"
    vulnerable_version_range: string
    first_patched_version: { identifier: string } | null
  }
  url: string
  html_url: string
  created_at: string
  updated_at: string
  dismissed_at: string | null
  dismissed_by: { login: string } | null
  dismissed_reason: string | null
  dismissed_comment: string | null
  fixed_at: string | null
  state_changed_at?: string | null
  first_seen_at?: string | null
  source?: "git"
  matched_by?: string[]
  manifest_snippet?: string | null
  manifest_match_line?: number | null
  repository: {
    id: number
    name: string
    full_name: string
    html_url: string
    private: boolean
  }
}

export interface DependenciesHealthRunEntry {
  id: string
  createdAt: string
  status: "completed" | "failed" | "running" | "ingesting" | "cancelled"
  scanMode?: string
  startedAt?: string
  finishedAt?: string
  findingsCount: number
  durationSeconds?: number
  repositories: string[]
  sourceCategory?: "code-repositories" | "container-images" | "mixed"
  error?: string
  logTail?: string[]
  progress?: {
    expectedRepos?: number | null
    scannedRepos?: number
    finishedRepos?: number
    percent?: number
    currentRepo?: string | null
    stage?: string
  }
  counts: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
}

export type Severity = "critical" | "high" | "medium" | "low"
