export const SCANNER_COUNTS_QUERY = `
  query ScannerCounts {
    scans {
      dependenciesScanning { counts { total critical high medium low } }
      codeScanning { counts { total critical high medium low } }
      containerScanning { counts { total critical high medium low } }
      secretScanning { counts { total critical high medium low } }
    }
  }
`

export const HOME_DASHBOARD_QUERY = `
  query HomeDashboard($trendDays: Int, $epssLimit: Int) {
    scans {
      dependenciesScanning { counts { total critical high medium low } }
      codeScanning { counts { total critical high medium low } }
      containerScanning { counts { total critical high medium low } }
      secretScanning { counts { total critical high medium low } }
    }
    posture {
      trend(days: $trendDays) { date total critical high medium low }
      homeAnalytics {
        topRepositories { name open critical high }
        ageBuckets { label count }
        remediation { totalFixed avgDays medianDays fixedLast30d }
      }
    }
    sla {
      epssTop(limit: $epssLimit) {
        findings {
          findingId tool repo severity identityKey cve
          epssScore epssPercentile scoredDate
        }
        count
      }
    }
  }
`

export const SCAN_RUNS_QUERY = `
  query ScanRuns($tool: String!, $limit: Int!) {
    sources {
      scanRuns(tool: $tool, limit: $limit) {
        id
        org
        status
        createdAt
        startedAt
        finishedAt
        durationSeconds
        findingsCount
        error
      }
    }
  }
`
