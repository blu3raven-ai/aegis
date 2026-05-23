export const DEPENDENCIES_COUNTS_QUERY = `
  query DependenciesCounts($org: String) {
    dependenciesCounts(org: $org) {
      total
      critical
      high
      medium
      low
    }
  }
`

export const DEPENDENCIES_FINDINGS_QUERY = `
  query DependenciesFindings(
    $org: String!, $page: Int, $perPage: Int,
    $severity: String, $state: String, $ecosystem: [String!],
    $repository: String, $organization: String,
    $packageSearch: String, $fixAvailability: String,
    $cvssRange: String, $ageBucket: String,
    $search: String, $newSinceLastScan: Boolean, $lastScanDate: String
  ) {
    dependenciesFindings(
      org: $org, page: $page, perPage: $perPage,
      severity: $severity, state: $state, ecosystem: $ecosystem,
      repository: $repository, organization: $organization,
      packageSearch: $packageSearch, fixAvailability: $fixAvailability,
      cvssRange: $cvssRange, ageBucket: $ageBucket,
      search: $search, newSinceLastScan: $newSinceLastScan, lastScanDate: $lastScanDate
    ) {
      items {
        id state severity ecosystem packageName vulnerableVersion
        patchedVersion repoFullName advisorySummary
        cvssScore firstSeenAt fixedAt currentVersion manifestPath ghsaId
      }
      totalCount
      pageInfo { hasNextPage hasPreviousPage totalPages }
    }
  }
`

export const DEPENDENCIES_FILTER_OPTIONS_QUERY = `
  query DependenciesFilterOptions($org: String!) {
    dependenciesFilterOptions(org: $org) {
      ecosystems
      repositories
      organizations
    }
  }
`

export const DEPENDENCIES_ANALYTICS_QUERY = `
  query DependenciesAnalytics($org: String!) {
    dependenciesAnalytics(org: $org) {
      counts { total critical high medium low }
      severityDistribution { severity count percentage }
      ageBuckets { label count }
      topRepositories { name open critical high }
      remediation { totalFixed avgDays medianDays fixedLast30d }
      repositoryCoverage { total affected unaffected percentage }
      riskScore { score rating summary }
      staleFindingsCount
      deferredFindingsCount
      monthlyTrend { month introduced resolved openAtEnd }
      ecosystemBreakdown { ecosystem critical high medium low total }
      topVulnerablePackages { name ecosystem repoCount critical high medium low }
      mttrBySeverity { critical high medium low }
      remediationPriority {
        rank packageName ecosystem ghsaId cveId severity
        reposAffected patchVersion advisoryUrl
      }
    }
  }
`

export const CODE_SCANNING_COUNTS_QUERY = `
  query CodeScanningCounts($org: String) {
    codeScanningCounts(org: $org) {
      total
      critical
      high
      medium
      low
    }
  }
`

export const CODE_SCANNING_FINDINGS_QUERY = `
  query CodeScanningFindings(
    $org: String!, $page: Int, $perPage: Int,
    $severity: String, $state: String,
    $language: String, $reachability: String, $confidence: String,
    $ruleId: String, $repository: String,
    $ageBucket: String, $search: String,
    $newSinceLastScan: Boolean, $lastScanDate: String
  ) {
    codeScanningFindings(
      org: $org, page: $page, perPage: $perPage,
      severity: $severity, state: $state,
      language: $language, reachability: $reachability, confidence: $confidence,
      ruleId: $ruleId, repository: $repository,
      ageBucket: $ageBucket, search: $search,
      newSinceLastScan: $newSinceLastScan, lastScanDate: $lastScanDate
    ) {
      items {
        id state severity ruleId ruleName message
        filePath line repoFullName firstSeenAt fixedAt
        language confidence category cwe snippet fixSuggestion codeWindow
        aiReview { verdict explanation reasoning confidence }
        codeFlows { file line snippet }
        reachability { verdict entryPoint callChain { function file line snippet } }
      }
      totalCount
      pageInfo { hasNextPage hasPreviousPage totalPages }
    }
  }
`

export const CODE_SCANNING_ANALYTICS_QUERY = `
  query CodeScanningAnalytics($org: String!) {
    codeScanningAnalytics(org: $org) {
      counts { total critical high medium low }
      severityDistribution { severity count percentage }
      ageBuckets { label count }
      topRepositories { name open critical high }
      remediation { totalFixed avgDays medianDays fixedLast30d }
      repositoryCoverage { total affected unaffected percentage }
      riskScore { score rating summary }
      topRules { ruleId ruleName count }
      awaitingFixCount
      stateBreakdown { open dismissed fixed awaitingFix }
      categoryBreakdown { category count }
    }
  }
`

export const CODE_SCANNING_FILTER_OPTIONS_QUERY = `
  query CodeScanningFilterOptions($org: String!) {
    codeScanningFilterOptions(org: $org) {
      repositories
      languages
      ruleIds
    }
  }
`

export const CONTAINER_COUNTS_QUERY = `
  query ContainerCounts($org: String) {
    containerCounts(org: $org) {
      total
      critical
      high
      medium
      low
    }
  }
`

export const CONTAINER_FINDINGS_QUERY = `
  query ContainerFindings(
    $org: String!, $page: Int, $perPage: Int,
    $severity: String, $state: String, $ecosystem: [String!],
    $repository: String, $organization: String,
    $packageSearch: String, $fixAvailability: String,
    $cvssRange: String, $ageBucket: String,
    $search: String, $newSinceLastScan: Boolean, $lastScanDate: String
  ) {
    containerFindings(
      org: $org, page: $page, perPage: $perPage,
      severity: $severity, state: $state, ecosystem: $ecosystem,
      repository: $repository, organization: $organization,
      packageSearch: $packageSearch, fixAvailability: $fixAvailability,
      cvssRange: $cvssRange, ageBucket: $ageBucket,
      search: $search, newSinceLastScan: $newSinceLastScan, lastScanDate: $lastScanDate
    ) {
      items {
        id state severity ecosystem packageName vulnerableVersion
        patchedVersion repoFullName advisorySummary
        cvssScore firstSeenAt fixedAt currentVersion manifestPath
      }
      totalCount
      pageInfo { hasNextPage hasPreviousPage totalPages }
    }
  }
`

export const CONTAINER_FILTER_OPTIONS_QUERY = `
  query ContainerFilterOptions($org: String!) {
    containerFilterOptions(org: $org) {
      ecosystems
      repositories
      organizations
    }
  }
`

export const CONTAINER_ANALYTICS_QUERY = `
  query ContainerAnalytics($org: String!) {
    containerAnalytics(org: $org) {
      counts { total critical high medium low }
      severityDistribution { severity count percentage }
      ageBuckets { label count }
      topRepositories { name open critical high }
      remediation { totalFixed avgDays medianDays fixedLast30d }
      repositoryCoverage { total affected unaffected percentage }
      riskScore { score rating summary }
      staleFindingsCount
      deferredFindingsCount
      monthlyTrend { month introduced resolved openAtEnd }
      ecosystemBreakdown { ecosystem critical high medium low total }
      topVulnerablePackages { name ecosystem repoCount critical high medium low }
      mttrBySeverity { critical high medium low }
      remediationPriority {
        rank packageName ecosystem ghsaId cveId severity
        reposAffected patchVersion advisoryUrl
      }
    }
  }
`

export const SECRET_COUNTS_QUERY = `
  query SecretCounts($org: String) {
    secretCounts(org: $org) {
      total
      critical
      high
      medium
      low
    }
  }
`

export const SECRET_FINDINGS_QUERY = `
  query SecretFindings(
    $org: String!, $page: Int, $perPage: Int,
    $severity: String, $state: String,
    $reviewStatus: String, $detector: String,
    $repository: String, $organization: String,
    $source: String, $search: String,
    $classification: String, $ageBucket: String,
    $newSinceLastScan: Boolean, $lastScanDate: String
  ) {
    secretFindings(
      org: $org, page: $page, perPage: $perPage,
      severity: $severity, state: $state,
      reviewStatus: $reviewStatus, detector: $detector,
      repository: $repository, organization: $organization,
      source: $source, search: $search,
      classification: $classification, ageBucket: $ageBucket,
      newSinceLastScan: $newSinceLastScan, lastScanDate: $lastScanDate
    ) {
      items {
        id state reviewStatus detector filePath line
        repository organization commit secretSnippet
        firstSeenAt dismissedAt dismissedBy dismissedReason
        secretIdentity fingerprint source
        classificationHistory { value source scanDepth confidence runId scannedAt }
        riskScore occurrenceCount confirmedAt resolvedAt detectedAt
      }
      totalCount
      pageInfo { hasNextPage hasPreviousPage totalPages }
    }
  }
`

export const SECRET_OVERVIEW_QUERY = `
  query SecretsOverview($org: String!) {
    secretsOverview(org: $org) {
      uniqueKeyCount
      totalFindingsCount
      reviewFunnel { newCount confirmedCount falsePositiveCount actionTakenCount }
      sourceBreakdown { source count }
      remediation { totalFixed avgDays medianDays fixedLast30d }
      repositoryCoverage { total affected unaffected percentage }
      staleFindingsCount
      resolvedRecentlyCount
      unresolvedCount
      ageBuckets { label count }
      triagePriority { organization repository unreviewedCount confirmedCount }
    }
  }
`

export const SECRET_FILTER_OPTIONS_QUERY = `
  query SecretsFilterOptions($org: String!) {
    secretsFilterOptions(org: $org) {
      organizations
      repositories
      detectors
      sources
    }
  }
`


export const POSTURE_TREND_QUERY = `
  query PostureTrend($days: Int) {
    postureTrend(days: $days) {
      date
      total
      critical
      high
      medium
      low
    }
  }
`

export const HOME_ANALYTICS_QUERY = `
  query HomeAnalytics {
    homeAnalytics {
      topRepositories { name open critical high }
      ageBuckets { label count }
      remediation { totalFixed avgDays medianDays fixedLast30d }
    }
  }
`

export const DEPENDENCIES_FINDING_DETAIL_QUERY = `
  query DependenciesFindingDetail($org: String!, $identityKey: String!) {
    dependenciesFindingDetail(org: $org, identityKey: $identityKey) {
      identityKey org state severity
      ecosystem packageName currentVersion manifestPath
      ghsaId cveId advisorySummary advisoryDescription advisoryUrl
      publishedAt advisoryUpdatedAt references
      cvssScore cvssVector
      vulnerableVersionRange patchedVersion
      manifestSnippet manifestMatchLine
      firstSeenAt fixedAt dismissedReason repoFullName
    }
  }
`
