import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./FindingsBoardView.tsx", import.meta.url).pathname, "utf-8")
const mapperSrc = readFileSync(
  new URL("../../../lib/shared/findings/row-mapper.ts", import.meta.url).pathname,
  "utf-8",
)
// Package / detector / rule now live in the consolidated advisory spec table.
const advisorySrc = readFileSync(new URL("./AdvisoryHeader.tsx", import.meta.url).pathname, "utf-8")

describe("FindingsBoardView filter bar additions", () => {
  it("declares a ScannerFilter type that includes 'all' + every FindingScanner option", () => {
    assert.match(src, /type ScannerFilter = FindingScanner \| "all"/)
  })

  it("forwards searchQuery and scannerFilter to listFindings via spread", () => {
    assert.match(src, /scanner !== "all" \?\s*\{ scanner: \[scanner\] \}/)
    assert.match(src, /q \? \{ q \}/)
  })

  it("derives the accepted scanner filter set from SCANNER_ORDER so no scanner is dropped", () => {
    // Regression: a hand-maintained VALID_SCANNERS once omitted agent_scanning,
    // so the URL-sync silently reset that filter to "all" and the agent view
    // showed nothing. Deriving from SCANNER_ORDER makes that drift impossible.
    assert.match(src, /const VALID_SCANNERS = new Set<ScannerFilter>\(\["all", \.\.\.SCANNER_ORDER\]\)/)
    assert.match(src, /const SCANNER_ORDER: Scanner\[\] = \[[^\]]*"agent_scanning"[^\]]*\]/)
  })

  it("debounces the search input before triggering a fetch", () => {
    assert.match(src, /SEARCH_DEBOUNCE_MS/)
    assert.match(src, /setTimeout\(\(\) => setSearchQuery\(/)
  })

  it("re-runs load when severity, scanner, repo, state, sort, age, verdict, debounced searchQuery, per-scanner pages, or grouping changes", () => {
    assert.match(src, /\[sevFilter,\s*scannerFilter,\s*searchQuery,\s*repoFilter,\s*stateFilter,\s*sortKey,\s*agePreset,\s*moreFilters,\s*verdictFilter,\s*page,\s*scannerPages,\s*groupBy,\s*load\]/)
  })

  it("delegates the non-compact filter bar to FindingsCommandBar", () => {
    assert.match(src, /import \{ FindingsCommandBar \} from "\.\/FindingsCommandBar"/)
    assert.match(src, /<FindingsCommandBar/)
    assert.match(src, /severity=\{sevFilter\}/)
    assert.match(src, /moreFilters=\{moreFilters\}/)
    assert.match(src, /repoOptions=\{repoOptions\}/)
  })

  it("refetches the findings list when a scan completes (no manual reload)", () => {
    // New findings only land at scan-ingest, so the board must refetch on the
    // scan.completed SSE event or the list stays stale until a browser refresh.
    assert.match(src, /useSSE\("scan\.completed",/)
  })

  it("scopes scanner via the command-bar filter, not scanner NavTabs", () => {
    // The scanner tabs (#1014) are removed everywhere; scanner scoping now comes
    // from a command-bar filter (scanner={scannerFilter}) plus per-scanner-group
    // pagination for the unfiltered "all" view so each group paginates independently.
    assert.doesNotMatch(src, /NavTabs/)
    assert.doesNotMatch(src, /scannerTabs/)
    assert.doesNotMatch(src, /scannerCounts/)
    assert.match(src, /scanner=\{scannerFilter\}/)
    assert.match(src, /onScannerChange=\{/)
  })

  it("derives a perScannerMode and paginates each scanner group independently", () => {
    assert.match(src, /const perScannerMode = groupBy === "scanner" && !flat && scannerFilter === "all"/)
    assert.match(src, /const \[scannerPages, setScannerPages\] = useState<Record<string, number>>\(\{\}\)/)
    assert.match(src, /const \[scannerTotals, setScannerTotals\] = useState<Record<string, number>>\(\{\}\)/)
    // One page-sized fetch per scanner in SCANNER_ORDER, each on its own page,
    // run with bounded concurrency so the heavy queries don't all contend for
    // the GraphQL 5s timeout at once.
    assert.match(src, /mapWithConcurrency\(\s*SCANNER_ORDER,\s*PER_SCANNER_FETCH_CONCURRENCY/)
    assert.match(src, /page: scannerPages\[s\] \?\? 1/)
    // Each group renders its own shared paginator keyed by the group's scanner.
    assert.match(src, /page=\{scannerPages\[group\.key\] \?\? 1\}/)
    assert.match(src, /total=\{scannerTotals\[group\.key\] \?\? 0\}/)
    // The single global paginator is suppressed in per-scanner mode.
    assert.match(src, /\{!perScannerMode && \(\s*<FindingsPagination/)
  })

  it("ships a STATE_FILTER_OPTIONS array with the four finding states + 'all'", () => {
    for (const value of ['"all"', '"open"', '"closed"', '"fixed"', '"dismissed"']) {
      assert.ok(src.includes(`value: ${value}`), `STATE_FILTER_OPTIONS should include ${value}`)
    }
  })

  it("derives stateFilter initial value from initialStateFilter prop", () => {
    assert.match(src, /function initialStateFromProp/)
    assert.match(src, /initialStateFromProp\(initialStateFilter\)/)
  })

  it("forwards stateFilter to listFindings as state: [state] when not 'all'", () => {
    assert.match(src, /state !== "all"\s*\?\s*\{ state: \[state\] \}/)
  })

  it("populates the Repo dropdown from listRepos", () => {
    assert.match(src, /listRepos\(\{\s*limit:\s*200\s*\}\)/)
    assert.match(src, /setRepoOptions/)
  })

  it("forwards repo to listFindings when filter is not 'all'", () => {
    assert.match(src, /repo !== "all"\s*\?\s*\{ repo \}/)
  })

  it("threads repo into the ExportFindingsButton filters as repo_id", () => {
    assert.match(src, /repoFilter !== "all"\s*\?\s*\{ repo_id: repoFilter \}\s*:\s*\{\}/)
  })

  it("renders the FindingsCommandBar unconditionally — same surface for findings and inbox", () => {
    const cmdBarPattern = /<FindingsCommandBar/g
    const matches = src.match(cmdBarPattern) ?? []
    assert.equal(matches.length, 1, "FindingsCommandBar should be rendered exactly once (no compact branch)")
    assert.doesNotMatch(src, /CompactListHeader/)
  })

  it("threads scannerFilter into the ExportFindingsButton filters", () => {
    assert.match(src, /\.\.\.\(scannerFilter !== "all" \? \{ scanner: scannerFilter \} : \{\}\)/)
  })

  it("syncs bands through URL state and fetch params", () => {
    assert.match(src, /"bands"/)
    assert.match(src, /moreFilters\.bands\.length \? \{ bands: moreFilters\.bands \} : \{\}/)
    assert.match(src, /params\.bands = moreFilters\.bands\.join\(","\)/)
    assert.match(src, /bands: state\.bands/)
  })

  it("registers the action_band sort key in VALID_SORT_KEYS without the retired risk_score key", () => {
    assert.match(src, /new Set<SortKey>\(\["severity_age", "epss", "cvss", "action_band", "newest", "oldest"\]\)/)
  })

  it("sorts the Exploitability column header by action_band", () => {
    assert.match(src, /direction=\{sortKey === "action_band" \? "descending" : "none"\}/)
    assert.match(src, /onClick=\{\(\) => setSortKey\("action_band"\)\}/)
  })

  it("renders the Exploitability cell as a passive action-band badge, not a risk number", () => {
    assert.match(src, /finding\.actionBand \? \(/)
    assert.match(src, /<ActionBandBadge band=\{finding\.actionBand\}/)
    assert.doesNotMatch(src, /<RiskScoreCell/)
  })

  it("renders the action band in the compact triage row, not the legacy 0-100 exploit meter", () => {
    assert.match(src, /<ActionBandBadge band=\{finding\.actionBand\}/)
    assert.doesNotMatch(src, /Exploitability \$\{finding\.riskScore\} of 100/)
  })

  it("shows the action band in the detail signal row instead of a numeric exploit score", () => {
    assert.match(src, /\{finding\.actionBand && \(\s*<SignalChip tone=\{bandTone\}/)
    assert.match(src, /\{ACTION_BAND_LABEL\[finding\.actionBand\]\}/)
    assert.doesNotMatch(src, /Exploit \{finding\.riskScore\}\/100/)
  })

  it("syncs assignee through URL state and fetch params", () => {
    assert.match(src, /"assignee"/)
    assert.match(src, /moreFilters\.assigneeUserId \? \{ assignee: moreFilters\.assigneeUserId \} : \{\}/)
    assert.match(src, /params\.assignee = moreFilters\.assigneeUserId/)
    assert.match(src, /assigneeUserId: state\.assignee \|\| null/)
  })

  it("no longer renders the legacy chained view-mode toggle or chains cross-link", () => {
    assert.doesNotMatch(src, /viewMode/)
    assert.doesNotMatch(src, /View Chains/)
    assert.doesNotMatch(src, /href="\/chains"/)
  })

  it("no longer renders the saved-views controls in the page header", () => {
    assert.doesNotMatch(src, /SavedViewsDropdown/)
    assert.doesNotMatch(src, /SaveViewModal/)
    assert.doesNotMatch(src, /ManageViewsPanel/)
  })
})

describe("mapApiFinding recommended-fix wiring", () => {
  it("maps api.recommended_fix to FindingRow.recommendedFix", () => {
    // Source assertions guard against silent regressions during refactors without
    // requiring a full API mock in this test harness.
    assert.match(mapperSrc, /recommended_fix/)
    assert.match(mapperSrc, /recommendedFix/)
  })

  it("maps api.action_band to FindingRow.actionBand through normaliseActionBand", () => {
    assert.match(mapperSrc, /function normaliseActionBand/)
    assert.match(mapperSrc, /actionBand: normaliseActionBand\(api\.action_band\)/)
  })

  it("FindingsBoardView merges recommendedFix from the detail response onto selectedFinding", () => {
    assert.match(src, /recommendedFix: d\.recommendedFix \?\? curr\.recommendedFix/)
  })

  it("FindingsBoardView passes selectedFinding.recommendedFix to RecommendedFixSection", () => {
    assert.match(src, /RecommendedFixSection/)
    assert.match(src, /fix=\{selectedFinding\.recommendedFix\}/)
  })
})

describe("FindingsBoardView verification + reachability wiring", () => {
  it("maps the detail-only verification fields in the row-mapper", () => {
    assert.match(mapperSrc, /evidence: normaliseEvidence\(api\.evidence\)/)
    assert.match(mapperSrc, /exploitChain: api\.exploit_chain/)
    assert.match(mapperSrc, /verificationMetadata: api\.verification_metadata/)
    assert.match(mapperSrc, /reachability: normaliseReachability\(api\.reachability\)/)
  })

  it("merges the detail-only verification fields onto selectedFinding on open", () => {
    assert.match(src, /evidence: d\.evidence \?\? curr\.evidence/)
    assert.match(src, /exploitChain: d\.exploitChain \?\? curr\.exploitChain/)
    assert.match(src, /verificationMetadata: d\.verificationMetadata \?\? curr\.verificationMetadata/)
    assert.match(src, /reachability: d\.reachability \?\? curr\.reachability/)
  })

  it("renders the discrete report sections in the analysis group", () => {
    assert.match(src, /<SummarySection/)
    assert.match(src, /<TechnicalDetailSection evidence=\{selectedFinding\.evidence\}/)
    assert.match(src, /<AttackScenarioSection/)
    assert.match(src, /<ImpactSection impact=/)
    assert.match(src, /<NotesVerificationSection/)
  })

  it("gives agent-scanner findings the emphasized Impact treatment for their curated advisory", () => {
    // Agent findings have no LLM verifier; their description IS the impact
    // statement, so it renders via the shared ImpactCallout, not a plain paragraph.
    assert.match(src, /emphasized=\{selectedFinding\.scanner === "agent_scanning"\}/)
    assert.match(src, /if \(emphasized\) \{[\s\S]*?<ImpactCallout>\{body\}<\/ImpactCallout>/)
    assert.match(src, /import \{ ImpactCallout \}/)
  })

  it("strips the title lead from the description so 'What's wrong' doesn't repeat the headline", () => {
    assert.match(src, /desc\.startsWith\(t\) \? desc\.slice\(t\.length\)\.trim\(\)/)
  })

  it("derives the verification-enabled signal from the LLM config status", () => {
    assert.match(src, /fetch\("\/api\/v1\/settings\/llm"\)/)
    assert.match(src, /setVerificationEnabled\(Boolean\(data\.enabled\)\)/)
  })

  it("renders the References section from the finding's cve + cwe + advisory refs", () => {
    assert.match(src, /<FindingReferencesSection[\s\S]*?cve=\{selectedFinding\.cve\}[\s\S]*?cwe=\{selectedFinding\.cwe\}/)
    assert.match(src, /advisoryReferences=\{advisory\?\.references\}/)
  })

  it("renders a reachability signal chip with glyph + label (not colour alone)", () => {
    assert.match(src, /REACHABILITY_SIGNAL/)
    assert.match(src, /reach && \(/)
    assert.match(src, /\{reach\.glyph\}/)
    assert.match(src, /\{reach\.label\}/)
  })

  it("gives the chip primitive a success tone for the de-risked 'not reachable' state", () => {
    assert.match(src, /tone: "danger" \| "warn" \| "success" \| "neutral"/)
    assert.match(src, /no_path:\s*\{\s*tone: "success"/)
  })
})

describe("FindingsBoardView deep-link (?finding=<id>)", () => {
  it("accepts an initialFindingId prop", () => {
    assert.match(src, /initialFindingId\?: string/)
    assert.match(src, /initialFindingId,/)
  })

  it("opens the drawer on mount by fetching the deep-linked finding's detail", () => {
    assert.match(src, /if \(!initialFindingId\) return/)
    assert.match(src, /getFindingDetail\(id\)/)
    assert.match(src, /setSelectedFinding\(mapApiFinding\(raw\)\)/)
    assert.match(src, /\}, \[initialFindingId\]\)/)
  })

  it("surfaces a missing/out-of-scope id via a notice instead of throwing or a 404", () => {
    // The catch sets the notice flag rather than dead-ending; one message
    // covers missing and out-of-scope so the id's existence isn't leaked.
    assert.match(src, /setDeepLinkMissing\(true\)/)
    assert.match(src, /deepLinkMissing &&/)
    assert.match(src, /no longer exists or isn’t in your scope/)
  })
})

describe("FindingsBoardView row rendering", () => {
  it("renders every age through the shared FindingAge (no inline {finding.age} spans)", () => {
    // The no-wrap invariant lives in FindingAge — guard against age rendering
    // drifting back into per-call-site spans (which regressed the row height).
    assert.doesNotMatch(src, /<span[^>]*>\s*\{finding\.age\}/)
    const uses = src.match(/age=\{finding\.age\}/g) ?? []
    assert.ok(uses.length >= 3, `expected every age cell to use FindingAge, found ${uses.length}`)
  })
})

describe("FindingsBoardView advisory Security Brief wiring", () => {
  it("lazily fetches the advisory per finding and clears it on navigation", () => {
    assert.match(src, /const \[advisory, setAdvisory\] = useState<FindingAdvisory \| null>\(null\)/)
    assert.match(src, /setAdvisory\(null\)/)
    assert.match(src, /getFindingAdvisory\(id\)\s*\.then\(\(a\) => \{ if \(active\) setAdvisory\(a\) \}\)/)
  })

  it("surfaces a detail-fetch failure instead of silently showing the lean row", () => {
    assert.match(src, /setDetailError\(e instanceof Error \? e\.message : String\(e\)\)/)
    assert.match(src, /detailError && \(/)
    assert.match(src, /Couldn&apos;t load the full detail/)
  })

  it("surfaces an advisory-fetch failure visibly", () => {
    assert.match(src, /setAdvisoryError\(e instanceof Error \? e\.message : String\(e\)\)/)
    assert.match(src, /advisoryError && \(/)
  })

  it("renders the Security Brief section with the fetched advisory", () => {
    assert.match(src, /<SecurityBriefSection advisory=\{advisory\}/)
  })

  it("shows the affected package as its own field", () => {
    assert.match(advisorySrc, /finding\.package \?/)
    assert.match(advisorySrc, /label="Package"/)
  })
})

describe("FindingsBoardView secret validity wiring", () => {
  it("maps the detail-only secret fields in the row-mapper", () => {
    assert.match(mapperSrc, /secretDetector: api\.secret_detector/)
    assert.match(mapperSrc, /secretVerified: api\.secret_verified/)
  })

  it("merges the secret fields onto selectedFinding on open", () => {
    assert.match(src, /secretDetector: d\.secretDetector \?\? curr\.secretDetector/)
    assert.match(src, /secretVerified: d\.secretVerified \?\? curr\.secretVerified/)
    assert.match(src, /introducedByCommit: d\.introducedByCommit \?\? curr\.introducedByCommit/)
  })

  it("shows a live-credential signal chip when the secret is verified", () => {
    assert.match(src, /finding\.secretVerified != null/)
    assert.match(src, /Live credential/)
    assert.match(src, /Unverified/)
  })

  it("shows the detector in the advisory table", () => {
    assert.match(advisorySrc, /finding\.secretDetector \?/)
    assert.match(advisorySrc, /label="Detector"/)
  })
})

describe("FindingsBoardView CWE context wiring", () => {
  it("renders the CWE context section from the finding's cwe", () => {
    assert.match(src, /<CweContextSection cwe=\{selectedFinding\.cwe\}/)
  })
})

describe("FindingsBoardView container image wiring", () => {
  it("merges the container image onto selectedFinding and renders the section", () => {
    assert.match(src, /containerImage: d\.containerImage \?\? curr\.containerImage/)
    assert.match(src, /<ContainerImageSection image=\{selectedFinding\.containerImage\}/)
  })
})

describe("FindingsBoardView blast-radius wiring", () => {
  it("merges the blast-radius count onto selectedFinding on open", () => {
    assert.match(src, /alsoAffectsRepos: d\.alsoAffectsRepos \?\? curr\.alsoAffectsRepos/)
  })

  it("renders the BlastRadiusSection with the finding id and count", () => {
    assert.match(src, /<BlastRadiusSection\s+findingId=\{Number\(selectedFinding\.id\)\}\s+count=\{selectedFinding\.alsoAffectsRepos\}/)
  })
})

describe("FindingsBoardView URL sync", () => {
  it("mirrors filters into the URL via replaceState, gated on the opt-in syncUrl prop", () => {
    assert.match(src, /if \(!syncUrl \|\| typeof window === "undefined"\) return/)
    assert.match(src, /window\.history\.replaceState\(null, ""/)
  })

  it("only syncs keys that round-trip — collapsed and page are excluded", () => {
    const block = src.match(/const URL_SYNC_KEYS = \[([\s\S]*?)\] as const/)
    assert.ok(block, "URL_SYNC_KEYS must be defined")
    for (const key of ["severity", "scanner", "state", "repo", "q", "sort", "age", "cwe", "kev", "epss_min", "bands", "assignee"]) {
      assert.ok(block![1].includes(`"${key}"`), `URL_SYNC_KEYS must include ${key}`)
    }
    assert.doesNotMatch(block![1], /"collapsed"|"page"/)
  })

  it("hydrates the full filter set on mount from initial props (not just the primary chips)", () => {
    assert.match(src, /readFromSet<SortKey>\(\{ sort: initialSort \?\? "" \}/)
    assert.match(src, /readFromSet<AgePresetKey>\(\{ age: initialAge \?\? "" \}/)
    assert.match(src, /cwe: initialCwe \|\| null/)
    assert.match(src, /assigneeUserId: initialAssignee \|\| null/)
    assert.match(src, /initialBands/)
  })

  it("preserves the open drawer in the URL as ?finding=<id>", () => {
    assert.match(src, /if \(selectedId != null\) params\.set\("finding", String\(selectedId\)\)/)
  })

  it("refetches on findings.updated (mid-scan preview + streaming verdicts)", () => {
    assert.match(src, /useSSE\("findings\.updated",/)
  })

  it("suppresses raw scanner metavar templates in the remediation section", () => {
    // A `$FUNC`-style token means the scanner sent its rule template, not a fix.
    assert.match(src, /\/\\\$\[A-Z\]\[A-Z0-9_\]\*\/\.test\(remediation\)/)
    assert.match(src, /No automated fix yet — verify this finding to generate one\./)
  })

  it("badges a fix that provably applies (positive-only, gated on fix_verified)", () => {
    assert.match(src, /verificationMetadata\?\.fix_verified/)
    assert.match(src, /applies cleanly to the current code/)
    assert.match(mapperSrc, /fix_verified\?: boolean/)
  })
})
