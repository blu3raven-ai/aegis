import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./FindingsBoardView.tsx", import.meta.url).pathname, "utf-8")

describe("FindingsBoardView filter bar additions", () => {
  it("declares a ScannerFilter type that includes 'all' + every FindingScanner option", () => {
    assert.match(src, /type ScannerFilter = FindingScanner \| "all"/)
  })

  it("ships a SCANNER_FILTER_OPTIONS array with the five scanner buckets the backend supports", () => {
    for (const value of ['"all"', '"dependencies_scanning"', '"code_scanning"', '"secret_scanning"', '"container_scanning"', '"iac_scanning"']) {
      assert.ok(src.includes(`value: ${value}`), `SCANNER_FILTER_OPTIONS should include ${value}`)
    }
  })

  it("forwards searchQuery and scannerFilter to listFindings via spread", () => {
    assert.match(src, /scanner !== "all" \?\s*\{ scanner: \[scanner\] \}/)
    assert.match(src, /q \? \{ q \}/)
  })

  it("debounces the search input before triggering a fetch", () => {
    assert.match(src, /SEARCH_DEBOUNCE_MS/)
    assert.match(src, /setTimeout\(\(\) => setSearchQuery\(/)
  })

  it("re-runs load when severity, scanner, repo, state, sort, age, verdict, or debounced searchQuery changes", () => {
    assert.match(src, /\[sevFilter,\s*scannerFilter,\s*searchQuery,\s*repoFilter,\s*stateFilter,\s*sortKey,\s*agePreset,\s*moreFilters,\s*verdictFilter,\s*page,\s*load\]/)
  })

  it("delegates the non-compact filter bar to FindingsCommandBar", () => {
    assert.match(src, /import \{ FindingsCommandBar \} from "\.\/FindingsCommandBar"/)
    assert.match(src, /<FindingsCommandBar/)
    assert.match(src, /severity=\{sevFilter\}/)
    assert.match(src, /scanner=\{scannerFilter\}/)
    assert.match(src, /moreFilters=\{moreFilters\}/)
    assert.match(src, /repoOptions=\{repoOptions\}/)
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

  it("syncs risk_score_min through URL state and fetch params", () => {
    assert.match(src, /"risk_score_min"/)
    assert.match(src, /moreFilters\.riskScoreMin != null \? \{ risk_score_min: moreFilters\.riskScoreMin \} : \{\}/)
    assert.match(src, /params\.risk_score_min = String\(moreFilters\.riskScoreMin\)/)
    assert.match(src, /riskScoreMin: state\.risk_score_min \? Number\(state\.risk_score_min\) : null/)
  })

  it("registers the risk_score sort key in VALID_SORT_KEYS", () => {
    assert.match(src, /new Set<SortKey>\(\["severity_age", "epss", "risk_score", "newest", "oldest"\]\)/)
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
