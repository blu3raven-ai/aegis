import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("FindingsBoardView component", () => {
  it("exports a named function FindingsBoardView", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.ok(src.includes("export function FindingsBoardView"), "FindingsBoardView must be exported")
  })

  it("accepts pageTitle, pageIcon, initialStateFilter props", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /pageTitle:\s*string/)
    assert.match(src, /pageIcon:\s*ReactNode/)
    assert.match(src, /initialStateFilter\?:\s*FindingState\[\]/)
  })

  it("seeds the state-filter dropdown from the initialStateFilter prop", () => {
    // The state filter is now driven by an in-page dropdown; the
    // initialStateFilter prop still controls the initial value via a helper
    // so existing callers (e.g. /inbox passing ["open"]) keep their behaviour.
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /initialStateFromProp\(initialStateFilter\)/, "must derive initial state from prop")
    assert.match(src, /state !== "all"\s*\?\s*\{ state: \[state\] \}/, "must forward selected state to listFindings")
  })

  it("uses props for PageHeader title and icon (not hard-coded Findings)", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.ok(src.includes("title={pageTitle}"), "PageHeader must use pageTitle prop")
    assert.ok(src.includes("icon={pageIcon}"), "PageHeader must use pageIcon prop")
  })

  it("keeps groupBy state seeded to scanner and delegates the selector to FindingsDisplayOverflow", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /useState<GroupKey>\("scanner"\)/, "groupBy state must default to scanner")
    const overflow = read("components/shared/findings/FindingsDisplayOverflow.tsx")
    for (const value of ["scanner", "severity", "repo", "status"]) {
      assert.ok(overflow.includes(`value: "${value}"`), `FindingsDisplayOverflow.GROUP_BY_OPTIONS must include ${value}`)
    }
  })

  it("groups sorted findings before rendering", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /const groups = useMemo\(/, "must compute groups via useMemo")
    assert.match(src, /groups\.map\(\(group\)/, "must render groups in table body")
  })

  it("computes per-group severity breakdown from group.rows", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /function groupSeverityCounts\(/)
    assert.match(src, /critical:\s*0,\s*high:\s*0,\s*medium:\s*0,\s*low:\s*0/)
  })

  it("renders groups via FindingsGroupHeader", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /import \{ FindingsGroupHeader \} from "\.\/FindingsGroupHeader"/)
    assert.match(src, /<FindingsGroupHeader/)
  })

  it("caps initial visible rows per group via INITIAL_ROWS_PER_GROUP", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /INITIAL_ROWS_PER_GROUP\s*=\s*5/)
    assert.match(src, /expandedGroups/)
  })

  it("renders 'Show N more' row when group.rows.length > visible.length", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /Show \$\{group\.rows\.length - INITIAL_ROWS_PER_GROUP\} more/)
  })

  it("renders FindingRowTags next to each row title", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /import \{ FindingRowTags \} from "\.\/FindingRowTags"/)
    assert.match(src, /<FindingRowTags[\s\S]*?kev=\{finding\.kev\}/)
  })

  it("delegates saved-views to the optional leftSidebar via the FindingsViewApi", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /export interface FindingsViewApi/)
    assert.match(src, /sidebarOwnsSavedViews/)
    assert.match(src, /applyView,/)
    assert.match(src, /currentUrlState,/)
  })

  it("computes currentUrlState as a memoized Record from active filter state", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /const currentUrlState: Record<string, string> = useMemo/)
  })

  it("applyView seeds local filter state from the saved view payload", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /function applyView/)
    assert.match(src, /setSevFilter\(readFromSet/)
    assert.match(src, /setSortKey\(readFromSet/)
  })

  it("declares VALID_VIEW_KEYS with the 14 URL-synced keys", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /const VALID_VIEW_KEYS = new Set<string>/)
    for (const k of ["severity", "scanner", "state", "repo", "q", "collapsed", "sort", "age", "cwe", "kev", "epss_min", "risk_score_min", "assignee", "page"]) {
      assert.ok(src.includes(`"${k}"`), `VALID_VIEW_KEYS must include "${k}"`)
    }
  })

  it("filters stale keys when applying a saved view", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /setStaleViewKeys\(stale\)/)
    assert.match(src, /VALID_VIEW_KEYS\.has/)
  })

  it("surfaces stale-filter warning when staleViewKeys is non-empty", () => {
    const src = read("components/shared/findings/FindingsBoardView.tsx")
    assert.match(src, /staleViewKeys\.length\s*>\s*0/)
    assert.match(src, /were skipped/)
  })
})

describe("/inbox page", () => {
  // /inbox redirects to its default tab; the open-findings queue lives at
  // /inbox/triage (sibling to /inbox/history).
  it("redirects to /inbox/triage", () => {
    const src = read("app/(app)/inbox/page.tsx")
    assert.ok(src.includes('redirect("/inbox/triage")'), "/inbox must redirect to triage")
  })

  it("triage renders FindingsBoardView with state: ['open']", () => {
    const src = read("app/(app)/inbox/triage/page.tsx")
    assert.ok(src.includes("FindingsBoardView"), "must import FindingsBoardView")
    assert.ok(src.includes('initialStateFilter={["open"]}'), "must pass initialStateFilter open")
    assert.ok(src.includes('pageTitle="Inbox"'), "must pass pageTitle Inbox")
  })

  it("triage uses InboxIcon from page-icons", () => {
    const src = read("app/(app)/inbox/triage/page.tsx")
    assert.ok(src.includes("InboxIcon"), "must import InboxIcon")
  })
})

describe("/findings page", () => {
  it("renders FindingsBoardView with no initialStateFilter", () => {
    const src = read("app/(app)/findings/page.tsx")
    assert.ok(src.includes("FindingsBoardView"), "must import FindingsBoardView")
    assert.ok(src.includes('pageTitle="Findings"'), "must pass pageTitle Findings")
    assert.ok(!src.includes("initialStateFilter"), "must not pass initialStateFilter (state-agnostic)")
  })

  it("uses FindingsIcon from page-icons", () => {
    const src = read("app/(app)/findings/page.tsx")
    assert.ok(src.includes("FindingsIcon"))
  })
})

describe("InboxIcon export", () => {
  it("page-icons.tsx exports InboxIcon", () => {
    const src = read("lib/shared/ui/page-icons.tsx")
    assert.ok(src.includes("export function InboxIcon"), "InboxIcon must be exported")
  })
})
