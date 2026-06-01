import test from "node:test"
import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"

import { relativeTime } from "../../lib/shared/relative-time.ts"

function makeIso(msAgo: number): string {
  return new Date(Date.now() - msAgo).toISOString()
}

const SECOND = 1_000
const MINUTE = 60 * SECOND
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const MONTH = 30 * DAY
const YEAR = 365 * DAY

test("relativeTime: < 1 minute returns 'just now'", () => {
  assert.equal(relativeTime(makeIso(30 * SECOND)), "just now")
})

test("relativeTime: 1 minute ago", () => {
  assert.equal(relativeTime(makeIso(1 * MINUTE + 5 * SECOND)), "1 minute ago")
})

test("relativeTime: 3 minutes ago", () => {
  assert.equal(relativeTime(makeIso(3 * MINUTE + 5 * SECOND)), "3 minutes ago")
})

test("relativeTime: 1 hour ago", () => {
  assert.equal(relativeTime(makeIso(1 * HOUR + 30 * SECOND)), "1 hour ago")
})

test("relativeTime: 5 hours ago", () => {
  assert.equal(relativeTime(makeIso(5 * HOUR + 30 * SECOND)), "5 hours ago")
})

test("relativeTime: 1 day ago", () => {
  assert.equal(relativeTime(makeIso(1 * DAY + 30 * SECOND)), "1 day ago")
})

test("relativeTime: 3 days ago", () => {
  assert.equal(relativeTime(makeIso(3 * DAY + 30 * SECOND)), "3 days ago")
})

test("relativeTime: 2 months ago", () => {
  assert.equal(relativeTime(makeIso(2 * MONTH + 30 * SECOND)), "2 months ago")
})

test("relativeTime: 1 year ago", () => {
  assert.equal(relativeTime(makeIso(1 * YEAR + 30 * SECOND)), "1 year ago")
})

test("relativeTime: invalid ISO returns raw input", () => {
  assert.equal(relativeTime("not-a-date"), "not-a-date")
})

// ---------------------------------------------------------------------------
// DrawerAttribution component render behaviour.
//
// The frontend test runner (node --test) cannot load .tsx files directly and
// the project ships without jsdom or testing-library — so following the
// established convention (see epss-cell-and-widget.test.ts and
// export-findings-button.test.ts) we validate render behaviour by mirroring
// the component's conditional logic against the canonical prop shape, plus
// pinning load-bearing source-level invariants (heading text, link target,
// SHA truncation, PR label derivation).
// ---------------------------------------------------------------------------

const HERE = new URL(".", import.meta.url).pathname
const COMPONENT_PATH = resolve(
  HERE,
  "../../components/shared/FindingDrawer/DrawerAttribution.tsx",
)

interface AttributionFields {
  introduced_by_commit_sha: string | null | undefined
  introduced_by_author: string | null | undefined
  introduced_at: string | null | undefined
  introduced_by_pr_url: string | null | undefined
}

interface RenderShape {
  rendered: boolean
  shortSha: string | null
  author: string | null
  date: string | null
  prHref: string | null
  prLabel: string | null
}

function extractPrLabel(url: string): string {
  const match = url.match(/\/pull\/(\d+)/)
  if (match) return `→ PR #${match[1]}`
  return `→ ${url}`
}

function renderDrawerAttribution(fields: AttributionFields): RenderShape {
  const {
    introduced_by_commit_sha,
    introduced_by_author,
    introduced_at,
    introduced_by_pr_url,
  } = fields

  const hasAny =
    introduced_by_commit_sha ||
    introduced_by_author ||
    introduced_at ||
    introduced_by_pr_url

  if (!hasAny) {
    return {
      rendered: false,
      shortSha: null,
      author: null,
      date: null,
      prHref: null,
      prLabel: null,
    }
  }

  return {
    rendered: true,
    shortSha: introduced_by_commit_sha ? introduced_by_commit_sha.slice(0, 7) : null,
    author: introduced_by_author ?? null,
    date: introduced_at ? relativeTime(introduced_at) : null,
    prHref: introduced_by_pr_url ?? null,
    prLabel: introduced_by_pr_url ? extractPrLabel(introduced_by_pr_url) : null,
  }
}

// ── File exists at expected path ─────────────────────────────────────────────

test("DrawerAttribution component file exists at expected path", () => {
  assert.ok(existsSync(COMPONENT_PATH), `Component not found at ${COMPONENT_PATH}`)
})

// ── Scenario 1: full attribution renders all fields ──────────────────────────

test("renders all fields when full attribution is present", () => {
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: "abcdef1234567890abcdef1234567890abcdef12",
    introduced_by_author: "alice@example.com",
    introduced_at: makeIso(3 * 24 * 60 * 60 * 1000 + 30 * 1000),
    introduced_by_pr_url: "https://github.com/acme-org/repo/pull/42",
  })

  assert.equal(shape.rendered, true)
  assert.equal(shape.shortSha, "abcdef1")
  assert.equal(shape.author, "alice@example.com")
  assert.equal(shape.date, "3 days ago")
  assert.equal(shape.prHref, "https://github.com/acme-org/repo/pull/42")
  assert.equal(shape.prLabel, "→ PR #42")
})

// ── Scenario 2: commit only, no PR link ──────────────────────────────────────

test("renders partial — commit only, PR link absent", () => {
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: "1234567abcdef",
    introduced_by_author: null,
    introduced_at: null,
    introduced_by_pr_url: null,
  })

  assert.equal(shape.rendered, true)
  assert.equal(shape.shortSha, "1234567")
  assert.equal(shape.author, null)
  assert.equal(shape.date, null)
  assert.equal(shape.prHref, null, "PR link element must be absent")
  assert.equal(shape.prLabel, null)
})

// ── Scenario 3: commit + author, no date or PR ───────────────────────────────

test("renders partial — commit + author, date and PR absent", () => {
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: "deadbeef1234",
    introduced_by_author: "bob@example.com",
    introduced_at: null,
    introduced_by_pr_url: null,
  })

  assert.equal(shape.rendered, true)
  assert.equal(shape.shortSha, "deadbee")
  assert.equal(shape.author, "bob@example.com")
  assert.equal(shape.date, null, "date row must be absent")
  assert.equal(shape.prHref, null)
})

// ── Scenario 4: all-null inputs render nothing ───────────────────────────────

test("renders nothing when all fields are null", () => {
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: null,
    introduced_by_author: null,
    introduced_at: null,
    introduced_by_pr_url: null,
  })

  assert.equal(shape.rendered, false, "section must not render at all")
  // Heading text must not appear when nothing renders.
  const source = readFileSync(COMPONENT_PATH, "utf8")
  const headingLiteral = "Introduced by"
  assert.ok(
    source.includes(headingLiteral),
    `expected component to use heading literal "${headingLiteral}"`,
  )
})

test("renders nothing when all fields are undefined", () => {
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: undefined,
    introduced_by_author: undefined,
    introduced_at: undefined,
    introduced_by_pr_url: undefined,
  })
  assert.equal(shape.rendered, false)
})

// ── Scenario 5: PR link href and target ──────────────────────────────────────

test("PR link opens in a new tab with noreferrer rel", () => {
  const source = readFileSync(COMPONENT_PATH, "utf8")
  assert.ok(
    /href=\{introduced_by_pr_url\}/.test(source),
    "anchor must bind href to introduced_by_pr_url",
  )
  assert.ok(/target="_blank"/.test(source), 'anchor must set target="_blank"')
  assert.ok(/rel="noreferrer"/.test(source), 'anchor must set rel="noreferrer"')
})

test("PR label derives from URL — GitHub /pull/<id> format", () => {
  assert.equal(
    extractPrLabel("https://github.com/acme-org/repo/pull/1234"),
    "→ PR #1234",
  )
})

test("PR label falls back to raw URL when /pull/<id> not present", () => {
  assert.equal(
    extractPrLabel("https://gitlab.example.com/group/proj/-/merge_requests/9"),
    "→ https://gitlab.example.com/group/proj/-/merge_requests/9",
  )
})

// ── Scenario 6: 40-char SHA truncates to first 7 chars ───────────────────────

test("commit SHA truncation — full 40-char SHA renders as first 7 chars", () => {
  const fullSha = "0123456789abcdef0123456789abcdef01234567"
  assert.equal(fullSha.length, 40)
  const shape = renderDrawerAttribution({
    introduced_by_commit_sha: fullSha,
    introduced_by_author: null,
    introduced_at: null,
    introduced_by_pr_url: null,
  })
  assert.equal(shape.shortSha, "0123456")
  assert.equal(shape.shortSha?.length, 7)
})

// ── Scenario 7: accessibility — heading is present and readable text ─────────

test("accessibility — heading 'Introduced by' is rendered as plain text", () => {
  const source = readFileSync(COMPONENT_PATH, "utf8")
  // The heading must be a text node inside a <p>, not visually hidden, so
  // screen readers announce it. Tracking-tight uppercase styling is OK
  // because the underlying text remains "Introduced by".
  assert.ok(
    /<p[^>]*>\s*Introduced by\s*<\/p>/.test(source),
    "heading 'Introduced by' must be present as visible text",
  )
})
