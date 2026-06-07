import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RecentReleaseChecksTable.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RecentReleaseChecksTable triggered-by branching", () => {
  it("branches on actor_type === 'user'", () => {
    // Regression guard: keep matching on a strict-equality check (not just
    // any occurrence of the literal "user") so that dropping the comparison
    // or switching to a loose check fails the test.
    assert.match(
      src,
      /actor_type\s*===\s*["']user["']/,
      "should branch on actor_type === 'user'",
    )
  })

  it("branches on actor_type === 'ci'", () => {
    assert.match(
      src,
      /actor_type\s*===\s*["']ci["']/,
      "should branch on actor_type === 'ci'",
    )
  })

  it("formats user actor with @ prefix and CLI suffix", () => {
    assert.ok(
      src.includes("`@${triggered_by.display_name} · CLI`"),
      "should format user as '@name · CLI'",
    )
  })

  it("formats ci actor with CI prefix", () => {
    assert.ok(
      src.includes("`CI · ${triggered_by.display_name}`"),
      "should format ci as 'CI · name'",
    )
  })
})

describe("RecentReleaseChecksTable row linking", () => {
  it("links rows to /repos/{id}?tab=scans&scan_id={scan}", () => {
    assert.ok(
      src.includes("`/repos/${encodeURIComponent(release.repo_id)}?tab=scans&scan_id=${encodeURIComponent(release.scan_id)}`"),
      "should link rows to repo scan tab",
    )
  })

  it("encodes repo_id when constructing the row href", () => {
    // Regression guard: repo IDs and scan IDs may contain characters that
    // need URL-encoding (slashes, spaces). Dropping encodeURIComponent on
    // either segment would produce malformed links.
    assert.match(
      src,
      /encodeURIComponent\(\s*release\.repo_id\s*\)/,
      "should call encodeURIComponent on repo_id",
    )
  })

  it("encodes scan_id when constructing the row href", () => {
    assert.match(
      src,
      /encodeURIComponent\(\s*release\.scan_id\s*\)/,
      "should call encodeURIComponent on scan_id",
    )
  })

  it("imports Link from next/link", () => {
    assert.ok(
      src.includes('import Link from "next/link"'),
      "should import next/link",
    )
  })
})

describe("RecentReleaseChecksTable empty + loading", () => {
  it("renders no-results copy when empty", () => {
    assert.ok(
      src.includes("No recent release checks"),
      "should render empty-state copy",
    )
  })

  it("renders View all CTA", () => {
    assert.ok(src.includes("View all →"), "should render view-all CTA")
  })
})
