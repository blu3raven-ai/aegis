import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

// fileURLToPath (rather than URL.pathname) is required here because this file
// lives under `[scanId]`, which URL encodes to `%5BscanId%5D`. .pathname leaves
// the encoding in place and fs.readFileSync then can't find the file.
function readSibling(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, import.meta.url)), "utf-8")
}

const page = readSibling("./page.tsx")
const content = readSibling("./ReleaseDetailPageContent.tsx")
const loading = readSibling("./loading.tsx")
const errorPage = readSibling("./error.tsx")

describe("release detail page shell", () => {
  it("wraps content in Suspense for static export", () => {
    assert.match(page, /<Suspense\b/, "should wrap content in Suspense")
  })

  it("exports generateStaticParams stub so static export builds", () => {
    assert.match(page, /export function generateStaticParams\(/)
  })
})

describe("release detail content", () => {
  it("reads scanId from route params", () => {
    assert.match(content, /useParams<\{\s*scanId:\s*string\s*\}>/)
    assert.match(content, /params\.scanId/)
  })

  it("calls getRelease with the route scanId", () => {
    assert.match(content, /getRelease\(scanId\)/)
  })

  it("renders the canonical PageHeader", () => {
    assert.match(content, /<PageHeader\b/)
  })

  it("renders ReleaseVerdictCard", () => {
    assert.match(content, /<ReleaseVerdictCard\b/)
  })

  it("renders BlockerDiffList with baselineRef wired through", () => {
    assert.match(content, /<BlockerDiffList\b[\s\S]*baselineRef=\{release\.baseline_ref\}/)
  })

  it("renders ImprovementsList", () => {
    assert.match(content, /<ImprovementsList\b/)
  })

  it("does not render action CTAs (Re3 owns Jira/Slack/Fix PR)", () => {
    // Regression guard: this page should NOT render onCreateJiraTicket or
    // onNotifySlack — those CTAs ship with the Re3 actions PR.
    assert.doesNotMatch(content, /onCreateJiraTicket=/)
    assert.doesNotMatch(content, /onNotifySlack=/)
  })

  it("constrains layout to max-w-7xl like other top-level pages", () => {
    assert.match(content, /max-w-7xl/)
  })

  it("links not-found fallback to /releases", () => {
    assert.match(content, /href="\/releases"/)
  })
})

describe("release detail loading skeleton", () => {
  it("exposes an aria-busy region for screen readers", () => {
    assert.match(loading, /aria-busy="true"/)
    assert.match(loading, /aria-label="Loading release scan"/)
  })
})

describe("release detail error boundary", () => {
  it("offers a reset action and a Go to releases CTA", () => {
    assert.match(errorPage, /onClick=\{reset\}/)
    assert.match(errorPage, /href="\/releases"/)
    assert.match(errorPage, /Go to releases/)
  })
})
