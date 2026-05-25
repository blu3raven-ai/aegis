import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const source = readFileSync(
  new URL("./code-scanning-finding-drawer.tsx", import.meta.url),
  "utf8"
)

test("drawer title uses firstSentence of message, not rule_name", () => {
  assert.match(source, /firstSentence\(finding\.message\)/)
  assert.doesNotMatch(source, /finding\.rule_name/)
})

test("drawer title receives full message as titleTooltip for tooltip", () => {
  assert.match(source, /titleTooltip=\{finding\??\.message\}/)
})

test("drawer imports firstSentence from drawer-helpers", () => {
  assert.match(source, /import.*firstSentence.*from.*drawer-helpers/)
})

test("Code Context section appears before AI Analysis section in JSX", () => {
  const codeContextIdx = source.indexOf("Code Context")
  const aiAnalysisIdx = source.indexOf("AI Analysis")
  assert.ok(
    codeContextIdx < aiAnalysisIdx,
    `Expected Code Context (${codeContextIdx}) before AI Analysis (${aiAnalysisIdx})`
  )
})

test("Location uses compact surface-raised style without heavy border card", () => {
  assert.match(source, /bg-\[var\(--color-surface-raised\)\].*px-3 py-2/)
  // The old pattern was a full bordered card with space-y-2 and "Location" label
  assert.doesNotMatch(source, /space-y-2 rounded-2xl border.*Location/)
})

test("Location block shows only repo name, not file path or line range", () => {
  // File path and lines are already shown in the code block metadata bar
  // Repository and repo_full_name should appear adjacent in the location div
  assert.match(source, /Repository[\s\S]{0,100}repo_full_name/)
})

test("Message card section is removed", () => {
  // The old standalone Message section had a label "Message" above finding.message
  // After redesign, message text only appears via firstSentence in the title
  assert.doesNotMatch(source, /mb-2 text-xs.*uppercase.*Message"\)/)
})

test("CWE renders conditionally only when non-empty", () => {
  assert.match(source, /finding\.cwe\.length > 0/)
  assert.match(source, /label: "CWE"/)
})

test("code block is rendered via DrawerCodeBlock", () => {
  assert.match(source, /DrawerCodeBlock/)
  assert.match(source, /highlightRange=/)
})

test("metadata bar receives file path and line range as DrawerCodeBlock props", () => {
  assert.match(source, /filePath=\{finding\.file_path\}/)
  assert.match(source, /codeStartLine \+ snippetLines\.length - 1/)
})

test("Data Flow section renders conditionally on code_flows", () => {
  assert.match(source, /finding\.code_flows && finding\.code_flows\.length > 0/)
  assert.match(source, /Data Flow/)
})

test("AI Analysis section appears before Data Flow section in JSX", () => {
  const aiAnalysisIdx = source.indexOf("AI Analysis")
  const dataFlowIdx = source.indexOf("Data Flow")
  assert.ok(
    aiAnalysisIdx < dataFlowIdx,
    `Expected AI Analysis (${aiAnalysisIdx}) before Data Flow (${dataFlowIdx})`
  )
})
