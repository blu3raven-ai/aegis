import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./field-schemas.ts", import.meta.url).pathname,
  "utf-8",
)

describe("NOTIFICATION_ROUTING_FIELDS", () => {
  // Scope assertions to the routing-fields array; the removed values still exist
  // in other rule schemas (SLA / auto-dismiss / retention), which evaluate real
  // Finding objects that carry them.
  const block = src.slice(
    src.indexOf("NOTIFICATION_ROUTING_FIELDS"),
    src.indexOf("SLA_RULE_FIELDS"),
  )

  it("includes severity", () => {
    assert.ok(block.includes('value: "severity"'), "should include severity field")
  })

  it("includes scanner", () => {
    assert.ok(block.includes('value: "scanner"'), "should include scanner field")
  })

  it("omits fields the event payload does not carry", () => {
    for (const field of ["repo_id", "repo_labels", "cve_id", "chain_role"]) {
      assert.ok(
        !block.includes(`value: "${field}"`),
        `${field} is not carried by the finding.created payload and should not be offered as a routing condition`,
      )
    }
  })
})

describe("SLA_RULE_FIELDS", () => {
  it("includes kev_matched", () => {
    assert.ok(src.includes('value: "kev_matched"'), "should include kev_matched field")
  })

  it("includes cwe_id", () => {
    assert.ok(src.includes('value: "cwe_id"'), "should include cwe_id field")
  })

  it("includes file_path", () => {
    assert.ok(src.includes('value: "file_path"'), "should include file_path field")
  })

  it("includes age_days", () => {
    assert.ok(src.includes('value: "age_days"'), "should include age_days field")
  })
})

describe("SCANNER_COVERAGE_RULE_FIELDS", () => {
  it("declares the schema export", () => {
    assert.ok(
      src.includes("export const SCANNER_COVERAGE_RULE_FIELDS"),
      "should export SCANNER_COVERAGE_RULE_FIELDS",
    )
  })

  for (const field of [
    "tier",
    "repo_labels",
    "archived",
    "image_registry",
    "last_scan_age_days",
  ]) {
    it(`includes ${field}`, () => {
      assert.ok(
        src.includes(`value: "${field}"`),
        `should include ${field} field`,
      )
    })
  }

  it("offers tier suggestions covering production/staging/development", () => {
    const tierLines = src
      .split("\n")
      .filter((l) => l.includes('value: "tier"'))
    assert.ok(tierLines.length > 0, "should declare a tier field")
    tierLines.forEach((line) => {
      assert.ok(line.includes('"production"'), "tier field should include 'production'")
      assert.ok(line.includes('"staging"'), "tier field should include 'staging'")
      assert.ok(line.includes('"development"'), "tier field should include 'development'")
    })
  })
})

describe("DATA_RETENTION_RULE_FIELDS", () => {
  it("declares the schema export", () => {
    assert.ok(
      src.includes("export const DATA_RETENTION_RULE_FIELDS"),
      "should export DATA_RETENTION_RULE_FIELDS",
    )
  })

  for (const field of ["tool", "repo_id", "age_days"]) {
    it(`includes ${field}`, () => {
      assert.ok(
        src.includes(`value: "${field}"`),
        `should include ${field} field`,
      )
    })
  }

  it("does not surface scan_id as a rule-builder field", () => {
    // Regression guard: scan_id is the subject identifier, not a useful
    // condition; surfacing it would mislead users into per-scan rules.
    const block = src.slice(src.indexOf("DATA_RETENTION_RULE_FIELDS"))
    const end = block.indexOf("]")
    const slice = block.slice(0, end)
    assert.ok(!slice.includes('value: "scan_id"'), "should omit scan_id")
    assert.ok(!slice.includes('value: "finished_at"'), "should omit finished_at")
  })

  it("offers tool suggestions covering all four scanner kinds", () => {
    const toolLines = src
      .split("\n")
      .filter((l) => l.includes('value: "tool"'))
    assert.ok(toolLines.length > 0, "should declare a tool field")
    toolLines.forEach((line) => {
      assert.ok(line.includes('"dependencies_scanning"'), "tool field should include 'dependencies'")
      assert.ok(line.includes('"code_scanning"'), "tool field should include 'code_scanning'")
      assert.ok(line.includes('"container_scanning"'), "tool field should include 'container_scanning'")
      assert.ok(line.includes('"secret_scanning"'), "tool field should include 'secrets'")
    })
  })
})

describe("AUTO_DISMISS_RULE_FIELDS", () => {
  it("includes dependency_scope with dev/prod suggestions", () => {
    const line = src
      .split("\n")
      .find((l) => l.includes('value: "dependency_scope"'))
    assert.ok(line, "auto-dismiss rules should offer dependency_scope")
    assert.ok(line!.includes('"dev"') && line!.includes('"prod"'), "should suggest dev/prod")
  })

  it("includes release_age_days as a numeric field", () => {
    const line = src
      .split("\n")
      .find((l) => l.includes('value: "release_age_days"'))
    assert.ok(line, "auto-dismiss rules should offer release_age_days")
    assert.ok(line!.includes('inputType: "number"'), "release_age_days should be numeric")
  })
})

describe("field value suggestions", () => {
  it("binds severity to a suggestions list that includes critical", () => {
    // Regression guard: severity dropdowns must offer the canonical
    // severity values so users don't have to memorise them.
    const severityLines = src
      .split("\n")
      .filter((l) => l.includes('value: "severity"'))
    assert.ok(severityLines.length > 0, "should declare a severity field")
    severityLines.forEach((line) => {
      assert.ok(line.includes('"critical"'), "severity field should include 'critical'")
    })
  })

  it("binds scanner to a suggestions list that includes dependencies", () => {
    const scannerLines = src
      .split("\n")
      .filter((l) => l.includes('value: "scanner"'))
    assert.ok(scannerLines.length > 0, "should declare a scanner field")
    scannerLines.forEach((line) => {
      assert.ok(line.includes('"dependencies_scanning"'), "scanner field should include 'dependencies'")
    })
  })
})
