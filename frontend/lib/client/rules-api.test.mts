import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./rules-api.ts", import.meta.url).pathname,
  "utf-8",
)

describe("rules-api type-guard exports", () => {
  it("exports the isSlaAction narrowing helper", () => {
    assert.ok(
      src.includes("export function isSlaAction"),
      "should export isSlaAction",
    )
  })

  it("exports the isRequireScannersAction narrowing helper", () => {
    assert.ok(
      src.includes("export function isRequireScannersAction"),
      "should export isRequireScannersAction",
    )
  })

  it("exports the isStaleAlertAction narrowing helper", () => {
    assert.ok(
      src.includes("export function isStaleAlertAction"),
      "should export isStaleAlertAction",
    )
  })

  it("exports the isArchiveAction narrowing helper", () => {
    assert.ok(
      src.includes("export function isArchiveAction"),
      "should export isArchiveAction",
    )
  })

  it("exports the isDeleteAction narrowing helper", () => {
    assert.ok(
      src.includes("export function isDeleteAction"),
      "should export isDeleteAction",
    )
  })

  it("exports the isDataRetentionAction union narrowing helper", () => {
    assert.ok(
      src.includes("export function isDataRetentionAction"),
      "should export isDataRetentionAction",
    )
  })

  it("isRequireScannersAction checks the require_scanners discriminator", () => {
    // Regression guard: the discriminator must be checked literally so
    // misshapen JSONB payloads from the backend don't narrow falsely.
    assert.match(
      src,
      /isRequireScannersAction[\s\S]*?type\s*===\s*"require_scanners"[\s\S]*?Array\.isArray/,
      "should narrow on type === 'require_scanners' and required_scanners array",
    )
  })

  it("isStaleAlertAction checks the stale_alert discriminator and numeric fields", () => {
    assert.match(
      src,
      /isStaleAlertAction[\s\S]*?type\s*===\s*"stale_alert"[\s\S]*?stale_after_days[\s\S]*?alert_channel_id/,
      "should narrow on type === 'stale_alert' and the two numeric fields",
    )
  })
})

describe("rules-api scanner coverage action types", () => {
  it("exports the ScannerType union", () => {
    assert.ok(
      src.includes("export type ScannerType"),
      "should export ScannerType",
    )
  })

  for (const scanner of [
    '"dependencies_scanning"',
    '"code_scanning"',
    '"container_scanning"',
    '"secret_scanning"',
  ]) {
    it(`ScannerType includes ${scanner}`, () => {
      assert.ok(
        src.includes(scanner),
        `ScannerType should include ${scanner}`,
      )
    })
  }

  it("exports RequireScannersAction with the literal discriminator", () => {
    assert.match(
      src,
      /export\s+interface\s+RequireScannersAction\s*\{[\s\S]*?type:\s*"require_scanners"[\s\S]*?required_scanners:\s*ScannerType\[\]/,
      "should export RequireScannersAction with type and required_scanners",
    )
  })

  it("exports StaleAlertAction with all four fields", () => {
    assert.match(
      src,
      /export\s+interface\s+StaleAlertAction\s*\{[\s\S]*?type:\s*"stale_alert"[\s\S]*?stale_after_days:\s*number[\s\S]*?alert_channel_id:\s*number[\s\S]*?auto_retrigger:\s*boolean/,
      "should export StaleAlertAction with type, stale_after_days, alert_channel_id, auto_retrigger",
    )
  })

  it("exports the ScannerCoverageAction discriminated union", () => {
    assert.match(
      src,
      /export\s+type\s+ScannerCoverageAction\s*=\s*RequireScannersAction\s*\|\s*StaleAlertAction/,
      "should export ScannerCoverageAction as RequireScannersAction | StaleAlertAction",
    )
  })

  it("RuleAction union includes ScannerCoverageAction", () => {
    assert.match(
      src,
      /export\s+type\s+RuleAction\s*=[^=]*ScannerCoverageAction/,
      "RuleAction should include ScannerCoverageAction",
    )
  })
})

describe("rules-api data retention action types", () => {
  it("exports ArchiveAction with the literal discriminator", () => {
    assert.match(
      src,
      /export\s+interface\s+ArchiveAction\s*\{[\s\S]*?type:\s*"archive"[\s\S]*?after_days:\s*number/,
      "should export ArchiveAction with type and after_days",
    )
  })

  it("exports DeleteAction with the literal discriminator", () => {
    assert.match(
      src,
      /export\s+interface\s+DeleteAction\s*\{[\s\S]*?type:\s*"delete"[\s\S]*?after_days:\s*number/,
      "should export DeleteAction with type and after_days",
    )
  })

  it("exports the DataRetentionAction discriminated union", () => {
    assert.match(
      src,
      /export\s+type\s+DataRetentionAction\s*=\s*ArchiveAction\s*\|\s*DeleteAction/,
      "should export DataRetentionAction as ArchiveAction | DeleteAction",
    )
  })

  it("RuleAction union includes DataRetentionAction", () => {
    assert.match(
      src,
      /export\s+type\s+RuleAction\s*=[^=]*DataRetentionAction/,
      "RuleAction should include DataRetentionAction",
    )
  })

  it("EditableRuleCategory includes data_retention", () => {
    assert.match(
      src,
      /EditableRuleCategory\s*=\s*Extract<\s*RuleCategory,[^>]*"data_retention"/,
      "EditableRuleCategory should include data_retention",
    )
  })

  it("isArchiveAction checks the archive discriminator", () => {
    assert.match(
      src,
      /isArchiveAction[\s\S]*?type\s*===\s*"archive"[\s\S]*?after_days/,
      "should narrow on type === 'archive' and after_days",
    )
  })

  it("isDeleteAction checks the delete discriminator", () => {
    assert.match(
      src,
      /isDeleteAction[\s\S]*?type\s*===\s*"delete"[\s\S]*?after_days/,
      "should narrow on type === 'delete' and after_days",
    )
  })
})

describe("rules-api payload type names", () => {
  it("exports CreateRulePayload (not RuleCreatePayload)", () => {
    // Regression guard: the payload types renamed during P2 — older
    // names should not reappear via copy-paste.
    assert.match(
      src,
      /export\s+interface\s+CreateRulePayload\b/,
      "should export CreateRulePayload",
    )
    assert.doesNotMatch(
      src,
      /export\s+(interface|type)\s+RuleCreatePayload\b/,
      "should not export the legacy RuleCreatePayload name",
    )
  })

  it("exports UpdateRulePayload (not RuleUpdatePayload)", () => {
    assert.match(
      src,
      /export\s+interface\s+UpdateRulePayload\b/,
      "should export UpdateRulePayload",
    )
    assert.doesNotMatch(
      src,
      /export\s+(interface|type)\s+RuleUpdatePayload\b/,
      "should not export the legacy RuleUpdatePayload name",
    )
  })
})

describe("rules-api function exports", () => {
  for (const fn of [
    "listRules",
    "getRulesSummary",
    "getRule",
    "listRuleViolations",
    "createRule",
    "updateRule",
    "deleteRule",
    "toggleRule",
    "previewRule",
  ]) {
    it(`exports ${fn}`, () => {
      assert.match(
        src,
        new RegExp(`export\\s+async\\s+function\\s+${fn}\\b`),
        `should export ${fn} as an async function`,
      )
    })
  }
})

describe("getRule 404 handling", () => {
  it("returns null when the API responds with 404", () => {
    // Regression guard: callers rely on null to distinguish missing
    // from network errors when prefetching a single rule.
    assert.ok(
      src.includes("ApiClientError"),
      "should check the error against ApiClientError",
    )
    assert.match(
      src,
      /status\s*===\s*404/,
      "should narrow on status === 404",
    )
    assert.match(
      src,
      /return\s+null/,
      "should return null for 404",
    )
  })
})

describe("rules-api base path", () => {
  it("targets the v1 rules base path", () => {
    assert.ok(
      src.includes('"/api/v1/rules"'),
      "should use /api/v1/rules as the base path",
    )
  })
})
