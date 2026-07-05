import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RuleEditorModal.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RuleEditorModal imports", () => {
  it("imports SLA_RULE_FIELDS from field-schemas", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bSLA_RULE_FIELDS\b[^}]*\}\s*from\s*["']@\/lib\/rules-engine\/field-schemas["']/,
      "should import SLA_RULE_FIELDS",
    )
  })

  it("imports ConditionBuilder from the shared rules-engine path", () => {
    assert.match(
      src,
      /import\s*\{\s*ConditionBuilder\s*\}\s*from\s*["']@\/components\/shared\/rules-engine\/ConditionBuilder["']/,
      "should import ConditionBuilder from shared path",
    )
  })

  it("imports isSlaAction from the rules api", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bisSlaAction\b[^}]*\}\s*from\s*["']@\/lib\/client\/rules-api["']/,
      "should import isSlaAction",
    )
  })
})

describe("RuleEditorModal tab styling", () => {
  it("uses the underline border-b-2 style for tabs", () => {
    assert.ok(
      src.includes("border-b-2"),
      "should use the underline tab style",
    )
  })

  it("uses the accent color for the active tab border", () => {
    assert.ok(
      src.includes("border-[var(--color-accent)]"),
      "should mark the active tab with the accent border",
    )
  })

  it("wires tablist, tab and tabpanel roles", () => {
    assert.ok(src.includes('role="tablist"'), "should expose a tablist role")
    assert.ok(src.includes('role="tab"'), "should expose tab roles")
    assert.ok(src.includes('role="tabpanel"'), "should expose tabpanel roles")
  })
})

describe("RuleEditorModal validation", () => {
  it("rejects names longer than 200 characters", () => {
    // Regression guard: enforce backend's name length cap.
    assert.match(
      src,
      /trimmedName\.length\s*>\s*200/,
      "should reject names with length > 200",
    )
  })

  it("rejects descriptions longer than 500 characters", () => {
    assert.match(
      src,
      /description\.length\s*>\s*500/,
      "should reject descriptions with length > 500",
    )
  })

  it("rejects deadlines below 1", () => {
    assert.match(
      src,
      /deadline_days\s*<\s*1/,
      "should reject deadlines below 1 day",
    )
  })

  it("no longer validates escalations (coming-soon leg)", () => {
    // Escalations don't deliver, so the editor can't add them and the modal
    // must not block save on their contents.
    assert.ok(
      !/esc\.at_hours\s*<\s*1/.test(src),
      "escalation hours validation should be removed",
    )
    assert.ok(
      !src.includes("errors.escalations"),
      "escalation error rendering should be removed",
    )
  })

  it("no longer requires a scanner-coverage alert channel", () => {
    assert.ok(
      !src.includes("alert_channel_id"),
      "the alert_channel_id requirement should be removed from validation",
    )
  })
})

describe("RuleEditorModal close-path guards", () => {
  it("wires an Escape keydown handler", () => {
    assert.ok(
      src.includes('addEventListener("keydown"'),
      "should register a keydown listener",
    )
    assert.ok(
      src.includes('e.key === "Escape"'),
      "should look for the Escape key",
    )
  })

  it("guards close paths on the saving flag", () => {
    // Regression guard: clicking the backdrop or × while saving must not
    // tear down the modal mid-flight.
    assert.match(
      src,
      /if\s*\(\s*!saving\s*\)/,
      "should not close while saving",
    )
  })
})

describe("RuleEditorModal save-error placement", () => {
  it("renders saveError outside the edit tab conditional", () => {
    // Regression guard: saveError lives in the footer so it stays visible
    // when the user is on the preview tab. The render block must not be
    // gated by activeTab === \"edit\".
    const editPanelStart = src.indexOf('{activeTab === "edit" && (')
    const editPanelEnd = src.indexOf('{activeTab === "preview" && (')
    const saveErrorIdx = src.indexOf("{saveError &&")
    assert.ok(saveErrorIdx > 0, "should render the saveError block")
    assert.ok(
      saveErrorIdx > editPanelEnd,
      "saveError block must be rendered after the preview-tab block (i.e. in the footer)",
    )
    assert.ok(
      saveErrorIdx > editPanelStart,
      "saveError block must not be inside the edit-tab conditional",
    )
  })
})

describe("RuleEditorModal category dispatch", () => {
  it("imports both action editors", () => {
    assert.match(src, /import\s*\{\s*SlaActionEditor\s*\}/)
    assert.match(src, /import\s*\{[^}]*ScannerCoverageActionEditor[^}]*\}\s*from/)
  })

  it("imports the SLA and scanner coverage field schemas", () => {
    assert.match(src, /SLA_RULE_FIELDS/)
    assert.match(src, /SCANNER_COVERAGE_RULE_FIELDS/)
  })

  it("renders SlaActionEditor for sla category", () => {
    assert.match(src, /category === "sla"[\s\S]*<SlaActionEditor/)
  })

  it("renders ScannerCoverageActionEditor for scanner_coverage category", () => {
    assert.match(src, /category === "scanner_coverage"[\s\S]*<ScannerCoverageActionEditor/)
  })

  it("picks the right field schema for ConditionBuilder", () => {
    // The modal dispatches across four categories. Verify all four field
    // schema constants are referenced in the fieldSchema assignment.
    assert.ok(src.includes("SLA_RULE_FIELDS"), "should reference SLA_RULE_FIELDS in fieldSchema")
    assert.ok(
      src.includes("SCANNER_COVERAGE_RULE_FIELDS"),
      "should reference SCANNER_COVERAGE_RULE_FIELDS in fieldSchema",
    )
    assert.ok(
      src.includes("AUTO_DISMISS_RULE_FIELDS"),
      "should reference AUTO_DISMISS_RULE_FIELDS in fieldSchema",
    )
    assert.ok(
      src.includes("DATA_RETENTION_RULE_FIELDS"),
      "should reference DATA_RETENTION_RULE_FIELDS in fieldSchema",
    )
    assert.match(
      src,
      /category === "sla"[\s\S]*\?\s*SLA_RULE_FIELDS[\s\S]*SCANNER_COVERAGE_RULE_FIELDS[\s\S]*DATA_RETENTION_RULE_FIELDS/,
    )
  })

  it("dispatches validation by category", () => {
    assert.match(src, /validateSlaAction/)
    assert.match(src, /validateScannerCoverageAction/)
  })

  it("uses EditableRuleCategory for the prop type", () => {
    assert.match(src, /category: EditableRuleCategory/)
  })

  it("titles the modal correctly per category and mode", () => {
    assert.ok(src.includes("New SLA rule") || src.includes('"New SLA rule"'))
    assert.ok(src.includes("Edit SLA rule") || src.includes('"Edit SLA rule"'))
    assert.ok(src.includes("New scanner coverage rule") || src.includes('"New scanner coverage rule"'))
    assert.ok(src.includes("Edit scanner coverage rule") || src.includes('"Edit scanner coverage rule"'))
  })
})

describe("RuleEditorModal action error blocks are category-guarded", () => {
  it("only renders SLA error blocks when category is sla", () => {
    // The SLA action now surfaces only the deadline error (escalations are a
    // coming-soon leg with no validation), guarded by the sla category.
    assert.match(src, /category === "sla"\s*&&\s*errors\.deadline/)
  })

  it("only renders scanner_coverage error blocks when category is scanner_coverage", () => {
    assert.match(src, /category === "scanner_coverage"\s*&&\s*errors\.scannerCoverage/)
  })
})

describe("RuleEditorModal auto-dismiss imports", () => {
  it("imports AutoDismissActionEditor", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bAutoDismissActionEditor\b[^}]*\}\s*from/,
      "should import AutoDismissActionEditor",
    )
  })

  it("imports AUTO_DISMISS_DEFAULT", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bAUTO_DISMISS_DEFAULT\b[^}]*\}\s*from/,
      "should import AUTO_DISMISS_DEFAULT",
    )
  })

  it("imports AUTO_DISMISS_RULE_FIELDS from field-schemas", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bAUTO_DISMISS_RULE_FIELDS\b[^}]*\}\s*from\s*["']@\/lib\/rules-engine\/field-schemas["']/,
      "should import AUTO_DISMISS_RULE_FIELDS",
    )
  })

  it("imports dryRunAndConfirm from rules-api", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bdryRunAndConfirm\b[^}]*\}\s*from\s*["']@\/lib\/client\/rules-api["']/,
      "should import dryRunAndConfirm from rules-api",
    )
  })
})

describe("RuleEditorModal data retention dispatch", () => {
  it("imports DataRetentionActionEditor and ARCHIVE_DEFAULT", () => {
    assert.match(
      src,
      /import\s*\{[^}]*DataRetentionActionEditor[^}]*ARCHIVE_DEFAULT[^}]*\}\s*from\s*["']\.\/DataRetentionActionEditor["']/,
      "should import DataRetentionActionEditor and ARCHIVE_DEFAULT",
    )
  })

  it("imports DATA_RETENTION_RULE_FIELDS from field-schemas", () => {
    assert.match(
      src,
      /\bDATA_RETENTION_RULE_FIELDS\b/,
      "should import DATA_RETENTION_RULE_FIELDS",
    )
  })

  it("imports isDataRetentionAction and DataRetentionAction type", () => {
    assert.match(src, /\bisDataRetentionAction\b/)
    assert.match(src, /\bDataRetentionAction\b/)
  })

  it("dispatches DataRetentionActionEditor when category is data_retention", () => {
    assert.match(
      src,
      /category === "data_retention"[\s\S]*<DataRetentionActionEditor/,
      "should render DataRetentionActionEditor for data_retention",
    )
  })

  it("uses DATA_RETENTION_RULE_FIELDS in the field schema dispatch", () => {
    assert.match(
      src,
      /SCANNER_COVERAGE_RULE_FIELDS[\s\S]*DATA_RETENTION_RULE_FIELDS/,
      "should pick DATA_RETENTION_RULE_FIELDS for data_retention category",
    )
  })

  it("titles the modal correctly for data_retention", () => {
    assert.ok(src.includes("New data retention rule"), "should expose New data retention rule title")
    assert.ok(src.includes("Edit data retention rule"), "should expose Edit data retention rule title")
  })

  it("loads initial data retention action when editing", () => {
    assert.match(
      src,
      /category === "data_retention"\s*&&\s*isDataRetentionAction\(initialRule\.action\)/,
      "should hydrate from initialRule for data_retention",
    )
  })
})

describe("RuleEditorModal dry-run state", () => {
  it("maintains a dryRunOpen state variable", () => {
    assert.ok(
      src.includes("dryRunOpen"),
      "should have a dryRunOpen state variable for the dry-run dialog",
    )
  })

  it("renders DryRunConfirmDialog", () => {
    assert.match(src, /<DryRunConfirmDialog/, "should render the DryRunConfirmDialog")
  })
})

describe("RuleEditorModal auto-dismiss intercept on enable", () => {
  it("intercepts submit for auto_dismiss in edit mode when enabling", () => {
    assert.match(
      src,
      /category === "auto_dismiss"[\s\S]*?mode === "edit"[\s\S]*?enabled/,
      "should intercept submit for auto_dismiss + edit + enabled",
    )
  })
})

describe("RuleEditorModal auto-dismiss create guard", () => {
  it("forces enabled:false on create for auto_dismiss category", () => {
    assert.ok(
      src.includes("cat !== \"auto_dismiss\"") ||
        src.includes('category === "auto_dismiss" ? false : enabled') ||
        src.includes("effectiveEnabled"),
      "should force enabled:false when creating an auto_dismiss rule",
    )
  })
})

describe("RuleEditorModal auto-dismiss validation", () => {
  it("validates reason length (minimum 3 characters)", () => {
    assert.match(
      src,
      /trimmedReason\.length\s*<\s*3/,
      "should reject reason shorter than 3 characters",
    )
  })

  it("validates reason length (maximum 200 characters)", () => {
    assert.match(
      src,
      /trimmedReason\.length\s*>\s*200/,
      "should reject reason longer than 200 characters",
    )
  })

  it("validates audit_note length (maximum 500 characters)", () => {
    assert.match(
      src,
      /auditNote\.length\s*>\s*500/,
      "should reject audit_note longer than 500 characters",
    )
  })

  it("validates rate_alarm_pct bounds (1–100)", () => {
    assert.match(
      src,
      /rate_alarm_pct\s*<\s*1/,
      "should reject rate_alarm_pct below 1",
    )
    assert.match(
      src,
      /rate_alarm_pct\s*>\s*100/,
      "should reject rate_alarm_pct above 100",
    )
  })

  it("validates rate_alarm_window_minutes bounds (5–10080)", () => {
    assert.match(
      src,
      /rate_alarm_window_minutes\s*<\s*5/,
      "should reject rate_alarm_window_minutes below 5",
    )
    assert.match(
      src,
      /rate_alarm_window_minutes\s*>\s*10080/,
      "should reject rate_alarm_window_minutes above 10080",
    )
  })

  it("renders auto_dismiss error blocks when category is auto_dismiss", () => {
    assert.match(
      src,
      /category === "auto_dismiss"\s*&&\s*errors\.autoDismiss/,
      "should render auto_dismiss error blocks when category is auto_dismiss",
    )
  })
})

describe("RuleEditorModal data retention validation", () => {
  it("validates after_days against the active type floor", () => {
    // Floor depends on action type: 30 archive, 90 delete.
    assert.match(
      src,
      /act\.type === "delete" \? 90 : 30/,
      "should pick floor based on action type",
    )
  })

  it("rejects after_days above 3650", () => {
    assert.match(
      src,
      /act\.after_days\s*>\s*3650/,
      "should reject after_days above 3650",
    )
  })

  it("wires validateDataRetentionAction into validate()", () => {
    assert.match(
      src,
      /validateDataRetentionAction\(action as DataRetentionAction, next\)/,
      "should call validateDataRetentionAction for data_retention category",
    )
  })

  it("renders the data retention after_days error block", () => {
    assert.match(
      src,
      /errors\.dataRetention\?\.after_days/,
      "should render the dataRetention.after_days error",
    )
  })
})

describe("RuleEditorModal typed-confirm gate", () => {
  it("requires typed-confirm before saving a delete data retention rule", () => {
    // Block submit on confirmDeleteAction when the action is delete.
    assert.match(
      src,
      /category === "data_retention"[\s\S]*action as DataRetentionAction\)\.type === "delete"[\s\S]*confirmDeleteAction\(\)/,
      "should gate delete actions behind confirmDeleteAction",
    )
  })

  it("does not require typed-confirm for archive action", () => {
    // The gate must be specifically scoped to type === "delete"; ensure
    // we never gate on `type === "archive"`.
    assert.ok(
      !src.includes('type === "archive"') || !src.includes("confirmDeleteAction") ||
        src.indexOf('type === "archive"') > src.indexOf("confirmDeleteAction"),
    )
    // Defensive: explicit assertion that the gate's condition checks
    // `delete`, not `archive`.
    assert.match(
      src,
      /\(action as DataRetentionAction\)\.type === "delete"/,
      "gate should match on delete, not archive",
    )
  })

  it("uses a Promise-based confirmation flow (not window.confirm)", () => {
    assert.ok(
      !src.includes("window.confirm"),
      "should not use window.confirm — it cannot accept typed input",
    )
    assert.match(
      src,
      /function confirmDeleteAction\(\)\s*:\s*Promise<boolean>/,
      "should expose a Promise-returning confirmation function",
    )
  })

  it("requires the exact confirmation phrase 'delete data retention'", () => {
    assert.match(
      src,
      /deleteConfirmInput !== "delete data retention"/,
      "Confirm button should be disabled unless input equals 'delete data retention'",
    )
  })

  it("uses critical severity styling for the confirmation modal", () => {
    assert.ok(
      src.includes("border-[var(--color-severity-critical)]") &&
        src.includes("bg-[var(--color-severity-critical)]/10"),
      "confirmation modal should use the critical color palette",
    )
  })

  it("closes the typed-confirm modal on Escape", () => {
    assert.match(
      src,
      /deleteConfirmState\.open[\s\S]*resolveDeleteConfirm\(false\)/,
      "Escape should resolve(false) for the typed-confirm modal",
    )
  })
})
