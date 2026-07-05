import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ConditionBuilder.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ConditionBuilder imports", () => {
  it("imports condition types from @/lib/rules-engine/conditions", () => {
    // Regression guard: ConditionBuilder must NOT depend on the older
    // notification-rules-api types — that coupling was removed when the
    // component moved to the shared rules-engine path.
    assert.match(
      src,
      /from\s*["']@\/lib\/rules-engine\/conditions["']/,
      "should import from @/lib/rules-engine/conditions",
    )
  })

  it("does not import from notification-rules-api", () => {
    assert.doesNotMatch(
      src,
      /from\s*["']@\/lib\/client\/notification-rules-api["']/,
      "should not depend on notification-rules-api",
    )
  })
})

describe("ConditionBuilder props", () => {
  it("exposes a fields prop on ConditionBuilderProps", () => {
    assert.match(
      src,
      /fields:\s*ConditionFieldSchema\[\]/,
      "should declare a fields prop",
    )
  })

  it("exposes an optional operatorsForField prop", () => {
    assert.match(
      src,
      /operatorsForField\?:/,
      "should declare an optional operatorsForField prop",
    )
  })
})

describe("ConditionBuilder has no hard-coded option lists", () => {
  it("does not define a module-level SEVERITY_VALUES const", () => {
    // Regression guard: severity options must come from the fields prop,
    // not from a hard-coded module-level array.
    assert.doesNotMatch(
      src,
      /^const\s+SEVERITY_VALUES/m,
      "should not hard-code SEVERITY_VALUES",
    )
  })

  it("does not define a module-level SCANNER_VALUES const", () => {
    assert.doesNotMatch(
      src,
      /^const\s+SCANNER_VALUES/m,
      "should not hard-code SCANNER_VALUES",
    )
  })

  it("does not define a module-level CHAIN_ROLE_VALUES const", () => {
    assert.doesNotMatch(
      src,
      /^const\s+CHAIN_ROLE_VALUES/m,
      "should not hard-code CHAIN_ROLE_VALUES",
    )
  })

  it("does not define a module-level FIELD_OPTIONS const", () => {
    assert.doesNotMatch(
      src,
      /^const\s+FIELD_OPTIONS/m,
      "should not hard-code FIELD_OPTIONS",
    )
  })
})

describe("ConditionBuilder addLeaf default value", () => {
  it("sources the default leaf value from valueSuggestions", () => {
    // Regression guard: adding a leaf must seed the value from the field's
    // suggestion list when one exists, so the user sees a valid default.
    assert.match(
      src,
      /valueSuggestions\[0\]/,
      "should use valueSuggestions[0] as the default value",
    )
  })

  it("defaults boolean fields to true", () => {
    // Regression guard for Task 2 fix: boolean fields with no valueSuggestions
    // should default to `true`, not `""`, so the boolean <select> renders a
    // non-empty value.
    assert.match(
      src,
      /inputType\s*===\s*["']boolean["'][\s\S]{0,80}defaultValue\s*=\s*true|defaultValue\s*=\s*true[\s\S]{0,80}inputType\s*===\s*["']boolean["']/,
      "should default boolean leaf to true",
    )
  })
})

describe("ConditionBuilder operator fallback", () => {
  it("falls back to OP_OPTIONS when operatorsForField returns empty", () => {
    // Regression guard: avoid an empty <select> when a caller's
    // operatorsForField hook returns no ops for a field.
    assert.match(
      src,
      /filteredOps\.length\s*>\s*0\s*\?\s*filteredOps\s*:\s*OP_OPTIONS/,
      "should fall back to OP_OPTIONS when filteredOps is empty",
    )
  })
})
