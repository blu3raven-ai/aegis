import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./CommandBar.tsx", import.meta.url).pathname,
  "utf-8",
)
const types = readFileSync(
  new URL("./types.ts", import.meta.url).pathname,
  "utf-8",
)

describe("CommandBar (shared)", () => {
  it("composes FilterChip and ValuePicker", () => {
    assert.match(src, /import \{ FilterChip \}/)
    assert.match(src, /import \{ ValuePicker \}/)
  })

  it("treats boolean attributes as immediate-apply toggles (skips the value picker)", () => {
    assert.match(src, /def\.type === "boolean"/)
    assert.match(src, /onChange\(key,\s*"true"\)/)
  })

  it("hides the search input when onSearchInputChange is not provided", () => {
    assert.match(src, /const isSearchEnabled = onSearchInputChange != null/)
    assert.match(src, /\{isSearchEnabled && \(/)
  })

  it("supports a customPickers override keyed by attribute", () => {
    assert.match(types, /customPickers\?: Record<string, ComponentType/)
    assert.match(src, /customPickers\?\.\[def\.key\]/)
  })

  it("formats the chip value via the optional displayValue function", () => {
    assert.match(src, /def\.displayValue\(raw\)/)
  })

  it("slots the page-specific displayOverflow component to the right of the bar", () => {
    assert.match(src, /\{displayOverflow\}/)
  })

  it("opens the typeahead on focus (no separate + Filter button)", () => {
    assert.match(src, /onFocus=\{\(\) => setOpenPicker\("typeahead"\)\}/)
    assert.doesNotMatch(src, /import \{ AttributePicker \}/)
    assert.doesNotMatch(src, /aria-label="Add filter"/)
  })

  it("lists every non-used attribute when the search query is empty", () => {
    assert.match(src, /const available = attributes\.filter\(\(a\) => !usedKeys\.has\(a\.key\)\)/)
    assert.match(src, /if \(!typeaheadQuery\) return available/)
  })

  it("filters typeahead matches by label or description and excludes already-used attributes", () => {
    assert.match(src, /a\.label\.toLowerCase\(\)\.includes\(typeaheadQuery\)/)
    assert.match(src, /a\.description\.toLowerCase\(\)\.includes\(typeaheadQuery\)/)
    assert.match(src, /!usedKeys\.has\(a\.key\)/)
  })

  it("supports ArrowDown / ArrowUp / Escape on the search input for typeahead navigation", () => {
    assert.match(src, /e\.key === "ArrowDown"/)
    assert.match(src, /e\.key === "ArrowUp"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("Enter accepts the highlighted (or implicit first) typeahead match; falls back to onSearchSubmit otherwise", () => {
    assert.match(src, /if \(e\.key === "Enter"\) \{/)
    assert.match(src, /handleTypeaheadPick\(typeaheadMatches\[idx\]\.key\)/)
    assert.match(src, /onSearchSubmit\?\.\(\)/)
  })

  it("does not bind Tab as an accept key (Tab keeps its default focus-out behaviour per WAI-ARIA combobox spec)", () => {
    assert.doesNotMatch(src, /e\.key === "Tab"/)
  })

  it("auto-highlights the first match while the user is typing so Enter can accept it without arrow-down", () => {
    assert.match(src, /if \(typeaheadQuery && highlightedIdx < 0\) \{\s*\n?\s*setHighlightedIdx\(0\)/)
  })

  it("sets aria-activedescendant on the input to the highlighted option's id for screen readers", () => {
    assert.match(src, /aria-activedescendant=\{activeOptionId\}/)
    assert.match(src, /`command-bar-typeahead-option-\$\{highlightedIdx\}`/)
  })

  it("renders a no-matches status node when the user's query has no matching attributes", () => {
    assert.match(src, /role="status"/)
    assert.match(src, /aria-live="polite"/)
    assert.match(src, /No matching filters/)
  })

  it("clears the search input when a typeahead row is picked so it doesn't double as a keyword", () => {
    assert.match(src, /onSearchInputChange\?\.\(""\)/)
  })

  it("only shows the keyword-search footer hint when there's a typed query", () => {
    assert.match(src, /\{typeaheadQuery && \(/)
  })

  it("renders a placeholder chip + value picker for the just-picked attribute (pending state)", () => {
    assert.match(src, /pendingPickAttr/)
    assert.match(src, /values\[openPicker\] != null\) return null/)
    assert.match(src, /\[\.\.\.activeAttrs, pendingPickAttr\]/)
    assert.match(src, /const isPending = raw == null/)
  })

  it("dismisses the placeholder chip on Remove without committing a value", () => {
    assert.match(src, /if \(isPending\) \{\s*\n?\s*\/\/[^\n]*\n?\s*setOpenPicker\(null\)/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
