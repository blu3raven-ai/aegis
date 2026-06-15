import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync(
  new URL("./EvidenceSection.tsx", import.meta.url).pathname,
  "utf-8",
);

describe("EvidenceSection llm-disabled hint", () => {
  it("checks for the llm_disabled skip reason on verification metadata", () => {
    assert.match(src, /skipped === "llm_disabled"/);
  });

  it("surfaces a verification-available hint when no verification data is present", () => {
    assert.match(src, /LLM-driven exploit verification is available/);
  });

  it("instructs the user to set LLM_API_KEY to enable verification", () => {
    assert.match(src, /LLM_API_KEY/);
  });

  it("keeps the existing early-return for the no-verification-and-no-hint case", () => {
    // The early-return branch should still trigger when there's no
    // verdict, chain, evidence, ruled-out, metadata AND no llm_disabled
    // hint to render.
    assert.match(src, /if \(!llmDisabled\) return null/);
  });

  it("renders the hint under the same Verification heading the verdict block uses", () => {
    // Both verdict block and hint block should sit under a heading
    // that follows the established type hierarchy (uppercase 2xs tracker).
    const headings = src.match(/text-2xs font-semibold uppercase/g) || [];
    assert.ok(
      headings.length >= 2,
      `expected at least two Verification headings, got ${headings.length}`,
    );
  });
});
