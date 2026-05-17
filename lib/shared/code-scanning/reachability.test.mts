import { describe, it } from "node:test"
import assert from "node:assert/strict"
import type { CodeScanningFinding } from "@/lib/client/code-scanning-client"

describe("CodeScanningFinding.reachability type", () => {
  it("accepts reachable finding with call chain", () => {
    const finding: CodeScanningFinding = {
      identity_key: "k",
      repo_full_name: "org/repo",
      file_path: "src/main.py",
      start_line: 5,
      end_line: 5,
      rule_id: "test.rule",
      rule_name: "Test Rule",
      severity: "high",
      confidence: "medium",
      category: "security",
      cwe: [],
      message: "A problem.",
      snippet: "foo()",
      state: "open",
      reachability: {
        verdict: "reachable",
        entry_point: "main",
        call_chain: [
          { function: "main", file: "src/main.py", line: 1 },
          { function: "foo",  file: "src/main.py", line: 5 },
        ],
      },
    }
    assert.strictEqual(finding.reachability?.verdict, "reachable")
    assert.strictEqual(finding.reachability?.call_chain?.length, 2)
  })

  it("accepts unreachable finding without chain", () => {
    const finding: CodeScanningFinding = {
      identity_key: "k2",
      repo_full_name: "org/repo",
      file_path: "utils/dead.py",
      start_line: 3,
      end_line: 3,
      rule_id: "test.rule",
      rule_name: "Test Rule",
      severity: "low",
      confidence: "low",
      category: "security",
      cwe: [],
      message: "Dead code.",
      snippet: "x()",
      state: "open",
      reachability: { verdict: "unreachable" },
    }
    assert.strictEqual(finding.reachability?.verdict, "unreachable")
    assert.strictEqual(finding.reachability?.call_chain, undefined)
  })

  it("accepts finding with no reachability field", () => {
    const finding: CodeScanningFinding = {
      identity_key: "k3",
      repo_full_name: "org/repo",
      file_path: "src/x.py",
      start_line: 1,
      end_line: 1,
      rule_id: "r",
      rule_name: "R",
      severity: "medium",
      confidence: "medium",
      category: "security",
      cwe: [],
      message: "msg",
      snippet: "",
      state: "open",
    }
    assert.strictEqual(finding.reachability, undefined)
  })
})
