import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Unit tests for the ConditionBuilder logic — tested through the API type
// definitions and the routing engine's evaluate_condition semantics.
//
// These tests focus on condition tree structure correctness: the shapes
// that ConditionBuilder produces must be accepted by the backend's
// evaluate_condition without error.
// ---------------------------------------------------------------------------

// Re-implement the minimal evaluator inline so we can test tree shapes
// without importing the React component (no DOM in Node test runner).

type Op = "eq" | "neq" | "in" | "nin" | "contains" | "not_contains" | "gt" | "gte" | "lt" | "lte"
type Field = "severity" | "scanner" | "repo_id" | "repo_labels" | "cve_id" | "chain_role"

interface LeafCond { field: Field; op: Op; value: string | string[] }
interface AllCond { all: Cond[] }
interface AnyCond { any: Cond[] }
type Cond = LeafCond | AllCond | AnyCond | Record<string, never>

interface Finding {
  severity: string
  scanner: string
  repo_id: string
  repo_labels: string[]
  cve_id: string | null
  chain_role: string | null
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1,
}

function getField(f: Finding, name: string): unknown {
  const valid = new Set(["severity", "scanner", "repo_id", "repo_labels", "cve_id", "chain_role"])
  if (!valid.has(name)) throw new Error(`unknown field: ${name}`)
  return (f as unknown as Record<string, unknown>)[name]
}

function applyOp(op: string, fv: unknown, rv: unknown): boolean {
  if (op === "eq") return fv === rv
  if (op === "neq") return fv !== rv
  if (op === "in") return (rv as unknown[]).includes(fv)
  if (op === "nin") return !(rv as unknown[]).includes(fv)
  if (op === "contains") return Array.isArray(fv) ? (fv as unknown[]).includes(rv) : String(fv).includes(String(rv))
  if (op === "not_contains") return Array.isArray(fv) ? !(fv as unknown[]).includes(rv) : !String(fv).includes(String(rv))
  const lhs = typeof fv === "string" ? (SEVERITY_RANK[fv] ?? 0) : (fv as number)
  const rhs = typeof rv === "string" ? (SEVERITY_RANK[rv as string] ?? 0) : (rv as number)
  if (op === "gt") return lhs > rhs
  if (op === "gte") return lhs >= rhs
  if (op === "lt") return lhs < rhs
  if (op === "lte") return lhs <= rhs
  throw new Error(`unknown op: ${op}`)
}

function evaluate(cond: Cond, f: Finding): boolean {
  if (!cond || Object.keys(cond).length === 0) return true
  if ("all" in cond) return ((cond as AllCond).all).every((c) => evaluate(c, f))
  if ("any" in cond) {
    const children = (cond as AnyCond).any
    return children.length === 0 ? true : children.some((c) => evaluate(c, f))
  }
  const { field, op, value } = cond as LeafCond
  return applyOp(op, getField(f, field), value)
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "medium",
    scanner: "dependencies_scanning",
    repo_id: "r1",
    repo_labels: [],
    cve_id: null,
    chain_role: null,
    ...overrides,
  }
}

// ── Empty and trivial trees ───────────────────────────────────────────────────

test("empty condition evaluates to true (catch-all)", () => {
  assert.equal(evaluate({}, finding()), true)
})

test("empty all group evaluates to true (vacuous and)", () => {
  assert.equal(evaluate({ all: [] }, finding()), true)
})

test("empty any group evaluates to true (vacuous or)", () => {
  assert.equal(evaluate({ any: [] }, finding()), true)
})

// ── Single leaf conditions ────────────────────────────────────────────────────

test("leaf eq: severity matches", () => {
  assert.equal(evaluate({ field: "severity", op: "eq", value: "critical" }, finding({ severity: "critical" })), true)
})

test("leaf eq: severity mismatch", () => {
  assert.equal(evaluate({ field: "severity", op: "eq", value: "critical" }, finding({ severity: "high" })), false)
})

test("leaf in: scanner in list", () => {
  assert.equal(
    evaluate({ field: "scanner", op: "in", value: ["secret_scanning", "code_scanning"] }, finding({ scanner: "secret_scanning" })),
    true,
  )
})

test("leaf nin: scanner not in list", () => {
  assert.equal(
    evaluate({ field: "scanner", op: "nin", value: ["secret_scanning"] }, finding({ scanner: "dependencies_scanning" })),
    true,
  )
})

test("leaf contains: repo_labels list contains value", () => {
  assert.equal(
    evaluate({ field: "repo_labels", op: "contains", value: "production" }, finding({ repo_labels: ["production", "backend"] })),
    true,
  )
})

test("leaf not_contains: repo_labels does not contain value", () => {
  assert.equal(
    evaluate({ field: "repo_labels", op: "not_contains", value: "production" }, finding({ repo_labels: ["staging"] })),
    true,
  )
})

test("leaf gt: critical > high using severity rank", () => {
  assert.equal(
    evaluate({ field: "severity", op: "gt", value: "high" }, finding({ severity: "critical" })),
    true,
  )
})

test("leaf lte: medium <= high", () => {
  assert.equal(
    evaluate({ field: "severity", op: "lte", value: "high" }, finding({ severity: "medium" })),
    true,
  )
})

// ── Compound trees ───────────────────────────────────────────────────────────

test("all group: both leaves true", () => {
  assert.equal(
    evaluate(
      {
        all: [
          { field: "severity", op: "eq", value: "critical" },
          { field: "scanner", op: "eq", value: "secret_scanning" },
        ],
      },
      finding({ severity: "critical", scanner: "secret_scanning" }),
    ),
    true,
  )
})

test("all group: one leaf false makes whole group false", () => {
  assert.equal(
    evaluate(
      {
        all: [
          { field: "severity", op: "eq", value: "critical" },
          { field: "scanner", op: "eq", value: "secret_scanning" },
        ],
      },
      finding({ severity: "high", scanner: "secret_scanning" }),
    ),
    false,
  )
})

test("any group: one leaf true satisfies the group", () => {
  assert.equal(
    evaluate(
      {
        any: [
          { field: "severity", op: "eq", value: "critical" },
          { field: "scanner", op: "eq", value: "secret_scanning" },
        ],
      },
      finding({ severity: "medium", scanner: "secret_scanning" }),
    ),
    true,
  )
})

test("nested all inside any: inner group matches", () => {
  const cond: Cond = {
    any: [
      {
        all: [
          { field: "severity", op: "eq", value: "critical" },
          { field: "repo_labels", op: "contains", value: "production" },
        ],
      },
      { field: "scanner", op: "eq", value: "secret_scanning" },
    ],
  }
  assert.equal(
    evaluate(cond, finding({ severity: "critical", repo_labels: ["production"], scanner: "code_scanning" })),
    true,
  )
})

test("nested any inside all: neither branch matches → false", () => {
  const cond: Cond = {
    all: [
      { field: "severity", op: "eq", value: "critical" },
      {
        any: [
          { field: "scanner", op: "eq", value: "secret_scanning" },
          { field: "scanner", op: "eq", value: "code_scanning" },
        ],
      },
    ],
  }
  // severity matches but scanner doesn't match any branch
  assert.equal(
    evaluate(cond, finding({ severity: "critical", scanner: "dependencies_scanning" })),
    false,
  )
})

// ── Field coverage ────────────────────────────────────────────────────────────

test("cve_id field: eq match", () => {
  assert.equal(
    evaluate({ field: "cve_id", op: "eq", value: "CVE-2024-12345" }, finding({ cve_id: "CVE-2024-12345" })),
    true,
  )
})

test("chain_role field: in match", () => {
  assert.equal(
    evaluate({ field: "chain_role", op: "in", value: ["entrypoint", "sink"] }, finding({ chain_role: "sink" })),
    true,
  )
})

test("repo_id field: neq match", () => {
  assert.equal(
    evaluate({ field: "repo_id", op: "neq", value: "repo-excluded" }, finding({ repo_id: "repo-other" })),
    true,
  )
})
