import test from "node:test"
import assert from "node:assert/strict"
import { computeDependencyRoots } from "../../frontend/lib/client/sbom-api.ts"

// ---------------------------------------------------------------------------
// computeDependencyRoots picks the top-level refs for the dependency tree.
// The canonical CycloneDX root's dependsOn ARE the direct deps, so when a root
// is declared the tree must head with exactly those — not the orphan heuristic.
// ---------------------------------------------------------------------------

test("canonical root: tree heads with the root's direct deps", () => {
  const deps = [
    { ref: "root-app", dependsOn: ["react", "lodash"] },
    { ref: "react", dependsOn: ["loose-envify"] },
    { ref: "loose-envify", dependsOn: ["js-tokens"] },
    { ref: "js-tokens", dependsOn: [] },
    { ref: "lodash", dependsOn: [] },
  ]

  const roots = computeDependencyRoots(deps, "root-app")
  assert.deepEqual(roots, ["react", "lodash"])
})

test("canonical root with no dependsOn yields an empty top level", () => {
  const deps = [{ ref: "root-app", dependsOn: [] }]
  assert.deepEqual(computeDependencyRoots(deps, "root-app"), [])
})

test("canonical root absent from graph falls back to the heuristic", () => {
  // rootRef declared in metadata but the graph has no node for it: the
  // heuristic (refs never anyone's child) must still produce a usable tree.
  const deps = [
    { ref: "a", dependsOn: ["b"] },
    { ref: "b", dependsOn: [] },
  ]
  assert.deepEqual(computeDependencyRoots(deps, "missing-root"), ["a"])
})

test("no root declared: heuristic returns refs that are never a child", () => {
  const deps = [
    { ref: "a", dependsOn: ["b", "c"] },
    { ref: "b", dependsOn: ["c"] },
    { ref: "c", dependsOn: [] },
    { ref: "d", dependsOn: ["b"] },
  ]
  // a and d are never depended upon; b and c are.
  assert.deepEqual(computeDependencyRoots(deps, undefined), ["a", "d"])
})

test("heuristic over-reports on a partial graph; canonical root narrows it", () => {
  // A flat graph where the root depends on everything but transitive edges are
  // missing (a common partial-SBOM shape). The heuristic would surface only the
  // root; the canonical path surfaces the true direct deps.
  const deps = [
    { ref: "root-app", dependsOn: ["x", "y", "z"] },
    { ref: "x", dependsOn: [] },
    { ref: "y", dependsOn: [] },
    { ref: "z", dependsOn: [] },
  ]
  assert.deepEqual(computeDependencyRoots(deps, "root-app"), ["x", "y", "z"])
  // Without the root, the heuristic correctly excludes x/y/z (all are children).
  assert.deepEqual(computeDependencyRoots(deps, undefined), ["root-app"])
})

test("missing dependsOn is treated as no children", () => {
  const deps = [{ ref: "solo" }]
  assert.deepEqual(computeDependencyRoots(deps, undefined), ["solo"])
})

test("cyclic graph with no declared root still yields roots without looping", () => {
  const deps = [
    { ref: "a", dependsOn: ["b"] },
    { ref: "b", dependsOn: ["a"] },
    { ref: "entry", dependsOn: ["a"] },
  ]
  // a and b reference each other; only entry is never a child.
  assert.deepEqual(computeDependencyRoots(deps, undefined), ["entry"])
})
