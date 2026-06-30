import test from "node:test"
import assert from "node:assert/strict"
import {
  buildDependencyTree,
  MAX_TREE_DEPTH,
  type CycloneDxComponent,
} from "../../frontend/lib/client/sbom-api.ts"

// ---------------------------------------------------------------------------
// buildDependencyTree resolves a dependency subtree and records hiddenCount so
// truncation (depth cap / cycle) is visible instead of a capped node rendering
// as a leaf.
// ---------------------------------------------------------------------------

function tree(depMap: Record<string, string[]>, components: CycloneDxComponent[] = []) {
  const dm = new Map(Object.entries(depMap))
  const cm = new Map<string, CycloneDxComponent>()
  for (const c of components) {
    if (c.purl) cm.set(c.purl, c)
    cm.set(c.name, c)
  }
  return buildDependencyTree("root", dm, cm, new Set(), 0)
}

test("expands children and reports hiddenCount 0 when nothing is cut", () => {
  const t = tree({ root: ["a", "b"], a: ["c"], b: [], c: [] })
  assert.deepEqual(t.children.map((n) => n.ref), ["a", "b"])
  assert.equal(t.hiddenCount, 0)
  const a = t.children[0]
  assert.equal(a.children[0].ref, "c")
  assert.equal(a.hiddenCount, 0)
})

test("a node at the depth cap reports its unexpanded children, not a leaf", () => {
  // A straight chain longer than the cap: the node at MAX_TREE_DEPTH has a child
  // it didn't expand, so hiddenCount surfaces it.
  const depMap: Record<string, string[]> = { root: ["d1"] }
  let prev = "d1"
  for (let i = 2; i <= MAX_TREE_DEPTH + 2; i++) {
    depMap[prev] = [`d${i}`]
    prev = `d${i}`
  }
  depMap[prev] = []

  let node = tree(depMap)
  let depth = 0
  while (node.children.length > 0) {
    node = node.children[0]
    depth++
  }
  // Stopped at the cap, and the boundary node flags its hidden child.
  assert.equal(depth, MAX_TREE_DEPTH)
  assert.equal(node.hiddenCount, 1)
})

test("a cycle stops expansion and records the unexpanded edge", () => {
  const t = tree({ root: ["a"], a: ["b"], b: ["a"] })
  // root -> a -> b -> a': the second a is already on the path, so it isn't
  // expanded; its edge back to b is flagged via hiddenCount instead of looping.
  const aRevisited = t.children[0].children[0].children[0]
  assert.equal(aRevisited.ref, "a")
  assert.equal(aRevisited.children.length, 0)
  assert.equal(aRevisited.hiddenCount, 1)
})

test("resolves name and version from the component map", () => {
  const t = tree(
    { root: ["pkg:npm/lodash@4.17.21"], "pkg:npm/lodash@4.17.21": [] },
    [{ name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21" } as CycloneDxComponent],
  )
  assert.equal(t.children[0].name, "lodash")
  assert.equal(t.children[0].version, "4.17.21")
})
