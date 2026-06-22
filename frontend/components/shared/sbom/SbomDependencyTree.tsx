"use client"

import { useMemo, useState } from "react"
import type { CycloneDxComponent } from "@/lib/client/sbom-api"
import { Skeleton } from "@/components/ui/Skeleton"

interface TreeNode {
  ref: string
  name: string
  version: string
  children: TreeNode[]
}

function buildTree(
  rootRef: string,
  depMap: Map<string, string[]>,
  componentMap: Map<string, CycloneDxComponent>,
  visited: Set<string>,
  depth: number,
): TreeNode {
  const comp = componentMap.get(rootRef)
  const name = comp?.name ?? rootRef.split("/").pop() ?? rootRef
  const version = comp?.version ?? ""
  const children: TreeNode[] = []

  // Avoid infinite cycles — depth cap as secondary guard
  if (!visited.has(rootRef) && depth < 6) {
    const childVisited = new Set(visited)
    childVisited.add(rootRef)
    for (const childRef of depMap.get(rootRef) ?? []) {
      children.push(buildTree(childRef, depMap, componentMap, childVisited, depth + 1))
    }
  }

  return { ref: rootRef, name, version, children }
}

function TreeNodeRow({
  node,
  depth,
  defaultExpanded,
}: {
  node: TreeNode
  depth: number
  defaultExpanded: boolean
}) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const hasChildren = node.children.length > 0

  return (
    <li>
      <div
        className={`flex items-center gap-1.5 rounded-lg px-2 py-1 transition-colors hover:bg-[var(--color-surface-raised)] ${depth === 0 ? "font-semibold" : ""}`}
        style={{ paddingLeft: `${8 + depth * 16}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            className="flex h-4 w-4 shrink-0 items-center justify-center rounded text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-accent)]"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            <svg
              className={`h-3 w-3 transition-transform ${expanded ? "rotate-90" : ""}`}
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="m9 18 6-6-6-6" />
            </svg>
          </button>
        ) : (
          <span className="h-4 w-4 shrink-0" />
        )}

        <span className="text-xs text-[var(--color-text-primary)] truncate max-w-[24ch]">
          {node.name}
        </span>
        {node.version && (
          <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]">
            {node.version}
          </code>
        )}
        {hasChildren && (
          <span className="ml-auto shrink-0 rounded-full bg-[var(--color-surface-raised)] px-1.5 py-px font-mono text-[9px] font-semibold text-[var(--color-text-tertiary)]">
            {node.children.length}
          </span>
        )}
      </div>

      {expanded && hasChildren && (
        <ul className="flex flex-col gap-0.5">
          {node.children.map((child) => (
            <TreeNodeRow
              key={child.ref}
              node={child}
              depth={depth + 1}
              defaultExpanded={depth < 1}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export function SbomDependencyTree({
  components,
  dependencies,
  loading,
}: {
  components: CycloneDxComponent[]
  dependencies: Array<{ ref: string; dependsOn?: string[] }>
  loading: boolean
}) {
  const { roots, depMap, componentMap } = useMemo(() => {
    const depMap = new Map<string, string[]>()
    const referencedAsChild = new Set<string>()

    for (const dep of dependencies) {
      depMap.set(dep.ref, dep.dependsOn ?? [])
      for (const child of dep.dependsOn ?? []) {
        referencedAsChild.add(child)
      }
    }

    const componentMap = new Map<string, CycloneDxComponent>()
    for (const c of components) {
      if (c.purl) componentMap.set(c.purl, c)
      componentMap.set(c.name, c)
    }

    // Root nodes are those that appear in depMap but are not a child of any other node
    const allRefs = new Set(depMap.keys())
    const roots = [...allRefs].filter((ref) => !referencedAsChild.has(ref))

    return { roots, depMap, componentMap }
  }, [components, dependencies])

  if (loading) {
    return (
      <div className="flex flex-col gap-2 p-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton
            key={i}
            className="h-6"
            style={{ width: `${60 + (i * 7) % 30}%`, marginLeft: `${(i % 3) * 16}px` }}
          />
        ))}
      </div>
    )
  }

  if (dependencies.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
        <p className="text-sm text-[var(--color-text-secondary)]">No dependency graph data available.</p>
      </div>
    )
  }

  const treeRoots = roots.map((ref) =>
    buildTree(ref, depMap, componentMap, new Set([ref]), 0),
  )

  return (
    <div className="overflow-y-auto py-2">
      <ul className="flex flex-col gap-0.5">
        {treeRoots.map((node) => (
          <TreeNodeRow key={node.ref} node={node} depth={0} defaultExpanded />
        ))}
      </ul>
    </div>
  )
}
