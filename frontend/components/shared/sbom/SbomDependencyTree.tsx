"use client"

import { useCallback, useMemo, useRef, useState, type KeyboardEvent } from "react"
import {
  buildDependencyTree,
  computeDependencyRoots,
  type CycloneDxComponent,
  type DependencyTreeNode,
} from "@/lib/client/sbom-api"
import { Skeleton } from "@/components/ui/Skeleton"

type TreeNode = DependencyTreeNode

interface FlatNode {
  uid: string
  node: TreeNode
  depth: number
  parentUid: string | null
  hasChildren: boolean
  expanded: boolean
}

// A ref can appear under multiple parents, so identity is the PATH, not the ref.
// The uid formula must match exactly between flatten() (used for keyboard nav)
// and the recursive render (used for the DOM) so focus lookups line up.
function uidFor(parentUid: string | null, idx: number, ref: string): string {
  return parentUid ? `${parentUid}>${idx}:${ref}` : `${idx}:${ref}`
}

// Depth-first list of currently-visible nodes (children only under expanded
// parents) — the linear order the Up/Down arrow keys walk.
function flatten(roots: TreeNode[], expanded: Set<string>): FlatNode[] {
  const out: FlatNode[] = []
  const walk = (node: TreeNode, depth: number, parentUid: string | null, idx: number) => {
    const uid = uidFor(parentUid, idx, node.ref)
    const hasChildren = node.children.length > 0
    const isExpanded = expanded.has(uid)
    out.push({ uid, node, depth, parentUid, hasChildren, expanded: isExpanded })
    if (hasChildren && isExpanded) {
      node.children.forEach((c, i) => walk(c, depth + 1, uid, i))
    }
  }
  roots.forEach((r, i) => walk(r, 0, null, i))
  return out
}

function TreeNodeRow({
  node,
  depth,
  uid,
  expanded,
  activeUid,
  onKeyDown,
  onRowClick,
}: {
  node: TreeNode
  depth: number
  uid: string
  expanded: Set<string>
  activeUid: string | null
  onKeyDown: (e: KeyboardEvent<HTMLLIElement>, uid: string) => void
  onRowClick: (uid: string, hasChildren: boolean) => void
}) {
  const hasChildren = node.children.length > 0
  const isExpanded = expanded.has(uid)
  const isTruncated = !hasChildren && node.hiddenCount > 0
  const isActive = uid === activeUid

  return (
    <li
      role="treeitem"
      aria-expanded={hasChildren ? isExpanded : undefined}
      // Roving tabindex: exactly one node is in the tab order; the arrow keys
      // move focus between nodes. Only handle keys that land on this node, not
      // ones bubbling up from a focused descendant.
      tabIndex={isActive ? 0 : -1}
      data-uid={uid}
      onKeyDown={(e) => {
        if (e.target === e.currentTarget) onKeyDown(e, uid)
      }}
      className="group/row outline-none"
    >
      <div
        onClick={() => onRowClick(uid, hasChildren)}
        className={`flex min-h-[30px] items-center gap-1.5 rounded-lg px-2 py-1.5 transition-colors hover:bg-[var(--color-surface-raised)] group-focus-visible/row:ring-1 group-focus-visible/row:ring-inset group-focus-visible/row:ring-[var(--color-accent)] ${hasChildren ? "cursor-pointer" : ""} ${depth === 0 ? "font-semibold" : ""}`}
        style={{ paddingLeft: `${8 + depth * 16}px` }}
      >
        {hasChildren ? (
          <span className="flex h-4 w-4 shrink-0 items-center justify-center text-[var(--color-text-tertiary)]" aria-hidden="true">
            <svg
              className={`h-3 w-3 transition-transform ${isExpanded ? "rotate-90" : ""}`}
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="m9 18 6-6-6-6" />
            </svg>
          </span>
        ) : (
          <span className="h-4 w-4 shrink-0" />
        )}

        <span className="text-xs text-[var(--color-text-primary)] truncate max-w-[24ch]" title={node.name}>
          {node.name}
        </span>
        {node.version && (
          <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]">
            {node.version}
          </code>
        )}
        {hasChildren && (
          <span className="ml-auto shrink-0 rounded-full bg-[var(--color-surface-raised)] px-1.5 py-px font-mono text-2xs font-semibold text-[var(--color-text-tertiary)]">
            {node.children.length}
          </span>
        )}
        {isTruncated && (
          <span
            className="ml-auto shrink-0 rounded-full bg-[var(--color-surface-raised)] px-1.5 py-px font-mono text-2xs font-semibold text-[var(--color-text-tertiary)]"
            title={`${node.hiddenCount} nested ${node.hiddenCount === 1 ? "dependency" : "dependencies"} not shown (depth limit)`}
          >
            +{node.hiddenCount}…
          </span>
        )}
      </div>

      {isExpanded && hasChildren && (
        <ul role="group" className="flex flex-col gap-0.5">
          {node.children.map((child, i) => {
            const childUid = uidFor(uid, i, child.ref)
            return (
              <TreeNodeRow
                key={childUid}
                node={child}
                depth={depth + 1}
                uid={childUid}
                expanded={expanded}
                activeUid={activeUid}
                onKeyDown={onKeyDown}
                onRowClick={onRowClick}
              />
            )
          })}
        </ul>
      )}
    </li>
  )
}

export function SbomDependencyTree({
  components,
  dependencies,
  loading,
  rootRef,
}: {
  components: CycloneDxComponent[]
  dependencies: Array<{ ref: string; dependsOn?: string[] }>
  loading: boolean
  /** The CycloneDX root (metadata.component bom-ref), when the SBOM declares one. */
  rootRef?: string
}) {
  const treeRoots = useMemo(() => {
    const depMap = new Map<string, string[]>()
    for (const dep of dependencies) {
      depMap.set(dep.ref, dep.dependsOn ?? [])
    }
    const componentMap = new Map<string, CycloneDxComponent>()
    for (const c of components) {
      // The graph references components by bom-ref (dependsOn / metadata.component
      // bom-ref), which often differs from the purl — index it first so tree
      // nodes resolve their real name/version instead of falling back to the ref.
      if (c.bomRef) componentMap.set(c.bomRef, c)
      if (c.purl) componentMap.set(c.purl, c)
      componentMap.set(c.name, c)
    }
    const roots = computeDependencyRoots(dependencies, rootRef)
    // Seed `visited` empty so each root expands its own dependencies; the
    // recursion adds each ref to the path before descending, so a self- or
    // back-edge is still caught one level down.
    return roots.map((ref) => buildDependencyTree(ref, depMap, componentMap, new Set(), 0))
  }, [components, dependencies, rootRef])

  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [activeUid, setActiveUid] = useState<string | null>(null)
  const containerRef = useRef<HTMLUListElement>(null)

  const flat = useMemo(() => flatten(treeRoots, expanded), [treeRoots, expanded])

  // Keep a valid roving-focus target as the visible set changes (a collapse can
  // remove the active node); fall back to the first node so Tab always lands.
  const effectiveActiveUid = useMemo(() => {
    if (activeUid && flat.some((f) => f.uid === activeUid)) return activeUid
    return flat[0]?.uid ?? null
  }, [activeUid, flat])

  const focusUid = useCallback((uid: string) => {
    setActiveUid(uid)
    // Defer until the roving tabIndex has updated, then move DOM focus.
    requestAnimationFrame(() => {
      containerRef.current
        ?.querySelector<HTMLElement>(`[data-uid="${CSS.escape(uid)}"]`)
        ?.focus()
    })
  }, [])

  const setOpen = useCallback((uid: string, next?: boolean) => {
    setExpanded((prev) => {
      const s = new Set(prev)
      const open = next ?? !s.has(uid)
      if (open) s.add(uid)
      else s.delete(uid)
      return s
    })
  }, [])

  const onRowClick = useCallback(
    (uid: string, hasChildren: boolean) => {
      focusUid(uid)
      if (hasChildren) setOpen(uid)
    },
    [focusUid, setOpen],
  )

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLLIElement>, uid: string) => {
      const idx = flat.findIndex((f) => f.uid === uid)
      if (idx < 0) return
      const f = flat[idx]
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault()
          if (flat[idx + 1]) focusUid(flat[idx + 1].uid)
          break
        case "ArrowUp":
          e.preventDefault()
          if (flat[idx - 1]) focusUid(flat[idx - 1].uid)
          break
        case "Home":
          e.preventDefault()
          if (flat[0]) focusUid(flat[0].uid)
          break
        case "End":
          e.preventDefault()
          if (flat.length) focusUid(flat[flat.length - 1].uid)
          break
        case "ArrowRight":
          e.preventDefault()
          if (f.hasChildren && !f.expanded) setOpen(f.uid, true)
          else if (f.hasChildren && f.expanded && flat[idx + 1]) focusUid(flat[idx + 1].uid)
          break
        case "ArrowLeft":
          e.preventDefault()
          if (f.hasChildren && f.expanded) setOpen(f.uid, false)
          else if (f.parentUid) focusUid(f.parentUid)
          break
        case "Enter":
        case " ":
          if (f.hasChildren) {
            e.preventDefault()
            setOpen(f.uid)
          }
          break
      }
    },
    [flat, focusUid, setOpen],
  )

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

  // Dependency edges exist but no entry point could be derived (every ref is
  // referenced as a child, or the graph is a pure cycle) — say so rather than
  // render an empty tree that reads as "no data".
  if (treeRoots.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
        <p className="text-sm text-[var(--color-text-secondary)]">
          Dependency relationships couldn&apos;t be resolved into a tree for this SBOM.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-y-auto py-2">
      <ul ref={containerRef} role="tree" aria-label="Dependency graph" className="flex flex-col gap-0.5">
        {treeRoots.map((node, i) => {
          const uid = uidFor(null, i, node.ref)
          return (
            <TreeNodeRow
              key={uid}
              node={node}
              depth={0}
              uid={uid}
              expanded={expanded}
              activeUid={effectiveActiveUid}
              onKeyDown={onKeyDown}
              onRowClick={onRowClick}
            />
          )
        })}
      </ul>
    </div>
  )
}
