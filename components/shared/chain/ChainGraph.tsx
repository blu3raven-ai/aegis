"use client"

import { useCallback, useMemo } from "react"
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeTypes,
  MarkerType,
  useNodesState,
  useEdgesState,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { ChainListFallback } from "./ChainListFallback"

// ── Node type constants ──────────────────────────────────────────────────────

const SCANNER_CONFIG: Record<
  string,
  { bg: string; fg: string; label: string }
> = {
  Entry:     { bg: "var(--color-scanner-entry-bg)",      fg: "var(--color-scanner-entry-fg)",      label: "Entry"     },
  SAST:      { bg: "var(--color-scanner-sast-bg)",       fg: "var(--color-scanner-sast-fg)",       label: "SAST"      },
  Dep:       { bg: "var(--color-scanner-deps-bg)",       fg: "var(--color-scanner-deps-fg)",       label: "Dep"       },
  Container: { bg: "var(--color-scanner-containers-bg)", fg: "var(--color-scanner-containers-fg)", label: "Container" },
  Secret:    { bg: "var(--color-scanner-secrets-bg)",    fg: "var(--color-scanner-secrets-fg)",    label: "Secret"    },
  Impact:    { bg: "var(--color-scanner-impact-bg)",     fg: "var(--color-scanner-impact-fg)",     label: "Impact"    },
}

const SEV_BORDER: Record<string, string> = {
  critical: "rgba(248,113,113,0.50)",
  high:     "rgba(251,146,60,0.45)",
  medium:   "rgba(251,191,36,0.40)",
  low:      "rgba(96,165,250,0.45)",
}

// ── Custom node renderer ─────────────────────────────────────────────────────

function ChainNode({ data }: { data: ChainNodeData }) {
  const cfg = SCANNER_CONFIG[data.nodeType] ?? SCANNER_CONFIG.Dep
  const borderColor = SEV_BORDER[data.severity ?? "low"] ?? SEV_BORDER.low

  const isImpact = data.nodeType === "Impact"
  const isEntry = data.nodeType === "Entry"

  let nodeBg = "var(--color-surface-raised)"
  if (isImpact) nodeBg = "linear-gradient(135deg, rgba(248,113,113,0.10), rgba(192,132,252,0.06))"
  if (isEntry)  nodeBg = "linear-gradient(135deg, rgba(96,165,250,0.10), rgba(15,188,255,0.04))"

  return (
    <div
      className="w-[200px] rounded-xl border-[1.5px] p-3 shadow-[0_4px_12px_rgba(0,0,0,0.18)] cursor-pointer transition-transform hover:-translate-y-0.5 hover:shadow-[0_8px_20px_rgba(0,0,0,0.30)]"
      style={{
        borderColor,
        background: nodeBg,
      }}
    >
      <div className="mb-2 flex items-center gap-1.5">
        <span
          className="inline-flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded text-[9px] font-bold"
          style={{ background: cfg.bg, color: cfg.fg }}
        >
          {cfg.label.slice(0, 2).toUpperCase()}
        </span>
        <span className="rounded bg-[var(--color-bg-section)] px-1.5 py-px text-[9px] font-bold uppercase tracking-[0.08em] text-[var(--color-text-tertiary)]">
          {data.nodeType}
        </span>
      </div>
      <p className="mb-1.5 text-[12.5px] font-semibold leading-snug text-[var(--color-text-primary)] line-clamp-2">
        {data.title}
      </p>
      {data.meta && (
        <p className="font-[family-name:var(--font-jetbrains-mono)] text-[10.5px] text-[var(--color-text-tertiary)] truncate">
          {data.meta}
        </p>
      )}
      {(data.severity || data.extra) && (
        <div className="mt-2 flex items-center justify-between border-t border-[var(--color-border-divider)] pt-1.5 text-[10.5px] text-[var(--color-text-tertiary)]">
          {data.severity && (
            <span
              className="font-semibold uppercase"
              style={{ color: SEV_BORDER[data.severity] ?? "currentColor" }}
            >
              {data.severity}
            </span>
          )}
          {data.extra && <span>{data.extra}</span>}
        </div>
      )}
    </div>
  )
}

interface ChainNodeData extends Record<string, unknown> {
  nodeType: string
  title: string
  meta?: string
  severity?: string
  extra?: string
}

const nodeTypes: NodeTypes = {
  chainNode: ChainNode as any,
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface ChainGraphNode {
  id: string
  nodeType: "Entry" | "SAST" | "Dep" | "Container" | "Secret" | "Impact" | string
  title: string
  meta?: string
  severity?: string
  extra?: string
  /** Optional explicit position; auto-layouted otherwise */
  x?: number
  y?: number
}

export interface ChainGraphEdge {
  id: string
  source: string
  target: string
  label?: string
  /** 0–1 confidence score from the correlation engine; undefined = unknown */
  confidence?: number
}

interface ChainGraphProps {
  nodes: ChainGraphNode[]
  edges: ChainGraphEdge[]
  chainId: string
  chainType: string
  /** Force list fallback (e.g. a11y preference or >50 nodes) */
  forceFallback?: boolean
}

/** Derive a human-readable confidence label from a 0–1 score. */
function confidenceLabel(score: number): "high" | "medium" | "low" {
  if (score >= 0.85) return "high"
  if (score >= 0.6) return "medium"
  return "low"
}

const CONFIDENCE_LABEL_COLOR: Record<string, string> = {
  high:   "rgba(52,211,153,0.85)",
  medium: "rgba(251,191,36,0.85)",
  low:    "rgba(248,113,113,0.85)",
}

/** Simple left-to-right auto-layout for force-directed approximation. */
function autoLayout(
  rawNodes: ChainGraphNode[],
  rawEdges: ChainGraphEdge[],
): { nodes: Node[]; edges: Edge[] } {
  const NODE_W = 220
  const NODE_H = 130
  const COL_GAP = 80
  const ROW_GAP = 40

  // Build a rough topological layer assignment
  const inDegree: Record<string, number> = {}
  const adj: Record<string, string[]> = {}
  rawNodes.forEach((n) => { inDegree[n.id] = 0; adj[n.id] = [] })
  rawEdges.forEach((e) => {
    inDegree[e.target] = (inDegree[e.target] ?? 0) + 1
    adj[e.source]?.push(e.target)
  })

  const layer: Record<string, number> = {}
  const queue = rawNodes.filter((n) => inDegree[n.id] === 0).map((n) => n.id)
  queue.forEach((id) => { layer[id] = 0 })

  while (queue.length) {
    const cur = queue.shift()!
    for (const next of adj[cur] ?? []) {
      layer[next] = Math.max(layer[next] ?? 0, (layer[cur] ?? 0) + 1)
      queue.push(next)
    }
  }

  // Count nodes per layer for vertical centering
  const layerCounts: Record<number, number> = {}
  rawNodes.forEach((n) => {
    const l = layer[n.id] ?? 0
    layerCounts[l] = (layerCounts[l] ?? 0) + 1
  })
  const layerIndex: Record<number, number> = {}

  const nodes: Node[] = rawNodes.map((n) => {
    const l = layer[n.id] ?? 0
    const idx = layerIndex[l] ?? 0
    layerIndex[l] = idx + 1
    return {
      id: n.id,
      type: "chainNode",
      position: {
        x: n.x ?? l * (NODE_W + COL_GAP) + 40,
        y: n.y ?? idx * (NODE_H + ROW_GAP) + 40,
      },
      data: {
        nodeType: n.nodeType,
        title: n.title,
        meta: n.meta,
        severity: n.severity,
        extra: n.extra,
      },
    }
  })

  const edges: Edge[] = rawEdges.map((e) => {
    // Stroke width scales with confidence: 0.5 → 2.5px, 1.0 → 4px
    const strokeWidth = e.confidence !== undefined ? 1 + e.confidence * 3 : 2
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      labelStyle: {
        fontSize: 10.5,
        fill: "var(--color-text-secondary)",
        fontFamily: "var(--font-jetbrains-mono, monospace)",
      },
      labelBgStyle: {
        fill: "var(--color-surface)",
        stroke: "var(--color-border-medium)",
        strokeWidth: 1,
        rx: 11,
        ry: 11,
      },
      style: {
        stroke: "url(#chain-edge-gradient)",
        strokeWidth,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 14,
        height: 14,
        color: "rgba(192,132,252,0.7)",
      },
    }
  })

  return { nodes, edges }
}

/**
 * Chain attack-graph canvas powered by @xyflow/react.
 *
 * Auto-switches to ChainListFallback when there are >50 nodes or
 * forceFallback is set. Custom node/edge renderers use only existing
 * design tokens — no new colours introduced.
 */
export function ChainGraph({ nodes: rawNodes, edges: rawEdges, chainId, chainType, forceFallback }: ChainGraphProps) {
  const useFallback = forceFallback || rawNodes.length > 50

  const fallbackNodes = useMemo(
    () =>
      rawNodes.map((n) => ({
        id: String(n.id),
        type: n.nodeType,
        title: n.title,
        detail: n.meta,
        severity: n.severity,
      })),
    [rawNodes],
  )

  // Average confidence across all edges that carry a score
  const avgConfidence = useMemo(() => {
    const scored = rawEdges.filter((e) => e.confidence !== undefined)
    if (scored.length === 0) return undefined
    return scored.reduce((sum, e) => sum + (e.confidence ?? 0), 0) / scored.length
  }, [rawEdges])

  const { nodes: laidOut, edges: laidOutEdges } = useMemo(
    () => autoLayout(rawNodes, rawEdges),
    [rawNodes, rawEdges],
  )

  const [nodes, , onNodesChange] = useNodesState(laidOut)
  const [edges, , onEdgesChange] = useEdgesState(laidOutEdges)

  const onInit = useCallback(() => {}, [])

  if (useFallback) {
    return (
      <ChainListFallback
        chainId={chainId}
        chainType={chainType}
        nodes={fallbackNodes}
      />
    )
  }

  return (
    <div
      className="relative flex-1 overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]"
      style={{
        backgroundImage: "radial-gradient(circle, var(--color-border-divider) 1px, transparent 1px)",
        backgroundSize: "20px 20px",
      }}
    >
      {/* Gradient definition for blast-path edges */}
      <svg width="0" height="0" className="absolute" aria-hidden="true">
        <defs>
          <linearGradient id="chain-edge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor="rgba(96,165,250,0.7)" />
            <stop offset="50%"  stopColor="rgba(192,132,252,0.7)" />
            <stop offset="100%" stopColor="rgba(248,113,113,0.9)" />
          </linearGradient>
        </defs>
      </svg>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onInit={onInit}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.3}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="var(--color-border-divider)" />
        <Controls
          className="[&>button]:!bg-[var(--color-surface)] [&>button]:!border-[var(--color-border)] [&>button]:!text-[var(--color-text-secondary)] [&>button:hover]:!text-[var(--color-text-primary)]"
        />
        <MiniMap
          className="!border-[var(--color-border)] !bg-[var(--color-surface)] !rounded-lg"
          nodeColor={() => "var(--color-state-dismissed)"}
          maskColor="rgba(0,0,0,0.12)"
        />
      </ReactFlow>

      {/* Blast-path legend + confidence indicator */}
      <div className="absolute top-3 left-3 flex items-center gap-3 text-[11px] text-[var(--color-text-tertiary)] pointer-events-none">
        <span className="flex items-center gap-1.5">
          <span
            className="inline-block h-0.5 w-12 rounded-full"
            style={{ background: "linear-gradient(90deg, rgba(96,165,250,0.7), rgba(192,132,252,0.7), rgba(248,113,113,0.9))" }}
          />
          Blast path
        </span>
        {avgConfidence !== undefined && (
          <span className="flex items-center gap-1">
            <span className="opacity-50">·</span>
            <span>confidence:</span>
            <span
              className="font-semibold uppercase"
              style={{ color: CONFIDENCE_LABEL_COLOR[confidenceLabel(avgConfidence)] }}
            >
              {confidenceLabel(avgConfidence)}
            </span>
          </span>
        )}
      </div>
    </div>
  )
}
