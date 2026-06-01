/**
 * Chain graph renderer — plain SVG, no external dependencies.
 *
 * Uses a simple layered layout: nodes are arranged in columns by their
 * topological depth, with vertical spacing within each column.  No full
 * Sugiyama algorithm — the chains are small enough that simple BFS depth
 * ordering produces readable graphs.
 */

;(function () {
  'use strict'

  const vscode = acquireVsCodeApi()

  const svg = document.getElementById('graph')
  const container = document.getElementById('graph-container')
  const errorBanner = document.getElementById('error-banner')
  const header = document.querySelector('header h1')
  const badge = document.querySelector('header .badge')
  const emptyState = document.getElementById('empty-state')

  // ── Layout constants ────────────────────────────────────────────────────────

  const NODE_WIDTH = 160
  const NODE_HEIGHT = 52
  const H_GAP = 80    // horizontal gap between columns
  const V_GAP = 24    // vertical gap between nodes in same column
  const PADDING = 40  // canvas padding

  // ── Message handler ─────────────────────────────────────────────────────────

  window.addEventListener('message', (event) => {
    const msg = event.data
    switch (msg.type) {
      case 'load':
        renderChain(msg.chain)
        break
      case 'error':
        showError(msg.message)
        break
    }
  })

  // Signal to the extension that the webview is ready to receive data.
  vscode.postMessage({ type: 'ready' })

  // ── Rendering ───────────────────────────────────────────────────────────────

  function renderChain(chain) {
    if (!chain || !chain.nodes || chain.nodes.length === 0) {
      emptyState.style.display = 'flex'
      svg.style.display = 'none'
      return
    }

    emptyState.style.display = 'none'
    svg.style.display = 'block'

    if (header) header.textContent = chain.title || 'Attack Chain'
    if (badge) badge.textContent = `${chain.nodes.length} node${chain.nodes.length !== 1 ? 's' : ''}`

    const positions = computeLayout(chain.nodes, chain.edges || [])
    drawGraph(chain.nodes, chain.edges || [], positions)
  }

  /**
   * Computes (x, y) positions for each node using BFS-based layer assignment.
   * Returns a Map<nodeId, {x, y}>.
   */
  function computeLayout(nodes, edges) {
    const nodeIds = nodes.map((n) => n.id)

    // Build adjacency and in-degree maps.
    const adj = new Map()
    const inDeg = new Map()
    for (const id of nodeIds) {
      adj.set(id, [])
      inDeg.set(id, 0)
    }
    for (const e of edges) {
      if (adj.has(e.source) && adj.has(e.target)) {
        adj.get(e.source).push(e.target)
        inDeg.set(e.target, (inDeg.get(e.target) || 0) + 1)
      }
    }

    // BFS topological layering.
    const layer = new Map()
    const queue = []
    for (const id of nodeIds) {
      if (inDeg.get(id) === 0) {
        queue.push(id)
        layer.set(id, 0)
      }
    }

    let head = 0
    while (head < queue.length) {
      const cur = queue[head++]
      const nextLayer = (layer.get(cur) || 0) + 1
      for (const nbr of (adj.get(cur) || [])) {
        if (!layer.has(nbr) || layer.get(nbr) < nextLayer) {
          layer.set(nbr, nextLayer)
        }
        inDeg.set(nbr, inDeg.get(nbr) - 1)
        if (inDeg.get(nbr) === 0) queue.push(nbr)
      }
    }

    // Assign layer 0 to any node not reached (disconnected).
    for (const id of nodeIds) {
      if (!layer.has(id)) layer.set(id, 0)
    }

    // Group nodes by layer.
    const byLayer = new Map()
    for (const id of nodeIds) {
      const l = layer.get(id)
      if (!byLayer.has(l)) byLayer.set(l, [])
      byLayer.get(l).push(id)
    }

    // Assign pixel positions.
    const positions = new Map()
    const sortedLayers = Array.from(byLayer.keys()).sort((a, b) => a - b)

    for (const l of sortedLayers) {
      const col = byLayer.get(l)
      const x = PADDING + l * (NODE_WIDTH + H_GAP)
      const totalHeight = col.length * NODE_HEIGHT + (col.length - 1) * V_GAP
      const startY = PADDING + Math.max(0, (400 - totalHeight) / 2)

      col.forEach((id, i) => {
        positions.set(id, {
          x,
          y: startY + i * (NODE_HEIGHT + V_GAP),
        })
      })
    }

    return positions
  }

  /**
   * Writes SVG elements for all nodes and edges into the graph SVG.
   */
  function drawGraph(nodes, edges, positions) {
    // Clear previous render.
    while (svg.firstChild) svg.removeChild(svg.firstChild)

    // Compute canvas size.
    let maxX = 0
    let maxY = 0
    for (const [, pos] of positions) {
      maxX = Math.max(maxX, pos.x + NODE_WIDTH + PADDING)
      maxY = Math.max(maxY, pos.y + NODE_HEIGHT + PADDING)
    }

    svg.setAttribute('viewBox', `0 0 ${maxX} ${maxY}`)

    // Defs: arrowhead marker.
    const defs = svgEl('defs')
    const marker = svgEl('marker', {
      id: 'arrowhead',
      markerWidth: '8',
      markerHeight: '6',
      refX: '8',
      refY: '3',
      orient: 'auto',
    })
    const arrowPath = svgEl('path', { d: 'M0,0 L8,3 L0,6 Z' })
    marker.appendChild(arrowPath)
    defs.appendChild(marker)
    svg.appendChild(defs)

    // Edges first (rendered below nodes).
    const edgeGroup = svgEl('g', { class: 'edges' })
    for (const edge of edges) {
      const from = positions.get(edge.source)
      const to = positions.get(edge.target)
      if (!from || !to) continue

      const x1 = from.x + NODE_WIDTH
      const y1 = from.y + NODE_HEIGHT / 2
      const x2 = to.x
      const y2 = to.y + NODE_HEIGHT / 2
      const cx = (x1 + x2) / 2

      const g = svgEl('g', { class: 'edge' })
      const path = svgEl('path', {
        d: `M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`,
      })
      g.appendChild(path)

      if (edge.label) {
        const midX = (x1 + x2) / 2
        const midY = (y1 + y2) / 2
        const text = svgEl('text', { x: String(midX), y: String(midY - 4), 'text-anchor': 'middle' })
        text.textContent = edge.label
        g.appendChild(text)
      }

      edgeGroup.appendChild(g)
    }
    svg.appendChild(edgeGroup)

    // Nodes.
    const nodeGroup = svgEl('g', { class: 'nodes' })
    for (const node of nodes) {
      const pos = positions.get(node.id)
      if (!pos) continue

      const sev = (node.severity || 'none').toLowerCase()
      const g = svgEl('g', {
        class: `node severity-${sev}`,
        transform: `translate(${pos.x}, ${pos.y})`,
      })

      const rect = svgEl('rect', {
        width: String(NODE_WIDTH),
        height: String(NODE_HEIGHT),
      })
      g.appendChild(rect)

      // Type label (small, top).
      const typeText = svgEl('text', {
        class: 'type-label',
        x: '8',
        y: '14',
      })
      typeText.textContent = truncate(node.type || '', 22)
      g.appendChild(typeText)

      // Main label.
      const mainText = svgEl('text', { x: '8', y: '34' })
      mainText.textContent = truncate(node.label || node.id, 22)
      g.appendChild(mainText)

      nodeGroup.appendChild(g)
    }
    svg.appendChild(nodeGroup)
  }

  // ── Utilities ───────────────────────────────────────────────────────────────

  function svgEl(tag, attrs = {}) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag)
    for (const [k, v] of Object.entries(attrs)) {
      el.setAttribute(k, v)
    }
    return el
  }

  function truncate(str, maxLen) {
    return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str
  }

  function showError(message) {
    if (errorBanner) {
      errorBanner.textContent = `Error: ${message}`
      errorBanner.classList.add('visible')
    }
  }
})()
