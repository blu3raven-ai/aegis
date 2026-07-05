/**
 * Tree data provider for the Aegis sidebar panel.
 *
 * Findings are grouped as: Severity -> Scanner -> File -> Finding.
 * This three-level hierarchy makes it easy to spot which scanners produce
 * the most critical noise and which files are worst affected.
 */
import * as path from 'path'
import * as vscode from 'vscode'
import { Finding } from './client'

// ── Severity ordering ─────────────────────────────────────────────────────────

const SEVERITY_ORDER: Finding['severity'][] = ['critical', 'high', 'medium', 'low']

// ── Tree node types ───────────────────────────────────────────────────────────

export class SeverityGroupNode extends vscode.TreeItem {
  constructor(
    public readonly severity: Finding['severity'],
    public readonly count: number,
  ) {
    super(
      `${severity.charAt(0).toUpperCase() + severity.slice(1)} (${count})`,
      vscode.TreeItemCollapsibleState.Expanded,
    )
    this.iconPath = severityIcon(severity)
    this.contextValue = 'aegisSeverityGroup'
    this.tooltip = `${count} ${severity} finding${count !== 1 ? 's' : ''}`
  }
}

export class ScannerGroupNode extends vscode.TreeItem {
  constructor(
    public readonly scanner: string,
    public readonly count: number,
  ) {
    super(
      `${scanner} (${count})`,
      vscode.TreeItemCollapsibleState.Collapsed,
    )
    this.iconPath = new vscode.ThemeIcon('tools')
    this.contextValue = 'aegisScannerGroup'
    this.tooltip = `${count} finding${count !== 1 ? 's' : ''} from ${scanner}`
  }
}

export class FileGroupNode extends vscode.TreeItem {
  constructor(
    public readonly filePath: string,
    public readonly count: number,
  ) {
    super(
      `${path.basename(filePath)} (${count})`,
      vscode.TreeItemCollapsibleState.Collapsed,
    )
    this.description = path.dirname(filePath)
    this.tooltip = filePath
    this.iconPath = new vscode.ThemeIcon('file')
    this.contextValue = 'aegisFileGroup'
  }
}

export class FindingNode extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(finding.message, vscode.TreeItemCollapsibleState.None)
    this.description = `L${finding.line} * ${finding.ruleId}`
    this.tooltip = `[${finding.severity.toUpperCase()}] ${finding.message}\n${finding.ruleId} via ${finding.scanner}`
    this.iconPath = severityIcon(finding.severity)
    this.contextValue = 'aegisFinding'

    this.command = {
      command: 'vscode.open',
      title: 'Go to finding',
      arguments: [
        vscode.Uri.file(finding.filePath),
        { selection: new vscode.Range(finding.line - 1, 0, finding.line - 1, 0) },
      ],
    }
  }
}

// ── Internal tree structure ───────────────────────────────────────────────────

interface ScannerBucket {
  node: ScannerGroupNode
  files: Map<string, { node: FileGroupNode; findings: FindingNode[] }>
}

interface SeverityBucket {
  node: SeverityGroupNode
  scanners: Map<string, ScannerBucket>
}

// ── Provider ──────────────────────────────────────────────────────────────────

export type AegisTreeItem =
  | SeverityGroupNode
  | ScannerGroupNode
  | FileGroupNode
  | FindingNode

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<AegisTreeItem>
{
  private _onDidChangeTreeData =
    new vscode.EventEmitter<AegisTreeItem | undefined | null>()
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event

  private severityBuckets: SeverityBucket[] = []

  update(findings: Finding[]): void {
    this.severityBuckets = buildTree(findings)
    this._onDidChangeTreeData.fire(null)
  }

  clear(): void {
    this.severityBuckets = []
    this._onDidChangeTreeData.fire(null)
  }

  getTreeItem(element: AegisTreeItem): vscode.TreeItem {
    return element
  }

  getChildren(element?: AegisTreeItem): AegisTreeItem[] {
    if (!element) {
      // Root: one node per non-empty severity group.
      return this.severityBuckets.map((b) => b.node)
    }

    if (element instanceof SeverityGroupNode) {
      const bucket = this.severityBuckets.find((b) => b.node === element)
      if (!bucket) return []
      return Array.from(bucket.scanners.values()).map((s) => s.node)
    }

    if (element instanceof ScannerGroupNode) {
      for (const sevBucket of this.severityBuckets) {
        const scannerBucket = sevBucket.scanners.get(element.scanner)
        if (scannerBucket && scannerBucket.node === element) {
          return Array.from(scannerBucket.files.values()).map((f) => f.node)
        }
      }
      return []
    }

    if (element instanceof FileGroupNode) {
      for (const sevBucket of this.severityBuckets) {
        for (const scannerBucket of sevBucket.scanners.values()) {
          const fileBucket = scannerBucket.files.get(element.filePath)
          if (fileBucket && fileBucket.node === element) {
            return fileBucket.findings
          }
        }
      }
      return []
    }

    return []
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildTree(findings: Finding[]): SeverityBucket[] {
  // Group: severity -> scanner -> file -> findings
  const sevMap = new Map<Finding['severity'], Map<string, Map<string, Finding[]>>>()

  for (const f of findings) {
    if (!sevMap.has(f.severity)) sevMap.set(f.severity, new Map())
    const scannerMap = sevMap.get(f.severity)!

    if (!scannerMap.has(f.scanner)) scannerMap.set(f.scanner, new Map())
    const fileMap = scannerMap.get(f.scanner)!

    if (!fileMap.has(f.filePath)) fileMap.set(f.filePath, [])
    fileMap.get(f.filePath)!.push(f)
  }

  const buckets: SeverityBucket[] = []

  for (const severity of SEVERITY_ORDER) {
    const scannerMap = sevMap.get(severity)
    if (!scannerMap || scannerMap.size === 0) continue

    // Count total findings for this severity.
    let sevCount = 0
    const scannerBuckets = new Map<string, ScannerBucket>()

    for (const [scanner, fileMap] of scannerMap) {
      let scannerCount = 0
      const fileBuckets = new Map<string, { node: FileGroupNode; findings: FindingNode[] }>()

      for (const [filePath, fList] of fileMap) {
        const sorted = [...fList].sort((a, b) => a.line - b.line)
        const findingNodes = sorted.map((f) => new FindingNode(f))
        fileBuckets.set(filePath, {
          node: new FileGroupNode(filePath, fList.length),
          findings: findingNodes,
        })
        scannerCount += fList.length
      }

      scannerBuckets.set(scanner, {
        node: new ScannerGroupNode(scanner, scannerCount),
        files: fileBuckets,
      })
      sevCount += scannerCount
    }

    buckets.push({
      node: new SeverityGroupNode(severity, sevCount),
      scanners: scannerBuckets,
    })
  }

  return buckets
}

function severityIcon(severity: Finding['severity']): vscode.ThemeIcon {
  switch (severity) {
    case 'critical':
    case 'high':
      return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'))
    case 'medium':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'))
    case 'low':
      return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'))
    default:
      return new vscode.ThemeIcon('circle-outline')
  }
}
