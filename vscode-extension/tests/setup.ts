/**
 * Shared vscode mock setup for unit tests.
 *
 * All test files must import this module before importing any extension source.
 * The Module._load patch is idempotent — it only installs once per process.
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const Module = require('module')
const originalLoad = Module._load

// Patch only once, even if multiple test files import this module.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const g = global as any
if (!g.__aegisVscodeMockInstalled) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Module._load = function (request: string, parent: unknown, isMain: boolean): any {
    if (request === 'vscode') return vscodeMock
    return originalLoad(request, parent, isMain)
  }
  g.__aegisVscodeMockInstalled = true
}

class MockRange {
  constructor(
    public startLine: number,
    public startChar: number,
    public endLine: number,
    public endChar: number,
  ) {}
  get start() { return { line: this.startLine, character: this.startChar } }
}

class MockDiagnostic {
  source?: string
  code?: string
  constructor(public range: unknown, public message: string, public severity: number) {}
}

class MockTreeItem {
  label: string
  collapsibleState: number
  description?: string
  tooltip?: string
  iconPath?: unknown
  contextValue?: string
  command?: unknown
  constructor(label: string, collapsibleState = 0) {
    this.label = label
    this.collapsibleState = collapsibleState
  }
}

class MockCodeAction {
  command?: unknown
  constructor(public title: string, public kind: unknown) {}
}

export const vscodeMock = {
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Uri: {
    file: (p: string) => ({ toString: () => `file://${p}`, fsPath: p }),
    parse: (s: string) => ({ toString: () => s }),
    joinPath: (base: { fsPath: string }, ...parts: string[]) => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const path = require('path')
      const joined = path.join(base.fsPath, ...parts)
      return { fsPath: joined, toString: () => `file://${joined}` }
    },
  },
  Range: MockRange,
  Diagnostic: MockDiagnostic,
  TreeItem: MockTreeItem,
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  ThemeIcon: class { constructor(public id: string, public color?: unknown) {} },
  ThemeColor: class { constructor(public id: string) {} },
  EventEmitter: class {
    event = () => {}
    fire() {}
  },
  CodeAction: MockCodeAction,
  CodeActionKind: {
    QuickFix: { value: 'quickfix' },
    Empty: { value: '' },
  },
  ProgressLocation: { Notification: 15, Window: 10, SourceControl: 1 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: '/workspace' } }],
    registerTextDocumentContentProvider: () => ({ dispose: () => {} }),
  },
  window: {
    createOutputChannel: (_name: string) => ({
      appendLine: () => {},
      show: () => {},
      dispose: () => {},
    }),
    createStatusBarItem: (_align?: number, _priority?: number) => ({
      text: '',
      tooltip: '',
      command: '',
      backgroundColor: undefined as unknown,
      show: () => {},
      hide: () => {},
      dispose: () => {},
    }),
    createWebviewPanel: () => ({
      webview: {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        asWebviewUri: (uri: any) => ({ toString: () => uri.toString() }),
        cspSource: 'vscode-resource:',
        html: '',
        onDidReceiveMessage: () => ({ dispose: () => {} }),
        postMessage: () => Promise.resolve(),
      },
      title: '',
      reveal: () => {},
      onDidDispose: (_cb: () => void) => ({ dispose: () => {} }),
    }),
    showErrorMessage: (_msg: string) => Promise.resolve(undefined),
    showInformationMessage: (_msg: string) => Promise.resolve(undefined),
    showWarningMessage: (_msg: string) => Promise.resolve(undefined),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    withProgress: async (_opts: unknown, task: (progress: unknown, token: unknown) => Promise<any>) => task({}, {}),
    activeTextEditor: undefined as { document: { uri: { fsPath: string } } } | undefined,
  },
  ViewColumn: { Beside: 2 },
  languages: {
    registerCodeActionsProvider: () => ({ dispose: () => {} }),
  },
  commands: {
    executeCommand: () => Promise.resolve(),
  },
}
