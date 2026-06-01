/**
 * Thin subprocess wrapper around the `aegis` CLI.
 *
 * The extension deliberately avoids calling the backend directly -- all
 * network traffic goes through the CLI binary so auth, config precedence,
 * and retry logic stay in one place.  The CLI is required to be in PATH
 * (or configured via aegis.cliPath).
 */
import { spawn } from 'child_process'
import * as vscode from 'vscode'
import { AegisConfig } from './config'

export interface Finding {
  id: string
  filePath: string
  line: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  ruleId: string
  message: string
  scanner: string
  /** Present when the finding is part of an attack chain. */
  chainId?: string
}

export interface ChainNode {
  id: string
  label: string
  type: string
  severity?: string
}

export interface ChainEdge {
  source: string
  target: string
  label?: string
}

export interface Chain {
  id: string
  title: string
  nodes: ChainNode[]
  edges: ChainEdge[]
}

export interface DecisionResult {
  decision: 'allow' | 'warn' | 'block'
  blockers: string[]
  rationale: string
}

export class AegisClient {
  constructor(private readonly config: AegisConfig) {}

  /** Trigger a scan and wait for it to complete, returning normalised findings. */
  scan(): Promise<Finding[]> {
    return this.runCli<Finding[]>(['scan', '--wait', '--json'])
  }

  /** Fetch the latest findings without triggering a new scan run. */
  findings(): Promise<Finding[]> {
    return this.runCli<Finding[]>(['findings', '--json'])
  }

  /** Fetch the go/no-go deployment decision. */
  decide(): Promise<DecisionResult> {
    return this.runCli<DecisionResult>(['decide', '--json'])
  }

  /**
   * Fetch a chain by ID.  Requires aegis CLI >= 0.5; older versions will
   * reject the subcommand and this method will surface a clear error.
   */
  getChain(chainId: string): Promise<Chain> {
    return this.runCli<Chain>(['chain', 'get', chainId, '--json']).catch((err) => {
      const msg = (err as Error).message
      if (msg.includes('unknown command') || msg.includes('unrecognized')) {
        throw new Error(`aegis CLI version too old -- "chain get" requires aegis >= 0.5`)
      }
      throw err
    })
  }

  /**
   * Snooze a finding for the given number of days.
   * Requires aegis CLI >= 0.5.
   */
  snoozeFinding(findingId: string, durationDays: number): Promise<void> {
    return this.runCli<void>([
      'finding', 'snooze', findingId, '--days', String(durationDays),
    ]).catch((err) => {
      const msg = (err as Error).message
      if (msg.includes('unknown command') || msg.includes('unrecognized')) {
        throw new Error(`aegis CLI version too old -- "finding snooze" requires aegis >= 0.5`)
      }
      throw err
    })
  }

  /**
   * Mark a finding as fixed.
   * Requires aegis CLI >= 0.5.
   */
  markFixedFinding(findingId: string): Promise<void> {
    return this.runCli<void>(['finding', 'mark-fixed', findingId]).catch((err) => {
      const msg = (err as Error).message
      if (msg.includes('unknown command') || msg.includes('unrecognized')) {
        throw new Error(`aegis CLI version too old -- "finding mark-fixed" requires aegis >= 0.5`)
      }
      throw err
    })
  }

  /**
   * Trigger a SAST scan scoped to a folder, a single file, or the whole
   * workspace.  Pass forceRefreshRules to pull the latest rule pack before
   * scanning — useful after a rule-pack release.
   */
  scanScope(opts: {
    folderPath?: string
    filePath?: string
    forceRefreshRules?: boolean
  }): Promise<Finding[]> {
    const args: string[] = ['scan', '--wait', '--json']
    if (opts.folderPath) {
      args.push('--path', opts.folderPath)
    }
    if (opts.filePath) {
      args.push('--file', opts.filePath)
    }
    if (opts.forceRefreshRules) {
      args.push('--force', '--refresh-rules')
    }
    return this.runCli<Finding[]>(args)
  }

  /**
   * Spawns the aegis CLI with the given args, threads workspace config
   * through env vars, and resolves with parsed JSON output.
   *
   * Config values are injected as env vars so the CLI own precedence
   * rules (env > config file) still apply -- we never write to the CLI
   * config file from the extension.
   */
  private runCli<T>(args: string[]): Promise<T> {
    return new Promise((resolve, reject) => {
      const env: NodeJS.ProcessEnv = { ...process.env }
      if (this.config.baseUrl) {
        env.AEGIS_BASE_URL = this.config.baseUrl
      }
      if (this.config.apiToken) {
        env.AEGIS_API_TOKEN = this.config.apiToken
      }
      if (this.config.org) {
        env.AEGIS_DEFAULT_ORG = this.config.org
      }

      const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
      const proc = spawn(this.config.cliPath, args, { env, cwd })

      let stdout = ''
      let stderr = ''
      proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString() })
      proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString() })

      proc.on('error', (err) => {
        reject(new Error(
          `Failed to launch aegis CLI at '${ this.config.cliPath }': ${err.message}. ` +
          `Ensure the CLI is installed and aegis.cliPath is correct.`
        ))
      })

      proc.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`aegis CLI exited with code ${code}: ${stderr.trim()}`))
          return
        }
        try {
          resolve(JSON.parse(stdout) as T)
        } catch (err) {
          reject(new Error(
            `Failed to parse aegis CLI output: ${err}\n` +
            `Raw output (first 500 chars): ${stdout.slice(0, 500)}`
          ))
        }
      })
    })
  }
}
