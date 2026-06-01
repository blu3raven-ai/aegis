/**
 * Centralised output channel for the Aegis extension.
 *
 * A single named channel is created on first call and reused throughout the
 * session — multiple channels for the same extension clutters the Output panel.
 */
import * as vscode from 'vscode'

let _channel: vscode.OutputChannel | undefined

/** Returns the shared Aegis output channel, creating it on first call. */
export function getChannel(): vscode.OutputChannel {
  if (!_channel) {
    _channel = vscode.window.createOutputChannel('Aegis')
  }
  return _channel
}

type LogLevel = 'info' | 'error'

/**
 * Appends a timestamped line to the Aegis output channel.
 *
 * Errors are prefixed with [ERROR] so they stand out when scanning logs.
 */
export function log(message: string, level: LogLevel = 'info'): void {
  const timestamp = new Date().toISOString()
  const prefix = level === 'error' ? '[ERROR]' : '[INFO] '
  getChannel().appendLine(`${timestamp}  ${prefix}  ${message}`)
}
