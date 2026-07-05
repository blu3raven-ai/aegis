/**
 * CLI smoke tests — verify the aegis CLI binary (Python package) exposes the
 * expected commands and returns a parseable version string.
 *
 * These are subprocess tests that do NOT require a running backend or browser.
 * They run via `npm run test:contracts`.
 *
 * If the aegis_cli package isn't installed in the current environment the
 * tests are skipped rather than failed so CI can selectively enable them
 * in environments that have Python/uv available.
 */

import assert from "node:assert/strict"
import test from "node:test"
import { execSync, spawnSync } from "node:child_process"
import path from "node:path"
import fs from "node:fs"

const ROOT = path.resolve(import.meta.dirname, "../..")
const CLI_DIR = path.join(ROOT, "cli")

/** Resolve the CLI entry point — either the installed `aegis` binary or
 *  a direct invocation via `python -m aegis_cli`.                         */
function resolveCli(): { cmd: string; args: string[] } | null {
  // Prefer the installed entry point
  const installed = spawnSync("aegis", ["--version"], { encoding: "utf-8" })
  if (installed.status === 0) return { cmd: "aegis", args: [] }

  // Fall back to python -m aegis_cli (inside the cli/ virtualenv)
  const venv = path.join(CLI_DIR, ".venv", "bin", "python")
  if (fs.existsSync(venv)) {
    const direct = spawnSync(venv, ["-m", "aegis_cli", "--version"], { encoding: "utf-8", cwd: CLI_DIR })
    if (direct.status === 0) return { cmd: venv, args: ["-m", "aegis_cli"] }
  }

  // uv run as last resort
  const uv = spawnSync("uv", ["run", "--directory", CLI_DIR, "aegis", "--version"], { encoding: "utf-8" })
  if (uv.status === 0) return { cmd: "uv", args: ["run", "--directory", CLI_DIR, "aegis"] }

  return null
}

const cli = resolveCli()

function runCli(extraArgs: string[]): { stdout: string; stderr: string; status: number | null } {
  if (!cli) return { stdout: "", stderr: "CLI not found", status: 1 }
  const result = spawnSync(cli.cmd, [...cli.args, ...extraArgs], {
    encoding: "utf-8",
    timeout: 10_000,
  })
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status,
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("aegis --version returns a parseable semver string", { skip: !cli }, () => {
  const { stdout, status } = runCli(["--version"])
  assert.equal(status, 0, `aegis --version exited non-zero: ${stdout}`)
  // Accept "0.1.0", "aegis 0.1.0", "aegis, version 0.1.0" etc.
  assert.match(stdout + " ", /\d+\.\d+\.\d+/, "Version output should contain a semver string")
})

test("aegis --help lists the expected sub-commands", { skip: !cli }, () => {
  const { stdout, stderr, status } = runCli(["--help"])
  // --help often exits 0 but some Click apps exit 1; both are acceptable
  assert.ok(status === 0 || status === 1, `Unexpected exit code ${status}`)

  const output = (stdout + stderr).toLowerCase()

  const expectedCommands = ["scan", "status", "decide", "findings", "report", "login", "mcp"]
  for (const cmd of expectedCommands) {
    assert.ok(output.includes(cmd), `Expected '${cmd}' in --help output.\nOutput was:\n${output}`)
  }
})

test("aegis scan --help is accessible", { skip: !cli }, () => {
  const { stdout, stderr, status } = runCli(["scan", "--help"])
  assert.ok(status === 0 || status === 1)
  const output = stdout + stderr
  assert.ok(output.length > 0, "scan --help produced no output")
})

test("aegis findings --help is accessible", { skip: !cli }, () => {
  const { stdout, stderr, status } = runCli(["findings", "--help"])
  assert.ok(status === 0 || status === 1)
  const output = stdout + stderr
  assert.ok(output.length > 0, "findings --help produced no output")
})

test("aegis report --help is accessible", { skip: !cli }, () => {
  const { stdout, stderr, status } = runCli(["report", "--help"])
  assert.ok(status === 0 || status === 1)
  const output = stdout + stderr
  assert.ok(output.length > 0, "report --help produced no output")
})

test("aegis sbom --help is accessible (if command exists)", { skip: !cli }, () => {
  const { stdout, stderr, status } = runCli(["sbom", "--help"])
  // sbom may not be registered yet in all builds — skip if unknown command
  const output = stdout + stderr
  if (output.includes("No such command") || output.includes("unknown command")) {
    // Expected before Phase 18 ships
    return
  }
  assert.ok(status === 0 || status === 1)
  assert.ok(output.length > 0, "sbom --help produced no output")
})
