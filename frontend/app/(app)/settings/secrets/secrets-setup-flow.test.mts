import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import path from "node:path"

const dir = path.join(process.cwd(), "app/(app)/settings/secrets")
const settingsDir = path.join(process.cwd(), "app/(app)/settings")

test("SecretsContent.tsx uses SecretsSetupForm instead of ToolSettingsForm", () => {
  const source = readFileSync(path.join(dir, "SecretsContent.tsx"), "utf8")
  assert.match(source, /import \{ SecretsSetupForm \} from "\.\/SecretsSetupForm"/)
  assert.match(source, /<SecretsSetupForm/)
  assert.doesNotMatch(source, /import \{ ToolSettingsForm, type ToolSettingsDraft \} from "\.\.\/ToolSettingsForm"/)
  assert.doesNotMatch(source, /<ToolSettingsForm/)
})

test("SecretsSetupForm.tsx defines SecretsSetupForm component", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /export function SecretsSetupForm/)
})

test("SecretsSetupForm.tsx includes status determination logic", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /let status: "Setup required" \| "Verifying" \| "Ready" = "Setup required"/)
  assert.match(source, /status = "Verifying"/)
  assert.match(source, /status = "Ready"/)
})

test("SecretsSetupForm.tsx combines verification and installation guidance", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.doesNotMatch(source, /Installation Required/)
  assert.doesNotMatch(source, /installCommand=/)
  assert.doesNotMatch(source, /SECRET_SCANNER_INSTALL_COMMAND/)
})

test("SecretsSetupForm.tsx does not show install command copy UI", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  const panel = readFileSync(path.join(settingsDir, "PrerequisitePanel.tsx"), "utf8")
  assert.doesNotMatch(source, /handleCopyInstallCommand/)
  assert.match(panel, /Copied to clipboard/)
  assert.match(panel, /role="status"/)
  assert.match(panel, /aria-live="polite"/)
})

test("SecretsSetupForm.tsx has scan concurrency field", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /Scan concurrency/)
  assert.match(source, /values.scanConcurrency/)
})

test("SecretsSetupForm.tsx does not contain AI Review Assistant section", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.doesNotMatch(source, /AI Review Assistant/)
  assert.doesNotMatch(source, /aiReviewEnabled/)
  assert.doesNotMatch(source, /Enable AI assessment/)
})

test("SecretsSetupForm.tsx has scanner verification prerequisite panel", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /Scanner Verification/)
  assert.match(source, /canEnable/)
})

test("SecretsSetupForm.tsx no longer offers AI Enhanced scan depth", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.doesNotMatch(source, /ai_enhanced/)
  assert.doesNotMatch(source, /AI Enhanced/)
})

test("SecretsSetupForm.tsx scan depth picker uses 2-column grid", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /grid-cols-2/)
})

test("SecretsSetupForm.tsx normalizes scanDepth to light when unset", () => {
  const source = readFileSync(path.join(dir, "SecretsSetupForm.tsx"), "utf8")
  assert.match(source, /scanDepth: initialValues\.scanDepth \?\? "light"/)
})
