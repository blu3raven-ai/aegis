import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("Scanner-led landing routes", () => {
  it("/code renders the findings board pre-filtered to sast (no URL params)", () => {
    const src = read("app/(app)/code/page.tsx")
    assert.ok(src.includes('initialScannerFilter="sast"'), "/code must pre-filter to sast")
    assert.ok(!src.includes("/findings?scanner"), "/code must not redirect with URL params")
  })

  it("/code/dashboard renders sast in-place (with ?tab=settings → /settings/code)", () => {
    const src = read("app/(app)/code/dashboard/page.tsx")
    assert.ok(src.includes('initialScannerFilter="sast"'), "/code/dashboard must pre-filter to sast")
    assert.ok(src.includes('"/settings/code"'), "/code/dashboard ?tab=settings target")
    assert.ok(!src.includes("/findings?scanner"), "/code/dashboard must not redirect with URL params")
  })

  it("/containers/dashboard renders container in-place (with ?tab=settings → /settings/containers)", () => {
    const src = read("app/(app)/containers/dashboard/page.tsx")
    assert.ok(src.includes('initialScannerFilter="container"'), "/containers/dashboard must pre-filter to container")
    assert.ok(src.includes('"/settings/containers"'), "/containers/dashboard ?tab=settings target")
    assert.ok(!src.includes("/findings?scanner"), "/containers/dashboard must not redirect with URL params")
  })

  it("/dependencies/dashboard renders deps in-place (with ?tab=settings → /settings/dependencies)", () => {
    const src = read("app/(app)/dependencies/dashboard/page.tsx")
    assert.ok(src.includes('initialScannerFilter="deps"'), "/dependencies/dashboard must pre-filter to deps")
    assert.ok(src.includes('"/settings/dependencies"'), "/dependencies/dashboard ?tab=settings target")
    assert.ok(!src.includes("/findings?scanner"), "/dependencies/dashboard must not redirect with URL params")
  })

  it("/iac/dashboard renders iac in-place (with ?tab=settings → /settings/iac-security)", () => {
    const src = read("app/(app)/iac/dashboard/page.tsx")
    assert.ok(src.includes('initialScannerFilter="iac"'), "/iac/dashboard must pre-filter to iac")
    assert.ok(src.includes('"/settings/iac-security"'), "/iac/dashboard ?tab=settings target")
    assert.ok(!src.includes("/findings?scanner"), "/iac/dashboard must not redirect with URL params")
  })

  it("/secrets renders the findings board pre-filtered to secrets (no URL params)", () => {
    const src = read("app/(app)/secrets/page.tsx")
    assert.ok(src.includes('initialScannerFilter="secrets"'), "/secrets must pre-filter to secrets")
    assert.ok(!src.includes("/findings?scanner"), "/secrets must not redirect with URL params")
  })

  it("/secrets/dashboard renders secrets in-place (with ?tab=settings → /settings/secrets)", () => {
    const src = read("app/(app)/secrets/dashboard/page.tsx")
    assert.ok(src.includes('initialScannerFilter="secrets"'), "/secrets/dashboard must pre-filter to secrets")
    assert.ok(src.includes('"/settings/secrets"'), "/secrets/dashboard ?tab=settings target")
    assert.ok(!src.includes("/findings?scanner"), "/secrets/dashboard must not redirect with URL params")
  })

  it("FindingScanner type includes iac", () => {
    const src = read("lib/client/findings-api.ts")
    assert.ok(
      src.includes('"deps" | "container" | "sast" | "secrets" | "iac"'),
      "FindingScanner union must include iac",
    )
  })
})

describe("Settings page wrappers", () => {
  it("/settings/code/page.tsx renders CodeScanningContent", () => {
    const src = read("app/(app)/settings/code/page.tsx")
    assert.ok(src.includes("CodeScanningContent"))
    assert.ok(src.includes('export default function'))
  })

  it("/settings/containers/page.tsx renders ContainerScanningContent", () => {
    const src = read("app/(app)/settings/containers/page.tsx")
    assert.ok(src.includes("ContainerScanningContent"))
    assert.ok(src.includes('export default function'))
  })

  it("/settings/dependencies/page.tsx renders DependenciesContent", () => {
    const src = read("app/(app)/settings/dependencies/page.tsx")
    assert.ok(src.includes("DependenciesContent"))
    assert.ok(src.includes('export default function'))
  })

  it("/settings/secrets/page.tsx renders SecretsContent", () => {
    const src = read("app/(app)/settings/secrets/page.tsx")
    assert.ok(src.includes("SecretsContent"))
    assert.ok(src.includes('export default function'))
  })
})
