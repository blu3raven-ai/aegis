import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("Scanner-led redirects", () => {
  it("/code lands at /findings?scanner=sast", () => {
    const src = read("app/(app)/code/page.tsx")
    assert.ok(src.includes('redirect("/findings?scanner=sast")'), "/code must redirect to /findings?scanner=sast")
  })

  it("/code/dashboard lands at /findings?scanner=sast (with ?tab=settings → /settings/code)", () => {
    const src = read("app/(app)/code/dashboard/page.tsx")
    assert.ok(src.includes('"/findings?scanner=sast"'), "/code/dashboard default target")
    assert.ok(src.includes('"/settings/code"'), "/code/dashboard ?tab=settings target")
  })

  it("/containers/dashboard lands at /findings?scanner=container (with ?tab=settings → /settings/containers)", () => {
    const src = read("app/(app)/containers/dashboard/page.tsx")
    assert.ok(src.includes('"/findings?scanner=container"'), "/containers/dashboard default target")
    assert.ok(src.includes('"/settings/containers"'), "/containers/dashboard ?tab=settings target")
  })

  it("/dependencies/dashboard lands at /findings?scanner=deps (with ?tab=settings → /settings/dependencies)", () => {
    const src = read("app/(app)/dependencies/dashboard/page.tsx")
    assert.ok(src.includes('"/findings?scanner=deps"'), "/dependencies/dashboard default target")
    assert.ok(src.includes('"/settings/dependencies"'), "/dependencies/dashboard ?tab=settings target")
  })

  it("/iac/dashboard lands at /findings?scanner=iac (with ?tab=settings → /settings/iac-security)", () => {
    const src = read("app/(app)/iac/dashboard/page.tsx")
    assert.ok(src.includes('"/findings?scanner=iac"'), "/iac/dashboard default target")
    assert.ok(src.includes('"/settings/iac-security"'), "/iac/dashboard ?tab=settings target")
  })

  it("/secrets lands at /findings?scanner=secrets", () => {
    const src = read("app/(app)/secrets/page.tsx")
    assert.ok(src.includes('redirect("/findings?scanner=secrets")'), "/secrets must redirect to /findings?scanner=secrets")
  })

  it("/secrets/dashboard lands at /findings?scanner=secrets (with ?tab=settings → /settings/secrets)", () => {
    const src = read("app/(app)/secrets/dashboard/page.tsx")
    assert.ok(src.includes('"/findings?scanner=secrets"'), "/secrets/dashboard default target")
    assert.ok(src.includes('"/settings/secrets"'), "/secrets/dashboard ?tab=settings target")
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
