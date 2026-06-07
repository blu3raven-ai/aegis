import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

function read(path: string): string {
  return readFileSync(path, "utf-8")
}

describe("Sources settings pages", () => {
  describe("code-repositories scope config page", () => {
    const pageSrc = read("app/(app)/settings/sources/code-repositories/[id]/page.tsx")
    const contentSrc = read("app/(app)/settings/sources/code-repositories/[id]/CodeRepositoryScopeConfigContent.tsx")

    it("renders CodeRepositoryScopeConfigContent", () => {
      assert.match(pageSrc, /CodeRepositoryScopeConfigContent/)
    })

    it("checks manage_settings for edit", () => {
      assert.match(contentSrc, /can.*manage_settings/)
    })

    it("renders ScopeConfigContent with code-repositories category", () => {
      assert.match(contentSrc, /<ScopeConfigContent/)
      assert.match(contentSrc, /category="code-repositories"/)
    })

    it("passes connection id from params", () => {
      assert.match(contentSrc, /connectionId=\{id\}/)
    })
  })

  describe("container-images scope config page", () => {
    const pageSrc = read("app/(app)/settings/sources/container-images/[id]/page.tsx")
    const contentSrc = read("app/(app)/settings/sources/container-images/[id]/ContainerImageScopeConfigContent.tsx")

    it("renders ContainerImageScopeConfigContent", () => {
      assert.match(pageSrc, /ContainerImageScopeConfigContent/)
    })

    it("renders ScopeConfigContent with container-registry category", () => {
      assert.match(contentSrc, /<ScopeConfigContent/)
      assert.match(contentSrc, /category="container-registry"/)
    })
  })

  describe("sources API client", () => {
    const src = read("lib/client/sources-api.ts")

    it("exports listSourceConnections", () => {
      assert.match(src, /export async function listSourceConnections/)
    })

    it("exports createSourceConnection", () => {
      assert.match(src, /export async function createSourceConnection/)
    })

    it("exports testNewSourceConnection", () => {
      assert.match(src, /export async function testNewSourceConnection/)
    })

    it("exports syncSourceConnection", () => {
      assert.match(src, /export async function syncSourceConnection/)
    })

    it("exports getSourceConnectionCounts", () => {
      assert.match(src, /export async function getSourceConnectionCounts/)
    })
  })

  describe("sources types", () => {
    const src = read("lib/shared/sources-types.ts")

    it("defines SourceConnection interface", () => {
      assert.match(src, /interface SourceConnection/)
    })

    it("defines all three categories", () => {
      assert.match(src, /code-repositories/)
      assert.match(src, /container-registry/)
      assert.match(src, /cloud-infrastructure/)
    })

    it("defines source types", () => {
      assert.match(src, /"github"/)
      assert.match(src, /"gitlab"/)
      assert.match(src, /"docker-hub"/)
      assert.match(src, /"ghcr"/)
    })

    it("defines SOURCE_TYPE_FIELDS for each type", () => {
      assert.match(src, /SOURCE_TYPE_FIELDS/)
    })
  })

  describe("AddConnectionModal auto-sync behaviour", () => {
    const src = read("app/(app)/settings/sources/_components/AddConnectionModal.tsx")

    it("imports syncSourceConnection", () => {
      assert.match(src, /syncSourceConnection/)
    })

    it("calls syncSourceConnection after successful create", () => {
      assert.match(src, /syncSourceConnection\([^)]*\.id\)/)
    })

    it("closes modal immediately after create without setTimeout delay", () => {
      assert.doesNotMatch(src, /setSuccess\(true\)/)
      assert.doesNotMatch(src, /setTimeout.*onCreated/)
    })
  })

  describe("shared components exist", () => {
    it("ConnectionCard exists", () => {
      const src = read("app/(app)/settings/sources/_components/ConnectionCard.tsx")
      assert.match(src, /export function ConnectionCard/)
    })

    it("ConnectionList exists", () => {
      const src = read("app/(app)/settings/sources/_components/ConnectionList.tsx")
      assert.match(src, /export function ConnectionList/)
    })

    it("AddConnectionModal exists", () => {
      const src = read("app/(app)/settings/sources/_components/AddConnectionModal.tsx")
      assert.match(src, /export function AddConnectionModal/)
    })

    it("ScopeConfigurator exists", () => {
      const src = read("app/(app)/settings/sources/_components/ScopeConfigurator.tsx")
      assert.match(src, /export function ScopeConfigurator/)
    })

    it("ScopeConfigContent exists", () => {
      const src = read("app/(app)/settings/sources/_components/ScopeConfigContent.tsx")
      assert.match(src, /export function ScopeConfigContent/)
    })

    it("ConnectionStatusBadge exists", () => {
      const src = read("app/(app)/settings/sources/_components/ConnectionStatusBadge.tsx")
      assert.match(src, /export function ConnectionStatusBadge/)
    })
  })
})
