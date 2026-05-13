import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

function read(path: string): string {
  return readFileSync(path, "utf-8")
}

describe("Sources settings pages", () => {
  describe("SidebarNav", () => {
    const src = read("app/(app)/settings/SidebarNav.tsx")

    it("includes Sources nav group", () => {
      assert.match(src, /Sources/)
    })

    it("links to code-repositories page", () => {
      assert.match(src, /\/settings\/sources\/code-repositories/)
    })

    it("links to container-images page", () => {
      assert.match(src, /\/settings\/sources\/container-images/)
    })

    it("links to ci-cd-pipelines page", () => {
      assert.match(src, /\/settings\/sources\/ci-cd-pipelines/)
    })

    it("fetches source connection counts", () => {
      assert.match(src, /getSourceConnectionCounts/)
    })
  })

  describe("code-repositories list page", () => {
    const src = read("app/(app)/settings/sources/code-repositories/page.tsx")

    it("requires view_settings permission", () => {
      assert.match(src, /requirePermission.*view_settings/)
    })

    it("checks manage_settings for edit", () => {
      assert.match(src, /can.*manage_settings/)
    })

    it("renders ConnectionList with code-repositories category", () => {
      assert.match(src, /category.*code-repositories/)
    })
  })

  describe("code-repositories scope config page", () => {
    const src = read("app/(app)/settings/sources/code-repositories/[id]/page.tsx")

    it("requires view_settings permission", () => {
      assert.match(src, /requirePermission.*view_settings/)
    })

    it("renders ScopeConfigContent", () => {
      assert.match(src, /ScopeConfigContent/)
    })

    it("passes connection id from params", () => {
      assert.match(src, /connectionId.*id/)
    })
  })

  describe("container-images list page", () => {
    const src = read("app/(app)/settings/sources/container-images/page.tsx")

    it("renders ConnectionList with container-images category", () => {
      assert.match(src, /category.*container-images/)
    })
  })

  describe("ci-cd-pipelines list page", () => {
    const src = read("app/(app)/settings/sources/ci-cd-pipelines/page.tsx")

    it("renders ConnectionList with ci-cd-pipelines category", () => {
      assert.match(src, /category.*ci-cd-pipelines/)
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
      assert.match(src, /container-images/)
      assert.match(src, /ci-cd-pipelines/)
    })

    it("defines all source types", () => {
      assert.match(src, /"github"/)
      assert.match(src, /"gitlab"/)
      assert.match(src, /"docker-hub"/)
      assert.match(src, /"ghcr"/)
      assert.match(src, /"github-actions"/)
      assert.match(src, /"gitlab-ci"/)
    })

    it("defines SOURCE_TYPE_FIELDS for each type", () => {
      assert.match(src, /SOURCE_TYPE_FIELDS/)
    })
  })

  describe("AddConnectionModal auto-sync behaviour", () => {
    const src = read("components/sources/AddConnectionModal.tsx")

    it("imports syncSourceConnection", () => {
      assert.match(src, /syncSourceConnection/)
    })

    it("calls syncSourceConnection after successful create", () => {
      assert.match(src, /syncSourceConnection\(.*\.id\)/)
    })

    it("closes modal immediately after create without setTimeout delay", () => {
      // success state + setTimeout pattern must be gone
      assert.doesNotMatch(src, /setSuccess\(true\)/)
      assert.doesNotMatch(src, /setTimeout.*onCreated/)
    })
  })

  describe("ConnectionList sync polling", () => {
    const src = read("components/sources/ConnectionList.tsx")

    it("imports useRef", () => {
      assert.match(src, /useRef/)
    })

    it("uses setInterval for polling", () => {
      assert.match(src, /setInterval/)
    })

    it("clears interval with clearInterval", () => {
      assert.match(src, /clearInterval/)
    })

    it("polls only when a connection is syncing", () => {
      assert.match(src, /status.*syncing/)
    })
  })

  describe("shared components exist", () => {
    it("ConnectionCard exists", () => {
      const src = read("components/sources/ConnectionCard.tsx")
      assert.match(src, /export function ConnectionCard/)
    })

    it("ConnectionList exists", () => {
      const src = read("components/sources/ConnectionList.tsx")
      assert.match(src, /export function ConnectionList/)
    })

    it("AddConnectionModal exists", () => {
      const src = read("components/sources/AddConnectionModal.tsx")
      assert.match(src, /export function AddConnectionModal/)
    })

    it("ScopeConfigurator exists", () => {
      const src = read("components/sources/ScopeConfigurator.tsx")
      assert.match(src, /export function ScopeConfigurator/)
    })

    it("ScopeConfigContent exists", () => {
      const src = read("components/sources/ScopeConfigContent.tsx")
      assert.match(src, /export function ScopeConfigContent/)
    })

    it("ConnectionStatusBadge exists", () => {
      const src = read("components/sources/ConnectionStatusBadge.tsx")
      assert.match(src, /export function ConnectionStatusBadge/)
    })
  })
})
