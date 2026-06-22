import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { sourceDisplayName } from "./sources-types.ts"

const base = {
  sourceType: "github" as const,
  auth: { orgOrOwner: "acme-org" },
}

describe("sourceDisplayName", () => {
  it("uses a custom name when one was set", () => {
    assert.equal(sourceDisplayName({ ...base, name: "Payments repos" }), "Payments repos")
  })

  it("falls back to the org when the name is just the provider default", () => {
    // Sources created without a name default to the provider label ("GitHub").
    assert.equal(sourceDisplayName({ ...base, name: "GitHub" }), "acme-org")
  })

  it("prefers org, then group/project, then username", () => {
    assert.equal(
      sourceDisplayName({ sourceType: "gitlab", name: "GitLab", auth: { groupOrProject: "acme-group" } }),
      "acme-group",
    )
    assert.equal(
      sourceDisplayName({ sourceType: "docker-hub", name: "Docker Hub", auth: { username: "acme-user" } }),
      "acme-user",
    )
  })

  it("falls back to the provider label when nothing else identifies it", () => {
    assert.equal(sourceDisplayName({ sourceType: "github", name: "GitHub", auth: {} }), "GitHub")
  })
})
