import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { buildRepoFileUrl } from "./repo-link.ts"

describe("buildRepoFileUrl", () => {
  it("builds a github blob URL with line anchor", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api", filePath: "src/server.py:93" }),
      "https://github.com/acme/api/blob/HEAD/src/server.py#L93",
    )
  })

  it("uses gitlab's /-/blob/ path shape", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "gitlab:acme/api", filePath: "src/server.py:93" }),
      "https://gitlab.com/acme/api/-/blob/HEAD/src/server.py#L93",
    )
  })

  it("uses bitbucket's /src/ path and #lines- anchor", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "bitbucket:acme/api", filePath: "src/server.py:93" }),
      "https://bitbucket.org/acme/api/src/HEAD/src/server.py#lines-93",
    )
  })

  it("pins to a commit ref when supplied", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api", filePath: "a.py:5", commit: "abc1234" }),
      "https://github.com/acme/api/blob/abc1234/a.py#L5",
    )
  })

  it("strips the runner clone prefix to a repo-relative path", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api", filePath: "api/_checkout/src/x.py:7" }),
      "https://github.com/acme/api/blob/HEAD/src/x.py#L7",
    )
  })

  it("omits the line anchor when the location has no line", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api", filePath: "Dockerfile" }),
      "https://github.com/acme/api/blob/HEAD/Dockerfile",
    )
  })

  it("falls back to the repo root when there is no file path", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api" }),
      "https://github.com/acme/api",
    )
  })

  it("percent-encodes path segments but keeps the slashes", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "github:acme/api", filePath: "src/my file.py:3" }),
      "https://github.com/acme/api/blob/HEAD/src/my%20file.py#L3",
    )
  })

  it("returns null for an unprefixed (manual/CI) repo ref", () => {
    assert.equal(buildRepoFileUrl({ repo: "acme/api", filePath: "a.py:1" }), null)
  })

  it("returns null for a self-hosted provider with no known host", () => {
    assert.equal(buildRepoFileUrl({ repo: "gitea:acme/api", filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "azure_devops:acme/api", filePath: "a.py:1" }), null)
  })

  it("returns null when the repo ref is missing or malformed", () => {
    assert.equal(buildRepoFileUrl({ repo: undefined, filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "github:", filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "github:acme", filePath: "a.py:1" }), null)
  })
})
