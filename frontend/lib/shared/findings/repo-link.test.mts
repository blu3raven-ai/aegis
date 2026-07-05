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

  it("uses gitea's /src/branch/ path shape and #L anchor", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "gitea:acme/api", filePath: "src/server.py:93" }),
      "https://gitea.com/acme/api/src/branch/HEAD/src/server.py#L93",
    )
  })

  it("routes a gitea commit SHA through /src/commit/", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "gitea:acme/api", filePath: "a.py:5", commit: "abc1234" }),
      "https://gitea.com/acme/api/src/commit/abc1234/a.py#L5",
    )
  })

  it("honors a self-hosted gitea host from repoHtmlUrl", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "gitea:acme/api",
        filePath: "server.py:15",
        commit: "deadbeefcafe",
        repoHtmlUrl: "https://git.acme-corp.internal/acme/api",
      }),
      "https://git.acme-corp.internal/acme/api/src/commit/deadbeefcafe/server.py#L15",
    )
  })

  it("links to the repo root for a provider without a modelled file scheme (given a concrete URL)", () => {
    // Azure DevOps uses a query-param file scheme we don't model — link to the
    // repo root (a valid page) rather than a guessed file URL that could 404.
    assert.equal(
      buildRepoFileUrl({
        repo: "azure_devops:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://dev.azure.com/acme/proj/_git/api",
      }),
      "https://dev.azure.com/acme/proj/_git/api",
    )
  })

  it("returns null for an unmodelled provider with no concrete URL to fall back to", () => {
    // Azure's org/project/_git/repo root can't be reconstructed from owner/name,
    // so without a concrete repoHtmlUrl there's nothing safe to link to.
    assert.equal(buildRepoFileUrl({ repo: "azure_devops:acme/api", filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "jenkins:host/job", filePath: "a.py:1" }), null)
  })

  it("links to a browsable repo root when the ref is unprefixed but a concrete URL exists", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://scm.internal/acme/api",
      }),
      "https://scm.internal/acme/api",
    )
  })

  it("returns null when the repo ref is missing or malformed", () => {
    assert.equal(buildRepoFileUrl({ repo: undefined, filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "github:", filePath: "a.py:1" }), null)
    assert.equal(buildRepoFileUrl({ repo: "github:acme", filePath: "a.py:1" }), null)
  })
})

describe("buildRepoFileUrl with a self-hosted repoHtmlUrl", () => {
  it("uses the concrete host for a self-hosted GitHub Enterprise repo", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "github:acme/api",
        filePath: "src/server.py:93",
        repoHtmlUrl: "https://github.acme-corp.internal/acme/api",
      }),
      "https://github.acme-corp.internal/acme/api/blob/HEAD/src/server.py#L93",
    )
  })

  it("uses the concrete host + gitlab path shape for a self-hosted GitLab repo", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "gitlab:acme/api",
        filePath: "a.py:5",
        commit: "abc1234",
        repoHtmlUrl: "https://gitlab.acme-corp.internal/acme/api",
      }),
      "https://gitlab.acme-corp.internal/acme/api/-/blob/abc1234/a.py#L5",
    )
  })

  it("strips a trailing slash and .git from the concrete URL", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "github:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://ghe.internal/acme/api.git/",
      }),
      "https://ghe.internal/acme/api/blob/HEAD/a.py#L1",
    )
  })

  it("honours a cloud repoHtmlUrl that matches the provider host", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "github:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://github.com/acme/api",
      }),
      "https://github.com/acme/api/blob/HEAD/a.py#L1",
    )
  })

  it("resolves self-hosted Bitbucket Server: /scm/ clone URL → /projects/repos browse link", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "bitbucket:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://bitbucket.acme-corp.internal/scm/acme/api",
      }),
      "https://bitbucket.acme-corp.internal/projects/acme/repos/api/browse/a.py#1",
    )
  })

  it("resolves a Bitbucket Server web root URL directly to a browse link", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "bitbucket:acme/api",
        filePath: "src/a.py:9",
        repoHtmlUrl: "https://bitbucket.acme-corp.internal/projects/ACME/repos/api",
      }),
      "https://bitbucket.acme-corp.internal/projects/ACME/repos/api/browse/src/a.py#9",
    )
  })

  it("still resolves cloud Bitbucket via its concrete URL", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "bitbucket:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "https://bitbucket.org/acme/api",
      }),
      "https://bitbucket.org/acme/api/src/HEAD/a.py#lines-1",
    )
  })

  it("ignores a non-http(s) repoHtmlUrl and falls back to the cloud host", () => {
    assert.equal(
      buildRepoFileUrl({
        repo: "github:acme/api",
        filePath: "a.py:1",
        repoHtmlUrl: "javascript:alert(1)",
      }),
      "https://github.com/acme/api/blob/HEAD/a.py#L1",
    )
  })

  it("falls back to the cloud host when repoHtmlUrl is null", () => {
    assert.equal(
      buildRepoFileUrl({ repo: "gitlab:acme/api", filePath: "a.py:1", repoHtmlUrl: null }),
      "https://gitlab.com/acme/api/-/blob/HEAD/a.py#L1",
    )
  })
})
