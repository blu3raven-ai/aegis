import test from "node:test"
import assert from "node:assert/strict"

import { buildRepoFileUrl } from "../../frontend/lib/shared/findings/repo-link.ts"

test("buildRepoFileUrl: concrete cloud URL without a repo ref still deep-links to file+line", () => {
  // Secret/agent findings arrive with repo=null but a concrete repoHtmlUrl.
  const url = buildRepoFileUrl({
    repo: undefined,
    filePath: "backend/src/main.py:52",
    commit: "0c5e4c6712e4eb08ecc45190a7b0f45c90e98961",
    repoHtmlUrl: "https://github.com/blu3raven-ai/aegis",
  })
  assert.equal(
    url,
    "https://github.com/blu3raven-ai/aegis/blob/0c5e4c6712e4eb08ecc45190a7b0f45c90e98961/backend/src/main.py#L52",
  )
})

test("buildRepoFileUrl: parsed ref still produces file+line link (unchanged)", () => {
  const url = buildRepoFileUrl({
    repo: "github:blu3raven-ai/aegis",
    filePath: "backend/src/main.py:52",
    commit: undefined,
    repoHtmlUrl: null,
  })
  assert.equal(url, "https://github.com/blu3raven-ai/aegis/blob/HEAD/backend/src/main.py#L52")
})

test("buildRepoFileUrl: gitlab host infers the gitlab path shape", () => {
  const url = buildRepoFileUrl({
    repo: undefined,
    filePath: "app/models/user.rb:10",
    commit: undefined,
    repoHtmlUrl: "https://gitlab.com/acme/app",
  })
  assert.equal(url, "https://gitlab.com/acme/app/-/blob/HEAD/app/models/user.rb#L10")
})

test("buildRepoFileUrl: unknown self-hosted host without a ref falls back to repo root", () => {
  const url = buildRepoFileUrl({
    repo: undefined,
    filePath: "src/x.py:5",
    commit: undefined,
    repoHtmlUrl: "https://git.internal.example/team/repo",
  })
  assert.equal(url, "https://git.internal.example/team/repo")
})

test("buildRepoFileUrl: no repo ref and no concrete URL returns null", () => {
  const url = buildRepoFileUrl({
    repo: "aegis",
    filePath: "src/x.py:5",
    commit: undefined,
    repoHtmlUrl: null,
  })
  assert.equal(url, null)
})
