import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { mapApiFinding, normaliseReachability, normaliseScanner } from "./row-mapper.ts"
import type { Finding as ApiFinding } from "../../client/findings-api.ts"

function apiFinding(overrides: Partial<ApiFinding> = {}): ApiFinding {
  return {
    id: "1",
    scanner: "code_scanning",
    severity: "high",
    state: "open",
    title: "SQL injection",
    cve: null,
    package: null,
    file_path: "app/db.py",
    line: 42,
    repo: "acme/api",
    org_id: "acme",
    created_at: null,
    updated_at: null,
    ...overrides,
  }
}

describe("normaliseReachability", () => {
  for (const v of ["reachable", "no_path", "unknown"] as const) {
    it(`passes through the valid value ${v}`, () => {
      assert.equal(normaliseReachability(v), v)
    })
  }

  it("drops unknown/garbage values to undefined", () => {
    assert.equal(normaliseReachability("nope"), undefined)
    assert.equal(normaliseReachability(null), undefined)
    assert.equal(normaliseReachability(undefined), undefined)
  })
})

describe("mapApiFinding — verification fields", () => {
  it("maps exploit_chain, verification_metadata, and reachability", () => {
    const meta = { model: "argus", tokens_in: 100, tokens_out: 20 }
    const row = mapApiFinding(
      apiFinding({
        exploit_chain: "Tainted param flows into raw SQL.",
        verification_metadata: meta,
        reachability: "reachable",
      }),
    )
    assert.equal(row.exploitChain, "Tainted param flows into raw SQL.")
    assert.deepEqual(row.verificationMetadata, meta)
    assert.equal(row.reachability, "reachable")
  })

  it("normalises evidence and coerces an unknown kind to gate", () => {
    const row = mapApiFinding(
      apiFinding({
        evidence: [
          { file: "app/views.py", line: 10, snippet: "q = request.GET['q']", kind: "source" },
          { file: "app/db.py", line: 42, snippet: "cursor.execute(q)", kind: "weird" },
        ],
      }),
    )
    assert.equal(row.evidence?.length, 2)
    assert.equal(row.evidence?.[0].kind, "source")
    assert.equal(row.evidence?.[1].kind, "gate")
  })

  it("drops evidence items with no snippet and returns undefined when none remain", () => {
    const row = mapApiFinding(
      apiFinding({ evidence: [{ file: "x", line: 1, kind: "sink" }] }),
    )
    assert.equal(row.evidence, undefined)
  })

  it("leaves verification fields undefined for an unverified finding", () => {
    const row = mapApiFinding(apiFinding())
    assert.equal(row.evidence, undefined)
    assert.equal(row.exploitChain, undefined)
    assert.equal(row.verificationMetadata, undefined)
    assert.equal(row.reachability, undefined)
  })

  it("maps the introducing commit", () => {
    const row = mapApiFinding(apiFinding({ introduced_by_commit: "abc123def" }))
    assert.equal(row.introducedByCommit, "abc123def")
    assert.equal(mapApiFinding(apiFinding()).introducedByCommit, undefined)
  })

  it("maps the blast-radius count", () => {
    assert.equal(mapApiFinding(apiFinding({ also_affects_repos: 4 })).alsoAffectsRepos, 4)
    assert.equal(mapApiFinding(apiFinding()).alsoAffectsRepos, undefined)
  })

  it("maps container image context, nulls → undefined", () => {
    const row = mapApiFinding(
      apiFinding({
        container_image: {
          name: "acme/api",
          tag: "1.4.2",
          digest: "sha256:abcd",
          base_os: "debian 12",
          layer_count: 9,
          layer_digest: "sha256:layer3",
          layer_index: 2,
          newer_tags: ["1.5.0", "2.0.0"],
          layer_concentration: { layer_index: 0, finding_count: 5, total_with_layer: 8 },
          base_image_recommendation: {
            recommended_tag: "2.0.0", current_vuln_count: 14, recommended_vuln_count: 2,
          },
        },
      }),
    )
    assert.deepEqual(row.containerImage, {
      name: "acme/api",
      tag: "1.4.2",
      digest: "sha256:abcd",
      baseOs: "debian 12",
      layerCount: 9,
      layerDigest: "sha256:layer3",
      layerIndex: 2,
      newerTags: ["1.5.0", "2.0.0"],
      layerConcentration: { layerIndex: 0, findingCount: 5, totalWithLayer: 8 },
      baseImageRecommendation: { recommendedTag: "2.0.0", currentVulnCount: 14, recommendedVulnCount: 2 },
    })
    assert.equal(mapApiFinding(apiFinding()).containerImage, undefined)
    const partial = mapApiFinding(
      apiFinding({
        container_image: {
          name: "x", tag: null, digest: null, base_os: null, layer_count: null,
          layer_digest: null, layer_index: null, newer_tags: null, layer_concentration: null,
          base_image_recommendation: null,
        },
      }),
    ).containerImage
    assert.equal(partial?.name, "x")
    assert.equal(partial?.tag, undefined)
    assert.equal(partial?.digest, undefined)
    assert.equal(partial?.baseOs, undefined)
    assert.equal(partial?.layerCount, undefined)
  })
})

describe("mapApiFinding — filePath cleaning", () => {
  it("leaves an already repo-relative path untouched", () => {
    const row = mapApiFinding(apiFinding({ file_path: "app/db.py", line: 42 }))
    assert.equal(row.filePath, "app/db.py:42")
  })

  it("strips the runner's <repo>/_checkout/ clone-dir prefix", () => {
    const row = mapApiFinding(
      apiFinding({ file_path: "example-repo/_checkout/server.py", line: 93 }),
    )
    assert.equal(row.filePath, "server.py:93")
  })

  it("re-anchors on the last _checkout/ and keeps the repo-relative subpath", () => {
    const row = mapApiFinding(
      apiFinding({ file_path: "repo/_checkout/src/api/handler.py", line: 7 }),
    )
    assert.equal(row.filePath, "src/api/handler.py:7")
  })

  it("strips a workspace/job prefix ahead of the _checkout segment", () => {
    const row = mapApiFinding(
      apiFinding({
        file_path: "/workspace/job-abc123/repo/_checkout/main.go",
        line: 12,
      }),
    )
    assert.equal(row.filePath, "main.go:12")
  })
})

describe("normaliseScanner", () => {
  it("maps the canonical long scanner names to themselves", () => {
    assert.equal(normaliseScanner("secret_scanning"), "secret_scanning")
    assert.equal(normaliseScanner("code_scanning"), "code_scanning")
    assert.equal(normaliseScanner("iac_scanning"), "iac_scanning")
    assert.equal(normaliseScanner("agent_scanning"), "agent_scanning")
  })

  it("maps the backend public shorthand (from the REST detail endpoint)", () => {
    // Regression: a secret opened by deep-link arrived as "secrets" and fell
    // through to the dependencies fallback, showing the deps reachability panel.
    assert.equal(normaliseScanner("secrets"), "secret_scanning")
    assert.equal(normaliseScanner("sast"), "code_scanning")
    assert.equal(normaliseScanner("deps"), "dependencies_scanning")
    assert.equal(normaliseScanner("iac"), "iac_scanning")
    assert.equal(normaliseScanner("agent"), "agent_scanning")
    assert.equal(normaliseScanner("container"), "container_scanning")
  })

  it("still falls back for genuinely unknown values", () => {
    assert.equal(normaliseScanner("nope"), "dependencies_scanning")
  })
})
