import { test, describe } from "node:test"
import assert from "node:assert/strict"

import {
  bucketBulkMatches,
  type BulkExposureMatch,
} from "../../frontend/lib/sbom/bulk-exposure.ts"

function m(query: string, exposure: BulkExposureMatch["exposure"]): BulkExposureMatch {
  return { query, exposure }
}

describe("bucketBulkMatches", () => {
  test("splits matches into the five exposure buckets", () => {
    const buckets = bucketBulkMatches([
      m("lodash@4.17.21", "flagged_in_use"),
      m("semver@7.5.0", "latent"),
      m("axios@9.9.9", "other_versions"),
      m("react", "present"),
      m("ghost", "not_found"),
    ])
    assert.deepEqual(buckets.flaggedInUse.map((x) => x.query), ["lodash@4.17.21"])
    assert.deepEqual(buckets.latent.map((x) => x.query), ["semver@7.5.0"])
    assert.deepEqual(buckets.otherVersions.map((x) => x.query), ["axios@9.9.9"])
    assert.deepEqual(buckets.present.map((x) => x.query), ["react"])
    assert.deepEqual(buckets.notFound.map((x) => x.query), ["ghost"])
  })

  test("routes a latent match only into the latent bucket", () => {
    const buckets = bucketBulkMatches([m("semver@7.5.0", "latent")])
    assert.deepEqual(buckets.latent.map((x) => x.query), ["semver@7.5.0"])
    assert.deepEqual(buckets.flaggedInUse, [])
    assert.deepEqual(buckets.present, [])
    assert.deepEqual(buckets.otherVersions, [])
    assert.deepEqual(buckets.notFound, [])
  })

  test("preserves input order within a bucket", () => {
    const buckets = bucketBulkMatches([
      m("a", "present"),
      m("b", "present"),
      m("c", "present"),
    ])
    assert.deepEqual(buckets.present.map((x) => x.query), ["a", "b", "c"])
  })

  test("treats an unknown exposure as not_found (fail-closed)", () => {
    const buckets = bucketBulkMatches([
      { query: "weird", exposure: "totally_unknown" } as unknown as BulkExposureMatch,
    ])
    assert.deepEqual(buckets.notFound.map((x) => x.query), ["weird"])
  })

  test("returns empty buckets for an empty input", () => {
    const buckets = bucketBulkMatches([])
    assert.deepEqual(buckets, {
      flaggedInUse: [],
      latent: [],
      present: [],
      otherVersions: [],
      notFound: [],
    })
  })
})
