import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  baseOsFamily,
  formatBytes,
  registryOf,
  repoPathOf,
  scanFreshness,
  shortDigest,
} from "./format.ts"

describe("registryOf", () => {
  it("treats first segment with a dot or colon as the registry host", () => {
    assert.equal(registryOf("ghcr.io/acme/api"), "ghcr.io")
    assert.equal(
      registryOf("123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/billing"),
      "123456789012.dkr.ecr.us-east-1.amazonaws.com",
    )
    assert.equal(registryOf("registry:5000/acme/api"), "registry:5000")
    assert.equal(registryOf("localhost/acme/api"), "localhost")
  })

  it("defaults bare paths to docker.io", () => {
    assert.equal(registryOf("library/alpine"), "docker.io")
    assert.equal(registryOf("acme/api"), "docker.io")
    assert.equal(registryOf("alpine"), "docker.io")
  })

  it("returns a sentinel for null", () => {
    assert.equal(registryOf(null), "unknown registry")
  })
})

describe("repoPathOf", () => {
  it("strips a registry host prefix", () => {
    assert.equal(repoPathOf("ghcr.io/acme/api"), "acme/api")
  })

  it("returns the full path for docker.io implicit paths", () => {
    assert.equal(repoPathOf("acme/api"), "acme/api")
  })

  it("returns empty for null", () => {
    assert.equal(repoPathOf(null), "")
  })
})

describe("scanFreshness", () => {
  it("returns never when the image has not been scanned", () => {
    assert.equal(scanFreshness(null), "never")
  })

  it("returns fresh when last scan is recent", () => {
    const recent = new Date(Date.now() - 1000 * 60 * 60).toISOString()
    assert.equal(scanFreshness(recent), "fresh")
  })

  it("returns stale once last scan is older than 14 days", () => {
    const old = new Date(Date.now() - 1000 * 60 * 60 * 24 * 15).toISOString()
    assert.equal(scanFreshness(old), "stale")
  })
})

describe("formatBytes", () => {
  it("returns null when bytes are missing", () => {
    assert.equal(formatBytes(null), null)
  })

  it("renders human-readable sizes", () => {
    assert.equal(formatBytes(500), "500 B")
    assert.equal(formatBytes(1024 * 4), "4 KB")
    assert.equal(formatBytes(1024 * 1024 * 42), "42 MB")
    assert.equal(formatBytes(1024 * 1024 * 1024 * 2), "2.00 GB")
  })
})

describe("shortDigest", () => {
  it("truncates a sha256 prefix to six chars", () => {
    assert.equal(shortDigest("sha256:abcdef0123456789"), "sha256:abcdef…")
  })

  it("handles digests without a sha256 prefix", () => {
    assert.equal(shortDigest("deadbeefcafe"), "sha256:deadbe…")
  })
})

describe("baseOsFamily", () => {
  it("matches common families case-insensitively", () => {
    assert.equal(baseOsFamily("alpine:3.19"), "alpine")
    assert.equal(baseOsFamily("debian:bookworm"), "debian")
    assert.equal(baseOsFamily("ubuntu 22.04"), "ubuntu")
    assert.equal(baseOsFamily("distroless"), "distroless")
    assert.equal(baseOsFamily("Wolfi"), "wolfi")
  })

  it("returns unknown for null and other for unrecognized", () => {
    assert.equal(baseOsFamily(null), "unknown")
    assert.equal(baseOsFamily("some-mystery-os"), "other")
  })
})
