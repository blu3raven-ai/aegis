import test from "node:test"
import assert from "node:assert/strict"

import { isLocalOrigin } from "../../frontend/lib/shared/local-origin.ts"

test("isLocalOrigin: flags localhost with any port", () => {
  assert.equal(isLocalOrigin("http://localhost:3000"), true)
  assert.equal(isLocalOrigin("http://localhost"), true)
})

test("isLocalOrigin: flags loopback and unspecified addresses", () => {
  assert.equal(isLocalOrigin("http://127.0.0.1:3000"), true)
  assert.equal(isLocalOrigin("http://0.0.0.0:8000"), true)
  assert.equal(isLocalOrigin("http://[::1]:3000"), true)
})

test("isLocalOrigin: flags .localhost subdomains", () => {
  assert.equal(isLocalOrigin("http://aegis.localhost:3000"), true)
})

test("isLocalOrigin: does not flag public hostnames", () => {
  assert.equal(isLocalOrigin("https://scan.example.com"), false)
  assert.equal(isLocalOrigin("https://aegis.internal"), false)
})

test("isLocalOrigin: does not flag a private LAN IP (reachable on the network)", () => {
  assert.equal(isLocalOrigin("http://192.168.0.10:3000"), false)
})

test("isLocalOrigin: returns false for an unparseable origin", () => {
  assert.equal(isLocalOrigin(""), false)
  assert.equal(isLocalOrigin("not a url"), false)
})
