import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterEach, test } from "node:test"
import assert from "node:assert/strict"

import {
  createUser,
  resetUserPassword,
  setUserStorePathForTests,
} from "./users.ts"

let cleanupPath: string | null = null

function useTempStore() {
  const dir = mkdtempSync(path.join(tmpdir(), "dashboard-users-update-"))
  cleanupPath = dir
  const file = path.join(dir, "users.json")
  setUserStorePathForTests(file)
  return file
}

afterEach(() => {
  setUserStorePathForTests(null)
  if (cleanupPath) rmSync(cleanupPath, { recursive: true, force: true })
  cleanupPath = null
})

test("createUser leaves passwordResetRequired disabled for admin-provisioned users", async () => {
  useTempStore()
  const user = await createUser({
    username: "testuser",
    password: "password123",
    role: "viewer",
  })

  assert.equal(user.passwordResetRequired, false, "Manual user should be able to sign in with the assigned password")
})

test("resetUserPassword leaves passwordResetRequired disabled", async () => {
  useTempStore()
  const user = await createUser({
    username: "testuser",
    password: "old-password",
    role: "viewer",
  })

  const updated = await resetUserPassword(user.id, "new-password")
  assert.equal(updated.passwordResetRequired, false, "Admin reset should leave the account ready for sign-in")
})

test("updateOwnAccount can preserve an explicit passwordResetRequired change", async () => {
  useTempStore()
  const user = await createUser({
    username: "testuser",
    password: "password123",
    role: "viewer",
  })

  assert.equal(user.passwordResetRequired, false)

  const { updateOwnAccount } = await import("./users.ts")
  const updated = await updateOwnAccount({
    id: user.id,
    username: user.username,
    passwordResetRequired: false,
  })

  assert.equal(updated.passwordResetRequired, false, "Flag should be cleared after password update")
})

test("createUserWithEmailForTest sets passwordResetRequired to false", async () => {
  useTempStore()
  const { createUserWithEmailForTest } = await import("./users.ts")
  const user = await createUserWithEmailForTest({
    username: "invited-user",
    email: "invited@example.com",
    role: "viewer",
  })

  assert.equal(user.passwordResetRequired, false, "Provisioned user should be able to sign in with the assigned password")
})
