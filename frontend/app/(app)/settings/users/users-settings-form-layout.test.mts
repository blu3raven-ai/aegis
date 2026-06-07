import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const source = readFileSync(new URL("./UsersSettingsForm.tsx", import.meta.url), "utf8")

test("users table exposes deletion as a trash action", () => {
  assert.match(source, /async function handleDeleteUser\(user: UserEntry\)/)
  assert.match(source, /apiClient\(`\/settings\/api\/users\/\$\{user\.id\}`,\s*\{[\s\S]*method: "DELETE"[\s\S]*\}/)
  assert.match(source, /aria-label=\{`Delete \$\{user\.username\}`\}/)
  assert.match(source, /<path d=\{TRASH_ICON\}/)
  assert.match(source, /You cannot delete your own account/)
})

test("users form manages team assignments and shows source labels", () => {
  assert.match(source, /listOrganisationTeams/)
  assert.match(source, /listUserDirectory/)
  assert.match(source, /Team memberships/)
  assert.match(source, /Direct Access/)
  assert.match(source, /addOrganisationTeamMember/)
  assert.match(source, /removeOrganisationTeamMember/)
  assert.match(source, /member(!?)\.source === "github"/)
})

test("direct access autocomplete uses the controlled shared component API", () => {
  assert.match(source, /searchOrganisationRepositories/)
  assert.match(source, /searchOrganisationContainerImages/)
  assert.match(source, /const \[directRepoValue, setDirectRepoValue\]/)
  assert.match(source, /const \[directImageValue, setDirectImageValue\]/)
  assert.match(source, /<ResourceAutocomplete[\s\S]*value=\{directRepoValue\}[\s\S]*suggestions=\{directRepoSuggestions\}[\s\S]*onChange=\{\(next\) => void updateDirectRepoValue\(next\)\}[\s\S]*onPick=\{\(next\) => void handleAddDirectGrant\(user\.id, "repository", next\)\}/)
  assert.match(source, /<ResourceAutocomplete[\s\S]*value=\{directImageValue\}[\s\S]*suggestions=\{directImageSuggestions\}[\s\S]*onChange=\{\(next\) => void updateDirectImageValue\(next\)\}[\s\S]*onPick=\{\(next\) => void handleAddDirectGrant\(user\.id, "containerImage", next\)\}/)
})

test("users form supports pending user activation", () => {
  assert.match(source, /user\.status === "pending"/)
  assert.match(source, /Activate/)
})

test("users form supports admin password reset", () => {
  assert.match(source, /setShowResetPassword/)
  assert.match(source, /handleResetPassword/)
  assert.match(source, /reset-password/)
})

test("team assignment controls do not ask admins to type raw user ids", () => {
  assert.doesNotMatch(source, /User ID \(e\.g\. usr_\.\.\.\)/)
})

test("users form assigns roles from role records instead of fixed enum only", () => {
  const source = readFileSync(new URL("./UsersSettingsForm.tsx", import.meta.url), "utf8")
  assert.match(source, /roleId/)
  assert.match(source, /listRoles|getRoles/)
})
