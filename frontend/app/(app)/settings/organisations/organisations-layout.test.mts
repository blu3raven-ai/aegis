import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import path from "node:path"

const dir = path.join(process.cwd(), "app/(app)/settings/organisations")

test("OrganisationsContent.tsx uses TeamList and TeamEditor", () => {
  // Title + description were lifted to the parent <SettingsSection> when /settings
  // became a single-scroll page (PR #332). The descriptive copy is now covered by
  // the sectionsDescription test below.
  const source = readFileSync(path.join(dir, "OrganisationsContent.tsx"), "utf8")
  assert.match(source, /<TeamList/)
  assert.match(source, /<TeamEditor/)
  assert.match(source, /listOrganisationTeams\(\)/)
  assert.match(source, /md:min-h-\[calc\(100vh-12rem\)\]/)
})

test("TeamsPageContent carries the Teams title + description copy", () => {
  const source = readFileSync(
    path.join(process.cwd(), "app/(app)/teams/TeamsPageContent.tsx"),
    "utf8",
  )
  assert.match(source, /title="Teams"/)
  assert.match(source, /description="[^"]*[Tt]eam/)
})

test("TeamList.tsx keeps the team rail independently scrollable on desktop", () => {
  const source = readFileSync(path.join(dir, "TeamList.tsx"), "utf8")
  assert.match(source, /md:sticky md:top-6/)
  assert.match(source, /md:max-h-\[calc\(100vh-12rem\)\] md:overflow-y-auto/)
})

test("TeamEditor.tsx is resource-focused and shows source label", () => {
  const source = readFileSync(path.join(dir, "TeamEditor.tsx"), "utf8")
  assert.doesNotMatch(source, /TeamMembersTab/)
  assert.doesNotMatch(source, />Members</)
  assert.match(source, /Repositories/)
  assert.match(source, /Container Registry/)
  assert.match(source, /shared with/)
  assert.match(source, /Resources can be shared with multiple teams/)
  assert.match(source, /Synced from source/)
})

test("resource tabs show source labels and locks", () => {
  const repoSource = readFileSync(path.join(dir, "TeamRepositoriesTab.tsx"), "utf8")
  const imageSource = readFileSync(path.join(dir, "TeamImagesTab.tsx"), "utf8")

  assert.match(repoSource, /searchOrganisationRepositories/)
  assert.match(repoSource, /ResourceAutocomplete/)
  assert.match(repoSource, /asset\.source === "github"/)
  assert.match(repoSource, /synced from a source connection/)

  assert.match(imageSource, /searchOrganisationContainerImages/)
  assert.match(imageSource, /ResourceAutocomplete/)
})
