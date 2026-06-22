import { SourceSettingsPageContent } from "./SourceSettingsPageContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function SourceSettingsPage() {
  return <SourceSettingsPageContent />
}
