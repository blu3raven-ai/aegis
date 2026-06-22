import { SourceScansPageContent } from "./SourceScansPageContent"

// Returns a stub so the static export build succeeds.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function SourceScansPage() {
  return <SourceScansPageContent />
}
