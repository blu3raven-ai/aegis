import { ControlDetailPageContent } from "./ControlDetailPageContent"

// Returns a stub so the static export build succeeds.
// FastAPI SPA fallback serves this shell for any actual framework/controlId.
export function generateStaticParams(): { framework: string; controlId: string }[] {
  return [{ framework: "_", controlId: "_" }]
}

export default function ControlDetailPage(_props: { params: Promise<{ framework: string; controlId: string }> }) {
  return <ControlDetailPageContent />
}
