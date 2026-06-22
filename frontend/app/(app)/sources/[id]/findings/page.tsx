import { Suspense } from "react"
import SourceFindingsBoard from "./_SourceFindingsBoard"

// Required for Next.js static export — the actual content is client-rendered.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

export default function SourceFindingsPage() {
  return (
    <Suspense fallback={null}>
      <SourceFindingsBoard />
    </Suspense>
  )
}
