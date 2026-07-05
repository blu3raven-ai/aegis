import { Suspense } from "react"
import { PoliciesPageContent } from "./PoliciesPageContent"

export default function PoliciesPage() {
  return (
    <Suspense fallback={null}>
      <PoliciesPageContent />
    </Suspense>
  )
}
