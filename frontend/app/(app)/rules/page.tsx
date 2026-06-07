import { Suspense } from "react"
import { RulesPageContent } from "./RulesPageContent"

export default function RulesPage() {
  return (
    <Suspense fallback={null}>
      <RulesPageContent />
    </Suspense>
  )
}
