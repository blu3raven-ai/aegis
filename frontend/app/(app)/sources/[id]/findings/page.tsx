import { Bug } from "lucide-react"
import { EmptyState } from "@/components/ui/EmptyState"

export default function SourceFindingsPage() {
  return (
    <div className="px-6 py-6">
      <EmptyState
        icon={Bug}
        title="No findings linked yet"
        description="Findings will appear here once scanners are wired to this source."
      />
    </div>
  )
}
