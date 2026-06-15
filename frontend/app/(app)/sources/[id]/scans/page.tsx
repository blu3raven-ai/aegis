import { History } from "lucide-react"
import { EmptyState } from "@/components/ui/EmptyState"

export default function SourceScansPage() {
  return (
    <div className="px-6 py-6">
      <EmptyState
        icon={History}
        title="No scan history yet"
        description="Scan runs will be recorded here once this source has been scanned."
      />
    </div>
  )
}
