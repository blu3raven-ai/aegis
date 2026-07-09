import { ReportsIcon } from "@/lib/shared/ui/page-icons"
import { PageHeader } from "@/components/layout/PageHeader"
import { ReportsPageContent } from "./ReportsPageContent"

export default function ReportsPage() {
  return (
    <>
      <PageHeader
        icon={<ReportsIcon />}
        title="Reports"
        description="Generate and download security reports"
      />
      <ReportsPageContent />
    </>
  )
}
