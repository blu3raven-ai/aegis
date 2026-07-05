import { PostureIcon } from "@/lib/shared/ui/page-icons"
import { PageHeader } from "@/components/layout/PageHeader"
import { PosturePageContent } from "./PosturePageContent"

export const metadata = { title: "Insights" }

export default function InsightsPage() {
  return (
    <>
      <PageHeader
        icon={<PostureIcon />}
        title="Insights"
        description="Risk score, severity trend, and repository coverage"
      />
      <PosturePageContent />
    </>
  )
}
