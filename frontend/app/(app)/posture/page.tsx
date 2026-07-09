import { PostureIcon } from "@/lib/shared/ui/page-icons"
import { PageHeader } from "@/components/layout/PageHeader"
import { PosturePageContent } from "./PosturePageContent"

export default function PosturePage() {
  return (
    <>
      <PageHeader
        icon={<PostureIcon />}
        title="Posture"
        description="Risk score, severity trend, and repository coverage"
      />
      <PosturePageContent />
    </>
  )
}
