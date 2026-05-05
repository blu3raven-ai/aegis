import { redirect } from "next/navigation"
import { getToolEnabledOrgs } from "@/lib/server/tool-orgs"

export default async function CodeScanningLandingPage() {
  const org = (await getToolEnabledOrgs("codeScanning"))[0]
  if (org) {
    redirect(`/code/${org}`)
  }
  redirect("/code/dashboard")
}
