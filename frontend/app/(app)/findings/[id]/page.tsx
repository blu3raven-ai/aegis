import { FindingRedirectClient } from "./FindingRedirectClient"

// Static-export stub so the build succeeds; the FastAPI SPA fallback serves
// this shell for any real finding id, which the client reads at runtime.
export function generateStaticParams(): { id: string }[] {
  return [{ id: "_" }]
}

/**
 * Canonical per-finding URL. Findings open in a drawer over the list rather
 * than on a dedicated detail page, so `/findings/<id>` redirects to the list
 * with `?finding=<id>` (which opens that finding's drawer). This keeps every
 * `/findings/<id>` link across the app (activity feed, dashboard, releases,
 * compliance) working without a standalone detail route.
 */
export default function FindingRedirectPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  return <FindingRedirectClient params={params} />
}
