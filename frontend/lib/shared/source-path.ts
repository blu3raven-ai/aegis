// Extract the source-connection id from a /sources/<id>[/...] pathname.
//
// In a static export (`output: export`) the dynamic [id] segment is prerendered
// with the generateStaticParams stub id="_", so the router's param context
// returns "_" on a hard load or refresh — every API call then hits
// /sources/connections/_ and 404s. Deriving the id from the live pathname
// instead yields the real connection id on both client navigation and direct
// load. Returns "" for the stub id ("_") or any non-source path so callers can
// skip the doomed fetch.
export function sourceIdFromPathname(pathname: string): string {
  const segments = pathname.split("/").filter(Boolean)
  // ["sources", "<id>", ...]
  if (segments[0] !== "sources") return ""
  const id = segments[1] ?? ""
  return id === "_" ? "" : id
}
