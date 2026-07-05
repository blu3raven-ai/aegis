export function relativeScanTime(iso: string | null): string {
  if (!iso) return "never scanned"
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 0) return "just now"
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export type ScanFreshness = "fresh" | "stale" | "never"

const STALE_DAYS = 14

export function scanFreshness(iso: string | null): ScanFreshness {
  if (!iso) return "never"
  const days = (Date.now() - new Date(iso).getTime()) / (1000 * 60 * 60 * 24)
  return days > STALE_DAYS ? "stale" : "fresh"
}

export function formatBytes(bytes: number | null): string | null {
  if (bytes == null) return null
  if (bytes < 1024) return `${bytes} B`
  const kb = bytes / 1024
  if (kb < 1024) return `${kb.toFixed(0)} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb.toFixed(mb < 10 ? 1 : 0)} MB`
  const gb = mb / 1024
  return `${gb.toFixed(gb < 10 ? 2 : 1)} GB`
}

export function shortDigest(digest: string): string {
  const body = digest.startsWith("sha256:") ? digest.slice(7) : digest
  return `sha256:${body.slice(0, 6)}…`
}

export function registryOf(imageName: string | null): string {
  if (!imageName) return "unknown registry"
  const firstSlash = imageName.indexOf("/")
  if (firstSlash === -1) return "docker.io"
  const head = imageName.slice(0, firstSlash)
  if (head.includes(".") || head.includes(":") || head === "localhost") return head
  return "docker.io"
}

export function repoPathOf(imageName: string | null): string {
  if (!imageName) return ""
  const registry = registryOf(imageName)
  if (registry === "docker.io" && !imageName.startsWith("docker.io/")) return imageName
  return imageName.slice(registry.length + 1)
}

const BASE_OS_FAMILIES: { match: RegExp; family: string }[] = [
  { match: /alpine/i, family: "alpine" },
  { match: /debian/i, family: "debian" },
  { match: /ubuntu/i, family: "ubuntu" },
  { match: /distroless/i, family: "distroless" },
  { match: /rhel|redhat|red hat/i, family: "rhel" },
  { match: /centos/i, family: "centos" },
  { match: /amazon|amzn/i, family: "amazon" },
  { match: /wolfi/i, family: "wolfi" },
  { match: /chainguard/i, family: "chainguard" },
]

export function baseOsFamily(baseOs: string | null): string {
  if (!baseOs) return "unknown"
  const hit = BASE_OS_FAMILIES.find((f) => f.match.test(baseOs))
  return hit?.family ?? "other"
}
