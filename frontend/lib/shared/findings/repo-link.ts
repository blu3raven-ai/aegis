/**
 * Deep-link a finding's location back to its source repository.
 *
 * A finding's `repo` is the backend's canonical ref `<sourceType>:<owner>/<name>`
 * (e.g. `github:acme/api`, `gitlab:acme/api`) — the `sourceType` prefix tells us
 * which SCM provider hosts it, so the web URL is derived per-provider rather than
 * assuming one host. Cloud-hosted providers resolve to their canonical host;
 * self-hosted providers have no fixed host and return null until the backend
 * supplies the concrete repo URL.
 */

interface RepoRef {
  /** Lowercased SCM provider key, e.g. "github". */
  provider: string
  owner: string
  name: string
}

/** Builds blob (file) and home (repo root) web URLs for one SCM provider. */
interface ProviderUrls {
  /** Repo root, e.g. https://github.com/acme/api */
  home: (ref: RepoRef) => string
  /** A file at a ref+line, e.g. https://github.com/acme/api/blob/HEAD/src/x.py#L42 */
  blob: (ref: RepoRef, gitRef: string, path: string, line?: number) => string
}

/**
 * Cloud-hosted providers we can resolve from the source type alone. Self-hosted
 * providers (gitea, azure_devops, jenkins) have no canonical host, so they are
 * intentionally absent — those need the concrete repo URL from the backend.
 */
const PROVIDERS: Record<string, ProviderUrls> = {
  github: {
    home: (r) => `https://github.com/${r.owner}/${r.name}`,
    blob: (r, ref, path, line) =>
      `https://github.com/${r.owner}/${r.name}/blob/${ref}/${path}${line ? `#L${line}` : ""}`,
  },
  gitlab: {
    home: (r) => `https://gitlab.com/${r.owner}/${r.name}`,
    blob: (r, ref, path, line) =>
      `https://gitlab.com/${r.owner}/${r.name}/-/blob/${ref}/${path}${line ? `#L${line}` : ""}`,
  },
  bitbucket: {
    home: (r) => `https://bitbucket.org/${r.owner}/${r.name}`,
    blob: (r, ref, path, line) =>
      `https://bitbucket.org/${r.owner}/${r.name}/src/${ref}/${path}${line ? `#lines-${line}` : ""}`,
  },
}

/** Parse `<sourceType>:<owner>/<name>`; null for unprefixed (manual/CI) refs. */
function parseRepoRef(repo: string | undefined): RepoRef | null {
  if (!repo) return null
  const colon = repo.indexOf(":")
  if (colon <= 0) return null
  const provider = repo.slice(0, colon).toLowerCase()
  const slug = repo.slice(colon + 1)
  const slash = slug.indexOf("/")
  if (slash <= 0 || slash === slug.length - 1) return null
  return { provider, owner: slug.slice(0, slash), name: slug.slice(slash + 1) }
}

/**
 * Reduce a scanner-emitted path to its repo-relative form. The runner clones
 * into `<job>/<repo>/_checkout/`, so paths arrive either workspace-prefixed or
 * `_checkout/`-anchored; keep only the part below the clone root.
 */
function repoRelativePath(filePath: string): string {
  const marker = "_checkout/"
  const idx = filePath.lastIndexOf(marker)
  const rel = idx === -1 ? filePath : filePath.slice(idx + marker.length)
  return rel.replace(/^\/+/, "")
}

/** Split a "path:line" location into its path and (optional) trailing line. */
function splitPathAndLine(filePath: string): { path: string; line?: number } {
  const match = filePath.match(/^(.*):(\d+)$/)
  if (!match) return { path: filePath }
  return { path: match[1], line: Number(match[2]) }
}

/** Percent-encode each path segment while preserving the slashes. */
function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/")
}

export interface RepoFileUrlArgs {
  /** Finding's canonical repo ref, e.g. "github:acme/api". */
  repo?: string
  /** Display location "path:line" (workspace-cleaned), or just a path. */
  filePath?: string
  /** Commit/branch ref to pin the link to; defaults to the repo HEAD. */
  commit?: string
}

/**
 * Web URL for a finding's file location, or null when it can't be resolved
 * (unprefixed/manual repo, or a self-hosted provider with no known host).
 * Falls back to the repo root when there is no file path.
 */
export function buildRepoFileUrl({ repo, filePath, commit }: RepoFileUrlArgs): string | null {
  const ref = parseRepoRef(repo)
  if (!ref) return null
  const provider = PROVIDERS[ref.provider]
  if (!provider) return null

  if (!filePath) return provider.home(ref)

  const { path, line } = splitPathAndLine(filePath)
  const rel = repoRelativePath(path)
  if (!rel) return provider.home(ref)

  const gitRef = commit?.trim() || "HEAD"
  return provider.blob(ref, gitRef, encodePath(rel), line)
}
