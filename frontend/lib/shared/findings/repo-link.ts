/**
 * Deep-link a finding's location back to its source repository.
 *
 * A finding's `repo` is the backend's canonical ref `<sourceType>:<owner>/<name>`
 * (e.g. `github:acme/api`) — the `sourceType` prefix tells us the SCM provider,
 * which fixes the URL *path shape* (`/blob/` vs `/-/blob/` vs `/src/`). The
 * *host* comes from `repoHtmlUrl` when the backend supplies it (the concrete repo
 * URL the runner cloned from, so self-hosted hosts like an in-house GitLab work),
 * else the provider's canonical cloud host.
 *
 * Goal: a "View in repository" link for *any* git source. We emit a precise
 * file+line link for every provider whose path shape we model
 * (GitHub/GitLab/Gitea/Bitbucket, cloud and self-hosted). For anything we can't
 * pinpoint to a line (Azure DevOps' query scheme, an unmodelled host, or a
 * finding with no file), we fall back to the repo *root* — always a valid page,
 * never a guessed file URL that could 404. We return null only when there is no
 * browsable repo to point at.
 */

interface RepoRef {
  /** Lowercased SCM provider key, e.g. "github". */
  provider: string
  owner: string
  name: string
}

/** Canonical cloud host per provider — used to build a repo root when the
 *  backend didn't supply a concrete repoHtmlUrl. Only providers whose repo root
 *  is `https://host/owner/name` belong here (Azure's org/project/_git/repo shape
 *  does not, so it relies on a concrete URL instead). */
const CANONICAL_HOST: Record<string, string> = {
  github: "github.com",
  gitlab: "gitlab.com",
  bitbucket: "bitbucket.org",
  gitea: "gitea.com",
}

/**
 * Provider file-path suffix appended to a repo root, or "" to link to the root
 * (no precise file view available). `baseHost` distinguishes Bitbucket Cloud
 * from Server, whose schemes differ.
 */
function fileSuffix(
  provider: string,
  baseHost: string | null,
  gitRef: string,
  path: string,
  line?: number,
): string {
  switch (provider) {
    case "github":
      return `/blob/${gitRef}/${path}${line ? `#L${line}` : ""}`
    case "gitlab":
      return `/-/blob/${gitRef}/${path}${line ? `#L${line}` : ""}`
    case "gitea": {
      // Gitea keys the file view on ref type: /src/commit/<sha> vs
      // /src/branch/<name>. A blame SHA takes the commit route; anything else
      // (a branch name or the HEAD default) takes the branch route.
      const refType = /^[0-9a-f]{7,40}$/i.test(gitRef) ? "commit" : "branch"
      return `/src/${refType}/${gitRef}/${path}${line ? `#L${line}` : ""}`
    }
    case "bitbucket":
      // Cloud and Server use different schemes; resolveBase has already
      // normalised a Server URL to its web root (…/projects/KEY/repos/name), so
      // Server takes the /browse/ path. Server browse links to the default
      // branch (ref-pinning differs from Cloud), which still lands on the file.
      return baseHost === "bitbucket.org"
        ? `/src/${gitRef}/${path}${line ? `#lines-${line}` : ""}`
        : `/browse/${path}${line ? `#${line}` : ""}`
    default:
      // Azure DevOps (query-param file scheme) and any unmodelled provider:
      // link to the repo root rather than risk a 404.
      return ""
  }
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
 * A safe repo-root base from the backend-supplied URL, or null. Only `http(s)`
 * is accepted — the result becomes an href, so a `javascript:`/`data:` value
 * must never slip through. Strips a trailing slash and `.git`.
 */
function sanitizeRepoUrl(url: string | undefined | null): string | null {
  if (!url) return null
  const trimmed = url.trim()
  if (!/^https?:\/\//i.test(trimmed)) return null
  let host: string
  try {
    host = new URL(trimmed).host
  } catch {
    return null
  }
  if (!host) return null
  return trimmed.replace(/\/+$/, "").replace(/\.git$/i, "")
}

/** Host of a sanitized URL, or null. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).host.toLowerCase()
  } catch {
    return null
  }
}

/**
 * Normalise a concrete repo URL to its browsable web root. Bitbucket Server's
 * clone URL (`…/scm/KEY/name`) is not a web page; its browse root is
 * `…/projects/KEY/repos/name`. Everything else is already a web root.
 */
function toWebRoot(concrete: string, provider: string | undefined): string {
  if (provider === "bitbucket") {
    try {
      const u = new URL(concrete)
      const scm = u.pathname.match(/^\/scm\/([^/]+)\/([^/]+?)\/?$/i)
      if (scm) return `${u.origin}/projects/${scm[1]}/repos/${scm[2]}`
    } catch {
      /* fall through to concrete as-is */
    }
  }
  return concrete
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
  /** Concrete repo web URL from the backend (enables self-hosted hosts). */
  repoHtmlUrl?: string | null
}

/**
 * Web URL for a finding's source location. Prefers a precise file+line link,
 * falls back to the repo root when the file can't be pinpointed, and returns
 * null only when there is no browsable repo (no concrete URL and no ref we can
 * map to a canonical host — e.g. a manual/CI upload).
 */
export function buildRepoFileUrl({ repo, filePath, commit, repoHtmlUrl }: RepoFileUrlArgs): string | null {
  const ref = parseRepoRef(repo)
  const concrete = sanitizeRepoUrl(repoHtmlUrl)

  // Repo-root base. Prefer the concrete backend URL (covers self-hosted and any
  // provider we don't model a canonical host for), else a known canonical host.
  let base: string | null = null
  if (concrete) {
    base = toWebRoot(concrete, ref?.provider)
  } else if (ref && CANONICAL_HOST[ref.provider]) {
    base = `https://${CANONICAL_HOST[ref.provider]}/${ref.owner}/${ref.name}`
  }
  if (!base) return null // nothing browsable to point at

  if (!filePath) return base

  const { path, line } = splitPathAndLine(filePath)
  const rel = repoRelativePath(path)
  if (!rel) return base

  // Precise file link when we model the provider's path shape; else repo root.
  const gitRef = commit?.trim() || "HEAD"
  const suffix = ref ? fileSuffix(ref.provider, hostOf(base), gitRef, encodePath(rel), line) : ""
  return base + suffix
}
