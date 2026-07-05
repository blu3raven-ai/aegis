/**
 * Splits SBOM bulk-lookup matches into the four exposure buckets the result
 * view renders. Pure and dependency-free so it can be unit-tested in isolation.
 */

export type BulkExposure =
  | "flagged_in_use"
  | "latent"
  | "other_versions"
  | "present"
  | "not_found"

export interface BulkOccurrence {
  repo: string
  version: string
  flagged: boolean
  latent: boolean
}

export interface BulkExposureMatch {
  exposure: BulkExposure
  [key: string]: unknown
}

export interface BulkBuckets<T> {
  flaggedInUse: T[]
  latent: T[]
  present: T[]
  otherVersions: T[]
  notFound: T[]
}

/** Group matches by their server-assigned exposure bucket, preserving order. */
export function bucketBulkMatches<T extends BulkExposureMatch>(
  matches: readonly T[],
): BulkBuckets<T> {
  const buckets: BulkBuckets<T> = {
    flaggedInUse: [],
    latent: [],
    present: [],
    otherVersions: [],
    notFound: [],
  }
  for (const m of matches) {
    switch (m.exposure) {
      case "flagged_in_use":
        buckets.flaggedInUse.push(m)
        break
      case "latent":
        buckets.latent.push(m)
        break
      case "present":
        buckets.present.push(m)
        break
      case "other_versions":
        buckets.otherVersions.push(m)
        break
      default:
        buckets.notFound.push(m)
    }
  }
  return buckets
}
