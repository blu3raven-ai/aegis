import type { ImageRow as ImageRowData } from "@/lib/client/sources-api"
import { BaseOsChip } from "./BaseOsChip"
import { SeverityCounts } from "@/components/shared/SeverityCounts"
import {
  formatBytes,
  relativeScanTime,
  repoPathOf,
  scanFreshness,
  shortDigest,
} from "./format"

const FRESHNESS_TEXT = {
  fresh: "text-[var(--color-text-primary)]",
  stale: "text-[var(--color-severity-medium-text)]",
  never: "text-[var(--color-severity-critical-text)]",
} as const

const FRESHNESS_DOT = {
  fresh: "bg-[var(--color-state-fixed)]",
  stale: "bg-[var(--color-severity-medium)]",
  never: "bg-[var(--color-severity-critical)]",
} as const

export function ImageRow({ image }: { image: ImageRowData }) {
  const freshness = scanFreshness(image.last_scanned_at)
  const sizeLabel = formatBytes(image.size_bytes)
  const layerLabel =
    image.layer_count != null
      ? `${image.layer_count} layer${image.layer_count === 1 ? "" : "s"}`
      : null
  const metaParts = [sizeLabel, layerLabel].filter(Boolean) as string[]

  const repoPath = repoPathOf(image.image_name) || image.image_digest

  return (
    <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1fr)] items-center gap-4 border-b border-[var(--color-border)] px-5 py-3.5 last:border-b-0 hover:bg-[var(--color-surface-raised)] transition-colors">
      <div className="min-w-0">
        <div className="flex items-center gap-2 font-mono text-sm font-semibold text-[var(--color-text-primary)]">
          <span className="truncate">{repoPath}</span>
          {image.image_tag && (
            <span className="rounded bg-[var(--color-accent-subtle)] px-1.5 py-0.5 text-xs font-medium text-[var(--color-accent)]">
              {image.image_tag}
            </span>
          )}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-[var(--color-text-secondary)]">
          <span className="font-mono text-2xs text-[var(--color-text-tertiary)]">
            {shortDigest(image.image_digest)}
          </span>
          <BaseOsChip baseOs={image.base_os} />
          {metaParts.length > 0 && (
            <span className="tabular-nums">{metaParts.join(" · ")}</span>
          )}
        </div>
      </div>

      <SeverityCounts counts={image.finding_counts} />

      <div className="flex flex-col gap-0.5">
        <span className={`flex items-center gap-2 text-sm ${FRESHNESS_TEXT[freshness]}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${FRESHNESS_DOT[freshness]}`} aria-hidden="true" />
          {relativeScanTime(image.last_scanned_at)}
        </span>
        {freshness === "stale" && (
          <span className="text-xs text-[var(--color-text-tertiary)]">stale &gt;14d</span>
        )}
      </div>

      <div className="min-w-0 text-xs text-[var(--color-text-secondary)]">
        {image.repos.length === 0 ? (
          <span className="text-[var(--color-text-tertiary)]">no source repo</span>
        ) : (
          <span className="block truncate font-mono">{image.repos[0]}</span>
        )}
        {image.repos.length > 1 && (
          <span className="text-2xs text-[var(--color-text-tertiary)]">
            +{image.repos.length - 1} more
          </span>
        )}
      </div>
    </div>
  )
}
