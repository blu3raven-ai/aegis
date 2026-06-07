"use client"

import { useEffect, useMemo, useState } from "react"
import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { KpiCard } from "@/components/shared/KpiCard"
import { ImageRow } from "@/components/shared/images/ImageRow"
import { EmptyImagesState } from "@/components/shared/images/EmptyImagesState"
import { registryOf, repoPathOf, scanFreshness } from "@/components/shared/images/format"
import { listImages, type ImageRow as ImageRowData } from "@/lib/client/images-api"

import { ImagesDisplayOverflow, type ImagesSortMode } from "./ImagesDisplayOverflow"

type FilterMode = "all" | "critical" | "stale"
type SortMode = ImagesSortMode

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const WARN = "text-[var(--color-severity-medium)]"
const OK = "text-[var(--color-state-fixed)]"

export interface ImagesInventoryPanelProps {
  /** Optional callback fired with the total image count after each successful load. */
  onCountChange?: (count: number) => void
}

export function ImagesInventoryPanel({ onCountChange }: ImagesInventoryPanelProps = {}) {
  const [images, setImages] = useState<ImageRowData[]>([])
  const [totalCount, setTotalCount] = useState<number | null>(null)
  const [filter, setFilter] = useState<FilterMode>("all")
  const [sort, setSort] = useState<SortMode>("critical")
  const [search, setSearch] = useState<string>("")
  const [registryFilter, setRegistryFilter] = useState<string>("all")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    listImages({ limit: 200 })
      .then((res) => {
        if (cancelled) return
        setImages(res.images)
        setTotalCount(res.total_count)
        onCountChange?.(res.total_count)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : "Failed to load images.")
      })
      .finally(() => {
        if (cancelled) return
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [onCountChange])

  const stats = useMemo(() => {
    const total = totalCount ?? images.length
    const withCritical = images.filter((i) => i.finding_counts.critical > 0).length
    const stale = images.filter((i) => scanFreshness(i.last_scanned_at) !== "fresh").length
    const registries = new Set(images.map((i) => registryOf(i.image_name)))
    return { total, withCritical, stale, registries: registries.size }
  }, [images, totalCount])

  const registryOptions = useMemo(() => {
    const set = new Set<string>()
    for (const img of images) set.add(registryOf(img.image_name))
    return Array.from(set).sort()
  }, [images])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return images.filter((img) => {
      if (filter === "critical" && img.finding_counts.critical === 0) return false
      if (filter === "stale" && scanFreshness(img.last_scanned_at) === "fresh") return false
      if (registryFilter !== "all" && registryOf(img.image_name) !== registryFilter) return false
      if (q) {
        const haystack = [img.image_name, img.image_tag, img.image_digest, ...img.repos]
          .filter((v): v is string => Boolean(v))
          .join(" ")
          .toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [images, filter, search, registryFilter])

  const grouped = useMemo(() => {
    const map = new Map<string, ImageRowData[]>()
    for (const img of filtered) {
      const reg = registryOf(img.image_name)
      const bucket = map.get(reg) ?? []
      bucket.push(img)
      map.set(reg, bucket)
    }
    return Array.from(map.entries())
      .map(([registry, items]) => ({
        registry,
        items: items.sort((a, b) => {
          if (sort === "critical") {
            const diff = b.finding_counts.critical - a.finding_counts.critical
            if (diff !== 0) return diff
            const aName = repoPathOf(a.image_name) || a.image_digest
            const bName = repoPathOf(b.image_name) || b.image_digest
            return aName.localeCompare(bName)
          }
          if (sort === "last-scan") {
            const aTs = a.last_scanned_at ? Date.parse(a.last_scanned_at) : 0
            const bTs = b.last_scanned_at ? Date.parse(b.last_scanned_at) : 0
            return bTs - aTs
          }
          const aName = repoPathOf(a.image_name) || a.image_digest
          const bName = repoPathOf(b.image_name) || b.image_digest
          return aName.localeCompare(bName)
        }),
      }))
      .sort((a, b) => a.registry.localeCompare(b.registry))
  }, [filtered, sort])

  const isFiltered = filter !== "all" || search !== "" || registryFilter !== "all"
  const isEmptyData = !loading && !error && images.length === 0

  const attributes = useMemo<AttributeDef[]>(() => {
    const list: AttributeDef[] = [
      {
        key: "filter",
        label: "show",
        group: "Filter",
        description: "Critical findings · Stale scans",
        type: "enum",
        options: [
          { value: "critical", label: "With critical" },
          { value: "stale", label: "Stale scans" },
        ],
      },
    ]
    if (registryOptions.length > 1) {
      list.push({
        key: "registry",
        label: "registry",
        group: "Origin",
        description: "Image registry",
        type: "enum",
        options: registryOptions.map((reg) => ({ value: reg, label: reg })),
      })
    }
    return list
  }, [registryOptions])

  const values: Record<string, string | null> = {
    filter: filter === "all" ? null : filter,
    registry: registryFilter === "all" ? null : registryFilter,
  }

  const handleChange = (key: string, value: string | null) => {
    if (key === "filter") setFilter((value ?? "all") as FilterMode)
    else if (key === "registry") setRegistryFilter(value ?? "all")
  }

  return (
    <>
      {error && (
        <div className="flex items-center justify-between gap-3 border-b border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-5 py-3">
          <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
          <button
            type="button"
            onClick={() => {
              setError(null)
              setLoading(true)
              listImages({ limit: 200 })
                .then((res) => {
                  setImages(res.images)
                  setTotalCount(res.total_count)
                })
                .catch((err: unknown) => {
                  setError(err instanceof Error ? err.message : "Failed to load images.")
                })
                .finally(() => setLoading(false))
            }}
            className="shrink-0 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-3 lg:grid-cols-4">
        <KpiCard
          label="Total images"
          value={loading && images.length === 0 ? "—" : stats.total.toLocaleString()}
          note={loading && images.length === 0 ? "Loading…" : "Across all connected registries"}
          valueClass={NEUTRAL}
        />
        <KpiCard
          label="With critical"
          value={loading && images.length === 0 ? "—" : stats.withCritical.toLocaleString()}
          note={
            loading && images.length === 0
              ? "Loading…"
              : stats.withCritical === 0
                ? "No critical vulns"
                : `of ${stats.total.toLocaleString()} images`
          }
          valueClass={stats.withCritical > 0 ? CRITICAL : OK}
        />
        <KpiCard
          label="Stale scans"
          value={loading && images.length === 0 ? "—" : stats.stale.toLocaleString()}
          note={loading && images.length === 0 ? "Loading…" : ">14d since last scan"}
          valueClass={stats.stale > 0 ? WARN : OK}
        />
        <KpiCard
          label="Registries"
          value={loading && images.length === 0 ? "—" : stats.registries.toLocaleString()}
          note={loading && images.length === 0 ? "Loading…" : "Distinct registries detected"}
          valueClass={NEUTRAL}
        />
      </div>

      <div className="border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
        <CommandBar
          attributes={attributes}
          values={values}
          onChange={handleChange}
          searchInput={search}
          onSearchInputChange={setSearch}
          searchPlaceholder="Search images…"
          displayOverflow={<ImagesDisplayOverflow sort={sort} onSortChange={setSort} />}
        />
      </div>

      <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-6 py-8">
      {loading && images.length === 0 ? (
        <div className="overflow-hidden rounded-2xl border border-[var(--color-border)]">
          <ImagesHeaderRow />
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="flex items-center gap-4 border-b border-[var(--color-border)] px-5 py-4 last:border-b-0"
              aria-hidden="true"
            >
              <div className="h-3 w-48 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="h-3 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="ml-auto h-3 w-20 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
            </div>
          ))}
        </div>
      ) : isEmptyData ? (
        <div className="overflow-hidden rounded-2xl border border-[var(--color-border)]">
          <ImagesHeaderRow />
          <EmptyImagesState filtered={false} />
        </div>
      ) : grouped.length === 0 ? (
        <div className="overflow-hidden rounded-2xl border border-[var(--color-border)]">
          <ImagesHeaderRow />
          <EmptyImagesState filtered={isFiltered} />
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {grouped.map(({ registry, items }) => (
            <section key={registry} className="flex flex-col gap-2">
              <header className="flex items-baseline justify-between gap-3 px-1">
                <h2 className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                  {registry}
                </h2>
                <span className="text-2xs text-[var(--color-text-tertiary)] tabular-nums">
                  {items.length} {items.length === 1 ? "image" : "images"}
                </span>
              </header>
              <div className="overflow-hidden rounded-2xl border border-[var(--color-border)]">
                <ImagesHeaderRow />
                {items.map((img) => (
                  <ImageRow key={img.image_digest} image={img} />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
      </main>
    </>
  )
}

function ImagesHeaderRow() {
  return (
    <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1fr)] gap-4 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-2.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
      <div>Image</div>
      <div>Severity</div>
      <div>Last scan</div>
      <div>Source repo</div>
    </div>
  )
}
