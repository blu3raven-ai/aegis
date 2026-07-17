"use client"

import type { ReactNode } from "react"

import type { FindingContainerImage } from "@/lib/shared/findings/row-mapper"

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        {label}
      </dt>
      <dd className="mt-0.5 truncate text-sm text-[var(--color-text-primary)]">{children}</dd>
    </div>
  )
}

/**
 * Image context for a container finding — which image carries the vulnerable
 * package, its base OS, the digest (for pinning a fixed rebuild), and the layer
 * count. Renders nothing for non-container findings (the prop is undefined).
 */
export function ContainerImageSection({
  image,
}: {
  image: FindingContainerImage | undefined
}) {
  if (!image) return null

  const ref = image.tag ? `${image.name}:${image.tag}` : image.name

  return (
    <section>
      <h3 className="mb-2 text-base font-semibold text-[var(--color-text-primary)]">
        Container image
      </h3>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
        <div className="col-span-2 min-w-0">
          <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Image
          </dt>
          <dd className="mt-0.5 truncate font-mono text-xs text-[var(--color-text-primary)]" title={ref}>
            {ref}
          </dd>
        </div>
        {image.baseOs && <Field label="Base OS">{image.baseOs}</Field>}
        {image.layerCount != null && (
          <Field label="Layers">
            <span className="tabular-nums">{image.layerCount}</span>
          </Field>
        )}
        {image.layerDigest && (
          <Field label="Introduced in layer">
            <span className="tabular-nums" title={image.layerDigest}>
              {image.layerIndex != null
                ? `Layer ${image.layerIndex + 1}${
                    image.layerCount != null ? ` of ${image.layerCount}` : ""
                  }`
                : `${image.layerDigest.replace(/^sha256:/, "").slice(0, 12)}`}
            </span>
          </Field>
        )}
        {image.layerConcentration &&
          image.layerConcentration.totalWithLayer > 1 &&
          image.layerConcentration.findingCount > 1 && (
            <div className="col-span-2 min-w-0">
              <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                Layer concentration
              </dt>
              <dd className="mt-1 text-sm text-[var(--color-text-primary)]">
                Layer {image.layerConcentration.layerIndex + 1} introduced{" "}
                <span className="font-semibold tabular-nums">
                  {image.layerConcentration.findingCount} of {image.layerConcentration.totalWithLayer}
                </span>{" "}
                findings on this image
                {image.layerConcentration.layerIndex <= 2 ? " — likely the base image" : ""}.
              </dd>
            </div>
          )}
        {image.digest && (
          <div className="col-span-2 min-w-0">
            <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Digest
            </dt>
            <dd
              className="mt-0.5 truncate font-mono text-xs text-[var(--color-text-secondary)]"
              title={image.digest}
            >
              {image.digest}
            </dd>
          </div>
        )}
        {image.baseImageRecommendation && (
          <div className="col-span-2 min-w-0">
            <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Recommended base upgrade
            </dt>
            <dd className="mt-1 text-sm text-[var(--color-text-primary)]">
              Upgrade to{" "}
              <span className="font-[family-name:var(--font-jetbrains-mono)] text-[13px] font-semibold">
                {image.baseImageRecommendation.recommendedTag}
              </span>{" "}
              —{" "}
              <span className="font-semibold tabular-nums text-[var(--color-severity-low-text)]">
                {image.baseImageRecommendation.recommendedVulnCount}
              </span>{" "}
              vs{" "}
              <span className="tabular-nums">{image.baseImageRecommendation.currentVulnCount}</span>{" "}
              vulnerabilities.
            </dd>
          </div>
        )}
        {image.newerTags && image.newerTags.length > 0 && (
          <div className="col-span-2 min-w-0">
            <dt className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
              Newer tags available
            </dt>
            <dd className="mt-1 flex flex-wrap gap-1.5">
              {image.newerTags.map((tag) => (
                <span
                  key={tag}
                  className="rounded-sm border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-mono text-2xs text-[var(--color-text-primary)]"
                >
                  {tag}
                </span>
              ))}
            </dd>
          </div>
        )}
      </dl>
    </section>
  )
}
