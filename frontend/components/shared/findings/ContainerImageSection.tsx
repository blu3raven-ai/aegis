"use client"

import type { ReactNode } from "react"

import type { FindingContainerImage } from "@/lib/shared/findings/row-mapper"

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
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
    <section className="mt-6">
      <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        Container image
      </h3>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
        <div className="col-span-2 min-w-0">
          <dt className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
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
        {image.digest && (
          <div className="col-span-2 min-w-0">
            <dt className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
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
      </dl>
    </section>
  )
}
