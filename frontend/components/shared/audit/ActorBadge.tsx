// Compact display of who performed an action — shows email + role pill.
// Service actors (actor_id like "service:<name>") get a distinct visual.

export function ActorBadge({
  actorId,
  actorEmail,
  actorRole,
}: {
  actorId?: string
  actorEmail?: string
  actorRole?: string
}) {
  const isService = actorId?.startsWith("service:") ?? false
  const displayName = isService
    ? (actorId ?? "service")
    : (actorEmail ?? actorId ?? "—")

  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span
        className={`truncate text-sm font-medium ${
          isService
            ? "font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-accent)] text-xs"
            : "text-[var(--color-text-primary)]"
        }`}
        title={displayName}
      >
        {displayName}
      </span>
      {actorRole && !isService && (
        <span className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
          {actorRole}
        </span>
      )}
    </div>
  )
}
