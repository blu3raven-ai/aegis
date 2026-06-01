import type { SecretReviewStatus } from "@/lib/shared/secrets/types"

interface Props {
  currentStatus?: SecretReviewStatus
  size?: "sm" | "md"
  showReset?: boolean
  onConfirm?: () => void
  onFalsePositive?: () => void
  onActionTaken?: () => void
  onReset?: () => void
}

const SIZE_CLASSES = {
  sm: "px-3 py-2 text-xs",
  md: "px-4 py-2 text-sm",
}

function buttonClass(tone: "red" | "emerald" | "blue" | "slate", size: "sm" | "md") {
  const base = `rounded-lg border font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${SIZE_CLASSES[size]}`
  if (tone === "red") {
    return `${base} border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)] hover:opacity-90`
  }
  if (tone === "emerald") {
    return `${base} border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)] hover:opacity-90`
  }
  if (tone === "blue") {
    return `${base} border-[var(--color-accent-border)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)] hover:opacity-90`
  }
  return `${base} border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-primary)] hover:bg-[var(--color-border)]`
}

export function ReviewActionButtons({
  currentStatus,
  size = "md",
  showReset = false,
  onConfirm,
  onFalsePositive,
  onActionTaken,
  onReset,
}: Props) {
  return (
    <>
      {onConfirm ? (
        <button
          type="button"
          onClick={onConfirm}
          disabled={currentStatus === "confirmed"}
          className={buttonClass("red", size)}
        >
          {size === "sm" ? "Confirm" : "Confirmed"}
        </button>
      ) : null}
      {onFalsePositive ? (
        <button
          type="button"
          onClick={onFalsePositive}
          disabled={currentStatus === "false_positive"}
          className={buttonClass("emerald", size)}
        >
          False Positive
        </button>
      ) : null}
      {onActionTaken ? (
        <button
          type="button"
          onClick={onActionTaken}
          disabled={currentStatus === "action_taken"}
          className={buttonClass("blue", size)}
        >
          Action Taken
        </button>
      ) : null}
      {showReset && onReset ? (
        <button
          type="button"
          onClick={onReset}
          disabled={currentStatus === "new"}
          className={buttonClass("slate", size)}
        >
          Reset to New
        </button>
      ) : null}
    </>
  )
}
