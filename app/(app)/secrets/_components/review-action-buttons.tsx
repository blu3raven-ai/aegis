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
    return `${base} border-red-200 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300 dark:hover:bg-red-900/40`
  }
  if (tone === "emerald") {
    return `${base} border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-300 dark:hover:bg-emerald-900/40`
  }
  if (tone === "blue") {
    return `${base} border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 dark:border-blue-800 dark:bg-blue-900/20 dark:text-blue-300 dark:hover:bg-blue-900/40`
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
