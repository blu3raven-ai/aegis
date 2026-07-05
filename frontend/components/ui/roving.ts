import type { KeyboardEvent } from "react"

type Orientation = "horizontal" | "vertical" | "both"

/**
 * Keyboard handler for roving-tabindex widgets (WAI-ARIA `tablist` / `radiogroup`).
 *
 * Arrow keys step to the adjacent enabled item (wrapping at the ends); Home/End
 * jump to the first/last enabled item; disabled items are skipped. Orientation
 * controls which arrows are live. On a move it prevents default scrolling and
 * calls `onMove(nextIndex)` — the caller is responsible for selecting and
 * focusing that item (automatic activation, per the APG default for both
 * patterns). Non-navigation keys are ignored so typing/click handlers still fire.
 */
export function handleRovingKeyDown(
  e: Pick<KeyboardEvent, "key" | "preventDefault">,
  opts: {
    index: number
    count: number
    orientation?: Orientation
    isDisabled?: (i: number) => boolean
    onMove: (next: number) => void
  },
): void {
  const { index, count, orientation = "horizontal", isDisabled, onMove } = opts
  if (count <= 1) return
  const enabled = (i: number) => !isDisabled?.(i)

  const fwd =
    orientation === "vertical" ? ["ArrowDown"]
    : orientation === "both" ? ["ArrowRight", "ArrowDown"]
    : ["ArrowRight"]
  const back =
    orientation === "vertical" ? ["ArrowUp"]
    : orientation === "both" ? ["ArrowLeft", "ArrowUp"]
    : ["ArrowLeft"]

  // Walk in `dir` from `from`, wrapping, until an enabled item is found.
  const step = (from: number, dir: 1 | -1): number => {
    let next = from
    for (let i = 0; i < count; i++) {
      next = (next + dir + count) % count
      if (enabled(next)) return next
    }
    return from
  }

  let target: number
  if (fwd.includes(e.key)) target = step(index, 1)
  else if (back.includes(e.key)) target = step(index, -1)
  else if (e.key === "Home") target = enabled(0) ? 0 : step(0, 1)
  else if (e.key === "End") target = enabled(count - 1) ? count - 1 : step(count - 1, -1)
  else return

  if (target !== index) {
    e.preventDefault()
    onMove(target)
  }
}
