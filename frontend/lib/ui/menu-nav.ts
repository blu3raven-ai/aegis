/**
 * Roving-tabindex navigation for a vertical menu / listbox.
 *
 * Given the key pressed, the currently-active index, and the item count,
 * return the next active index — or `null` when the key isn't a navigation
 * key (the caller should let it through). ArrowUp/Down wrap around the ends;
 * Home/End jump to the first/last item. `current` is expected to be a valid
 * in-range index (the open handler seeds it), so wrapping is unambiguous.
 */
export function nextRovingIndex(
  key: string,
  current: number,
  count: number,
): number | null {
  if (count <= 0) return null
  switch (key) {
    case "ArrowDown":
      return (current + 1) % count
    case "ArrowUp":
      return (current - 1 + count) % count
    case "Home":
      return 0
    case "End":
      return count - 1
    default:
      return null
  }
}
