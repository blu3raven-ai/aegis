
/**
 * Extracts the first sentence from a SAST finding message.
 * Splits on the first `.`, `!`, or `?` followed by a space or end of string.
 * Truncates to 80 characters if no sentence boundary is found or the
 * first sentence itself exceeds 80 characters.
 */
export function firstSentence(message: string): string {
  const match = message.match(/^(.+?[.!?])(?:\s|$)/)
  const sentence = match ? match[1] : message
  if (sentence.length > 80) return sentence.slice(0, 80) + "…"
  return sentence
}

/**
 * Given a multi-line code window and a snippet, returns the index of the line
 * in the window that should be highlighted.
 *
 * When the same snippet appears more than once (e.g. the same pattern used in
 * multiple case branches), this picks the occurrence closest to the window
 * center rather than always returning the first — because the scanner centers
 * the code_window around start_line.
 *
 * Returns -1 when the snippet is empty or not found.
 */
export function pickHighlightIdx(windowLines: string[], snippet: string): number {
  if (!snippet) return -1
  const trimmed = snippet.trim()
  const matches: number[] = []
  for (let i = 0; i < windowLines.length; i++) {
    if (windowLines[i].trim() === trimmed) matches.push(i)
  }
  if (matches.length === 0) return -1
  const center = (windowLines.length - 1) / 2
  return matches.reduce((best, curr) =>
    Math.abs(curr - center) < Math.abs(best - center) ? curr : best
  )
}
