
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
