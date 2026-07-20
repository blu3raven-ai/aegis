/** Pick the singular or plural noun for a count, so a UI never reads "1 items".
 *  Defaults the plural form to `singular + "s"`; pass an explicit plural for
 *  irregular words (e.g. plural(n, "repository", "repositories")). */
export function plural(count: number, singular: string, pluralForm?: string): string {
  return count === 1 ? singular : (pluralForm ?? `${singular}s`)
}
