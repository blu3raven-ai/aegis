export function buildOrgQuery(orgValues: string[] | string) {
  const values = Array.isArray(orgValues)
    ? orgValues
    : orgValues
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)

  const params = new URLSearchParams()
  for (const value of values) {
    params.append("org", value)
  }
  return params.toString()
}
