import { NextResponse } from "next/server"

// MITRE CWE REST API returns { Weaknesses: [ { ID, Name, Description, ... } ] }
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id: rawIdParam } = await ctx.params
  const rawId = rawIdParam.replace(/^cwe-/i, "")
  const num = parseInt(rawId, 10)
  if (isNaN(num) || num < 1 || num > 999999) {
    return NextResponse.json({ error: "Invalid CWE ID" }, { status: 400 })
  }

  const empty = { id: rawId, name: null, description: null, likelihood: null, consequences: [], mitigations: [] }

  try {
    const res = await fetch(`https://cwe-api.mitre.org/api/v1/cwe/weakness/${num}`, {
      next: { revalidate: 86400 },
    })
    if (!res.ok) return NextResponse.json(empty)

    const data = await res.json()
    // Weaknesses is an array at the top level, not a nested object
    const weakness = Array.isArray(data?.Weaknesses) ? data.Weaknesses[0] : null
    if (!weakness) return NextResponse.json(empty)

    const name: string | null = weakness.Name ?? null
    const description: string | null = weakness.Description ?? null
    const likelihood: string | null = weakness.LikelihoodOfExploit ?? null

    const consequences: Array<{ scope: string[]; impact: string[] }> =
      (weakness.CommonConsequences ?? []).map((c: Record<string, unknown>) => ({
        scope: Array.isArray(c.Scope) ? (c.Scope as string[]) : [],
        impact: Array.isArray(c.Impact) ? (c.Impact as string[]) : [],
      })).filter((c: { scope: string[]; impact: string[] }) => c.scope.length || c.impact.length)

    const mitigations: Array<{ phase: string[]; description: string }> =
      (weakness.PotentialMitigations ?? []).map((m: Record<string, unknown>) => ({
        phase: Array.isArray(m.Phase) ? (m.Phase as string[]) : [],
        description: typeof m.Description === "string" ? m.Description : "",
      })).filter((m: { phase: string[]; description: string }) => m.description)

    return NextResponse.json({ id: rawId, name, description, likelihood, consequences, mitigations })
  } catch {
    return NextResponse.json(empty)
  }
}
