import { NextResponse } from "next/server"

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id: rawIdParam } = await ctx.params
  const rawId = rawIdParam.replace(/^cwe-/i, "")
  const num = parseInt(rawId, 10)
  if (isNaN(num) || num < 1 || num > 999999) {
    return NextResponse.json({ error: "Invalid CWE ID" }, { status: 400 })
  }

  try {
    const res = await fetch(`https://cwe-api.mitre.org/api/v1/cwe/weakness/${num}`, {
      next: { revalidate: 86400 },
    })
    if (!res.ok) {
      return NextResponse.json({ id: rawId, name: null, description: null })
    }
    const data = await res.json()
    const weakness = data?.Weaknesses?.Weakness?.[0]
    const name = weakness?.Name ?? null
    const description = weakness?.Description ?? null
    return NextResponse.json({ id: rawId, name, description })
  } catch {
    return NextResponse.json({ id: rawId, name: null, description: null })
  }
}
