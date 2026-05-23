import { NextResponse } from "next/server"

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id: rawIdParam } = await ctx.params
  const rawId = rawIdParam.replace(/^cwe-/i, "")
  const num = parseInt(rawId, 10)
  if (isNaN(num) || num < 1 || num > 999999) {
    return NextResponse.json({ error: "Invalid CWE ID" }, { status: 400 })
  }

  try {
    const res = await fetch(`https://cwe.mitre.org/data/definitions/${num}.html`, {
      next: { revalidate: 86400 },
    })
    if (!res.ok) {
      return NextResponse.json({ id: rawId, name: null })
    }
    const html = await res.text()
    // MITRE structure: <h2>CWE-{id}: {Name}</h2>
    const match = html.match(/CWE-\d+:\s*([^<\n]+)/)
    const name = match ? match[1].trim() : null
    return NextResponse.json({ id: rawId, name })
  } catch {
    return NextResponse.json({ id: rawId, name: null })
  }
}
