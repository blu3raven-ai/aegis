"use client"

import { useEffect, useRef } from "react"

export function DrawerCodeLines({
  code,
  startLine,
  highlightIdx,
  borderCls = "border-[var(--color-border)]/60",
  hlRowCls = "bg-orange-500/15",
  maxHeight = 192,
}: {
  code: string
  startLine: number
  highlightIdx: number
  borderCls?: string
  hlRowCls?: string
  maxHeight?: number
}) {
  const rows = code.trimEnd().split("\n")
  const hlRef = useRef<HTMLTableRowElement>(null)

  useEffect(() => {
    hlRef.current?.scrollIntoView({ block: "center" })
  }, [code, highlightIdx])

  return (
    <div className={`border-t ${borderCls} overflow-hidden`}>
      <div className="overflow-x-auto overflow-y-auto" style={{ maxHeight }}>
        <table className="w-full border-collapse">
          <tbody>
            {rows.map((row, i) => (
              <tr
                key={i}
                ref={i === highlightIdx ? hlRef : undefined}
                className={i === highlightIdx ? `${hlRowCls} text-orange-700 dark:text-orange-100` : ""}
              >
                <td className="select-none w-9 text-right pr-3 pl-2 font-[family-name:var(--font-jetbrains-mono)] text-[10px] text-[var(--color-text-secondary)]/35 leading-relaxed align-top py-[1px] whitespace-nowrap">
                  {startLine + i}
                </td>
                <td className="pr-3 align-top py-[1px]">
                  <pre className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-slate-700 dark:text-slate-300 whitespace-pre leading-relaxed">
                    {row || " "}
                  </pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
