"use client"

import { useEffect, useRef } from "react"
import { Table, Tbody, Tr, Td } from "@/components/ui/Table"

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
      <div className="overflow-x-auto overflow-y-auto bg-[var(--color-surface-raised)]" style={{ maxHeight }}>
        <Table className="border-collapse">
          <Tbody divided={false}>
            {rows.map((row, i) => (
              <Tr
                key={i}
                ref={i === highlightIdx ? hlRef : undefined}
                className={i === highlightIdx ? `${hlRowCls} text-orange-700 dark:text-orange-100` : ""}
              >
                <Td className="select-none w-9 text-right pr-3 pl-2 font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-secondary)]/35 leading-relaxed align-top py-[1px] px-0 whitespace-nowrap">
                  {startLine + i}
                </Td>
                <Td className="pr-3 align-top py-[1px] px-0">
                  <pre className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-slate-700 dark:text-slate-300 whitespace-pre leading-relaxed">
                    {row || " "}
                  </pre>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}
