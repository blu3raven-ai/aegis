"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { Card } from "@/components/ui/Card";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { ScannerCoverage, type ScannerType } from "@/components/ui/ScannerCoverage";
import { StatusPill } from "@/components/ui/StatusPill";
import { TypeChip, type SourceType as SourceCategoryUiType } from "@/components/ui/TypeChip";
import { TableSkeleton } from "@/components/ui/TableSkeleton";
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table";
import { EmptySourcesState } from "@/components/shared/sources/EmptySourcesState";
import { SourcesCommandBar } from "./SourcesCommandBar";

export type Source = {
  id: string;
  name: string;
  type: SourceCategoryUiType;
  scanners: ScannerType[];
  findings: { high: number; medium: number; low: number };
  last_synced_at: string | null;
  last_scan_at: string | null;
  status: "healthy" | "warning" | "failing" | "stale";
};

type Props = {
  sources: Source[] | null;
};

export function SourcesList({ sources }: Props) {
  const router = useRouter();
  const [typeFilter, setTypeFilter] = useState<SourceCategoryUiType | "all">("all");
  const [search, setSearch] = useState("");

  const list = sources ?? [];

  const filtered = useMemo(() => {
    return list.filter(s => {
      if (typeFilter !== "all" && s.type !== typeFilter) return false;
      if (search && !s.name.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [list, typeFilter, search]);

  if (sources === null) return <TableSkeleton rows={6} columns={7} />;

  const isEmpty = list.length === 0;
  const isFilteredEmpty = !isEmpty && filtered.length === 0;

  return (
    <>
      <div className="mb-4">
        <SourcesCommandBar
          search={search}
          onSearchChange={setSearch}
          typeFilter={typeFilter}
          onTypeChange={setTypeFilter}
        />
      </div>

      <Card padding="none" className="overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th className="py-2">Name</Th>
              <Th className="py-2">Type</Th>
              <Th className="py-2">Scanners</Th>
              <Th className="py-2">Findings</Th>
              <Th className="py-2">Last sync</Th>
              <Th className="py-2">Last scan</Th>
              <Th className="py-2">Status</Th>
            </Tr>
          </Thead>
          <Tbody divided={false}>
            {isEmpty ? (
              <Tr>
                <Td colSpan={7} className="p-0">
                  <EmptySourcesState filtered={false} />
                </Td>
              </Tr>
            ) : isFilteredEmpty ? (
              <Tr>
                <Td colSpan={7} className="p-0">
                  <EmptySourcesState filtered={true} />
                </Td>
              </Tr>
            ) : (
              filtered.map(s => (
                <Tr
                  key={s.id}
                  interactive
                  className="cursor-pointer border-t border-[var(--color-border)]"
                  onClick={() => router.push(`/sources/${s.id}`)}
                >
                  <Td>
                    {/* Keep <Link> so right-click / cmd+click / keyboard still works */}
                    <Link
                      href={`/sources/${s.id}`}
                      className="font-medium hover:underline"
                      onClick={e => e.stopPropagation()}
                    >
                      {s.name}
                    </Link>
                  </Td>
                  <Td><TypeChip type={s.type} /></Td>
                  <Td><ScannerCoverage scanners={s.scanners} /></Td>
                  <Td>
                    <div className="flex gap-1.5">
                      {s.findings.high > 0 && <SeverityPill severity="high" count={s.findings.high} size="sm" />}
                      {s.findings.medium > 0 && <SeverityPill severity="medium" count={s.findings.medium} size="sm" />}
                      {s.findings.low > 0 && <SeverityPill severity="low" count={s.findings.low} size="sm" />}
                      {s.findings.high === 0 && s.findings.medium === 0 && s.findings.low === 0 && (
                        <span className="text-2xs text-[var(--color-text-secondary)]">—</span>
                      )}
                    </div>
                  </Td>
                  <Td className="text-xs text-[var(--color-text-secondary)] tabular-nums">
                    {s.last_synced_at ? new Date(s.last_synced_at).toLocaleString() : "—"}
                  </Td>
                  <Td className="text-xs text-[var(--color-text-secondary)] tabular-nums">
                    {s.last_scan_at ? new Date(s.last_scan_at).toLocaleString() : "—"}
                  </Td>
                  <Td><StatusPill status={s.status} /></Td>
                </Tr>
              ))
            )}
          </Tbody>
        </Table>
      </Card>
    </>
  );
}
