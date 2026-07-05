"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { ScannerCoverage, type ScannerType } from "@/components/ui/ScannerCoverage";
import { StatusPill } from "@/components/ui/StatusPill";
import { TypeChip, type SourceType as SourceCategoryUiType } from "@/components/ui/TypeChip";
import { TableSkeleton } from "@/components/ui/TableSkeleton";
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table";
import { Dialog } from "@/components/layout/Dialog";
import { EmptySourcesState } from "@/components/shared/sources/EmptySourcesState";
import { useHasPermission } from "@/lib/client/use-permission";
import { deleteSourceConnection } from "@/lib/client/source-connections-api";
import { SourcesCommandBar } from "./SourcesCommandBar";

export type Source = {
  id: string;
  name: string;
  type: SourceCategoryUiType;
  scanners: ScannerType[];
  findings: { critical: number; high: number; medium: number; low: number };
  last_synced_at: string | null;
  last_scan_at: string | null;
  status: "healthy" | "warning" | "failing" | "stale";
};

type Props = {
  sources: Source[] | null;
  /** Called after a source is deleted so the parent can reload the list. */
  onDeleted?: () => void;
};

export function SourcesList({ sources, onDeleted }: Props) {
  const router = useRouter();
  const [typeFilter, setTypeFilter] = useState<SourceCategoryUiType | "all">("all");
  const [search, setSearch] = useState("");
  const { allowed: canManage } = useHasPermission("manage_sources");
  const [pendingDelete, setPendingDelete] = useState<Source | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const list = sources ?? [];

  const filtered = useMemo(() => {
    return list.filter(s => {
      if (typeFilter !== "all" && s.type !== typeFilter) return false;
      if (search && !s.name.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [list, typeFilter, search]);

  // Only managers get a delete control, so the trailing action column is
  // conditional — keep colSpan / skeleton columns in sync with it.
  const columnCount = canManage ? 8 : 7;

  async function handleDeleteConfirmed() {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    const result = await deleteSourceConnection(pendingDelete.id);
    setDeleting(false);
    if (result.ok) {
      setPendingDelete(null);
      onDeleted?.();
    } else {
      setDeleteError(result.error);
    }
  }

  if (sources === null) return <TableSkeleton rows={6} columns={columnCount} />;

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
              {canManage && (
                <Th className="py-2 w-px">
                  <span className="sr-only">Actions</span>
                </Th>
              )}
            </Tr>
          </Thead>
          <Tbody divided={false}>
            {isEmpty ? (
              <Tr>
                <Td colSpan={columnCount} className="p-0">
                  <EmptySourcesState filtered={false} />
                </Td>
              </Tr>
            ) : isFilteredEmpty ? (
              <Tr>
                <Td colSpan={columnCount} className="p-0">
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
                      {s.findings.critical > 0 && <SeverityPill severity="critical" count={s.findings.critical} size="sm" />}
                      {s.findings.high > 0 && <SeverityPill severity="high" count={s.findings.high} size="sm" />}
                      {s.findings.medium > 0 && <SeverityPill severity="medium" count={s.findings.medium} size="sm" />}
                      {s.findings.low > 0 && <SeverityPill severity="low" count={s.findings.low} size="sm" />}
                      {s.findings.critical === 0 && s.findings.high === 0 && s.findings.medium === 0 && s.findings.low === 0 && (
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
                  {canManage && (
                    <Td className="text-right" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="xs"
                        iconOnly
                        aria-label={`Delete ${s.name}`}
                        title={`Delete ${s.name}`}
                        onClick={(e) => { e.stopPropagation(); setDeleteError(null); setPendingDelete(s); }}
                        className="text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical-text)]"
                        leadingIcon={
                          // iconOnly Buttons drop their children — the glyph must
                          // come through leadingIcon or the button renders empty.
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-3.5 w-3.5" aria-hidden="true">
                            <polyline points="3 6 5 6 21 6" />
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                            <line x1="10" y1="11" x2="10" y2="17" />
                            <line x1="14" y1="11" x2="14" y2="17" />
                          </svg>
                        }
                      />
                    </Td>
                  )}
                </Tr>
              ))
            )}
          </Tbody>
        </Table>
      </Card>

      <Dialog
        open={pendingDelete !== null}
        onClose={() => { if (!deleting) { setPendingDelete(null); setDeleteError(null); } }}
        onConfirm={() => { void handleDeleteConfirmed(); }}
        title={pendingDelete ? `Delete ${pendingDelete.name}?` : "Delete source?"}
        description={
          deleteError ??
          "This removes the connection and stops syncing it. Scan history and findings will remain."
        }
        confirmLabel={deleting ? "Deleting…" : "Delete Source"}
        variant="danger"
      />
    </>
  );
}
