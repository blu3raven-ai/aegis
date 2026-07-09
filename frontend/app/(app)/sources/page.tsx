"use client";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/layout/PageHeader";
import { SourcesIcon } from "@/lib/shared/ui/page-icons";
import { listSourceConnections } from "@/lib/client/source-connections-api";
import { CATEGORY_SCANNERS, sourceDisplayName } from "@/lib/shared/sources-types";
import type { SourceCategory, ConnectionStatus, ScannerType } from "@/lib/shared/sources-types";
import { AddConnectionModal } from "@/components/sources/AddConnectionModal";
import { SourcesList, type Source } from "./_components/SourcesList";
import { Button } from "@/components/ui/Button";
import type { ScannerType as CoverageScanner } from "@/components/ui/ScannerCoverage";


const CATEGORY_TO_UI: Record<SourceCategory, "code" | "containers" | "cloud" | "ci"> = {
  "code-repositories": "code",
  "container-registry": "containers",
  "cloud-infrastructure": "cloud",
  "ci-systems": "ci",
};

// Map a source scan job-type to the generic coverage chip shown in the list.
// Container image scanning is a form of composition analysis, so it maps to SCA.
const SCANNER_TO_COVERAGE: Record<ScannerType, CoverageScanner> = {
  dependencies_scanning: "sca",
  code_scanning: "sast",
  secret_scanning: "secrets",
  container_scanning: "sca",
  iac_scanning: "iac",
  agent_scanning: "agent",
  deep_audit: "audit",
};

// An empty `scanners` array means "all applicable to the category", so expand
// it before mapping to the coverage chips.
function coverageFor(category: SourceCategory, scanners: ScannerType[]): CoverageScanner[] {
  const effective = scanners.length ? scanners : CATEGORY_SCANNERS[category];
  return Array.from(new Set(effective.map((s) => SCANNER_TO_COVERAGE[s])));
}

const STATUS_MAP: Record<ConnectionStatus, "healthy" | "warning" | "failing" | "stale"> = {
  "connected": "healthy",
  "syncing": "warning",
  "error": "failing",
  "disconnected": "failing",
  "not-synced": "stale",
};

export default function SourcesPage() {
  const [sources, setSources] = useState<Source[] | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    listSourceConnections().then(result => {
      if (result.ok) {
        setSources(
          result.data.connections.map(conn => ({
            id: conn.id,
            name: sourceDisplayName(conn),
            type: CATEGORY_TO_UI[conn.category],
            scanners: coverageFor(conn.category, conn.scanners ?? []),
            findings: {
              critical: conn.findingCounts?.critical ?? 0,
              high: conn.findingCounts?.high ?? 0,
              medium: conn.findingCounts?.medium ?? 0,
              low: conn.findingCounts?.low ?? 0,
            },
            last_synced_at: conn.lastSyncedAt ?? null,
            last_scan_at: conn.lastScanAt ?? null,
            status: STATUS_MAP[conn.status],
          })),
        );
      } else {
        setSources([]);
      }
    });
  }, [reloadKey]);

  return (
    <>
      <PageHeader
        icon={<SourcesIcon />}
        title="Sources"
        description="Connected repositories, registries, and cloud accounts"
        count={sources?.length ?? null}
        controls={
          <Button
            variant="primary"
            onClick={() => setShowAdd(true)}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            }
          >
            Add Source
          </Button>
        }
      />
      <div className="px-6 py-6">
        <SourcesList sources={sources} onDeleted={() => setReloadKey(k => k + 1)} />
      </div>
      {showAdd && (
        <AddConnectionModal
          onClose={() => setShowAdd(false)}
          onCreated={() => { setShowAdd(false); setReloadKey(k => k + 1); }}
        />
      )}
    </>
  );
}
