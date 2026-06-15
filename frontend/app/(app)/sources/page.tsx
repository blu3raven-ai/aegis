"use client";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/layout/PageHeader";
import { SourcesIcon } from "@/lib/shared/ui/page-icons";
import { listSourceConnections } from "@/lib/client/sources-api";
import type { SourceCategory, ConnectionStatus } from "@/lib/shared/sources-types";
import { AddConnectionModal } from "@/components/sources/AddConnectionModal";
import { SourcesList, type Source } from "./_components/SourcesList";
import { Button } from "@/components/ui/Button";

// ─── Adapter maps ──────────────────────────────────────────────────────────────

const CATEGORY_TO_UI: Record<SourceCategory, "code" | "containers" | "cloud"> = {
  "code-repositories": "code",
  "container-registry": "containers",
  "cloud-infrastructure": "cloud",
};

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
            name: conn.name,
            type: CATEGORY_TO_UI[conn.category],
            scanners: [],                              // populated by SCM plan companion
            findings: { high: 0, medium: 0, low: 0 }, // populated by SCM plan companion
            last_scan_at: conn.lastSyncedAt ?? null,
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
            Add source
          </Button>
        }
      />
      <div className="px-6 py-6">
        <SourcesList sources={sources} />
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
