"use client";
import { useEffect, useState } from "react";

import { apiClient } from "./api-client";

export type ConnectorKind = "sender" | "ingester" | "runner" | "wizard";
export type ConnectorStatus = "stable" | "beta" | "preview" | "deprecated";
export type ConnectorCategory = "ci" | "notification" | "runner";

export interface Connector {
  id: string;
  name: string;
  kind: ConnectorKind;
  category: ConnectorCategory;
  description: string;
  version: string;
  status: ConnectorStatus;
  icon_slug: string;
  href: string | null;
}

/** Frontend-facing alias matching the legacy `Integration` shape used across the integrations page. */
export interface Integration {
  slug: string;
  name: string;
  category: ConnectorCategory;
  description: string;
  version: string;
  status: ConnectorStatus;
  iconSlug: string;
  href?: string;
}

interface CatalogResponse {
  connectors: Connector[];
  total: number;
}

/**
 * Fetch the full catalog from the backend. Webhook ingesters are filtered
 * out — they're auto-registered backend receivers, not user-setup
 * integrations. The legacy `slug` and `iconSlug` field names are preserved
 * so existing consumers don't need to rename properties.
 */
export async function fetchConnectors(): Promise<Integration[]> {
  try {
    const data = await apiClient<CatalogResponse>("/api/v1/connectors");
    return data.connectors
      .filter(c => c.kind !== "ingester")
      .map(c => ({
        slug: c.id,
        name: c.name,
        category: c.category,
        description: c.description,
        version: c.version,
        status: c.status,
        iconSlug: c.icon_slug,
        ...(c.href ? { href: c.href } : {}),
      }));
  } catch {
    return [];
  }
}

let _cached: Promise<Integration[]> | null = null;

/** Module-level cache so repeated callers (page, drawer, breadcrumb) share one request. */
function getCachedCatalog(): Promise<Integration[]> {
  if (!_cached) _cached = fetchConnectors();
  return _cached;
}

/** React hook that returns the catalog plus a loading flag. */
export function useConnectorCatalog(): { catalog: Integration[]; loading: boolean } {
  const [catalog, setCatalog] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getCachedCatalog().then(items => {
      if (cancelled) return;
      setCatalog(items);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return { catalog, loading };
}
