"use client";
import { useEffect, useState } from "react";
import { gqlFetch } from "./graphql-fetch.ts"

export type ConnectorStatus = "stable" | "beta" | "preview" | "deprecated";
export type ConnectorCategory =
  | "cicd"
  | "notifications"
  | "ticketing"
  | "automation"
  | "runner";

export interface ConfigField {
  name: string;
  label: string;
  field_type: "text" | "url" | "password" | "select";
  required: boolean;
  placeholder?: string;
  options?: string[];
  secret: boolean;
}

export interface ConnectorType {
  id: string;
  name: string;
  description: string;
  category: ConnectorCategory | string;
  icon_slug: string;
  enterprise_only: boolean;
  config_fields: ConfigField[];
  docs_url: string;
  version: string;
  status: ConnectorStatus;
  href: string | null;
  coming_soon?: boolean;
}

export interface CatalogResponse {
  connectors: ConnectorType[];
  total: number;
}

/** Frontend-facing alias preserving the legacy `Integration` shape used across the integrations page. */
export interface Integration {
  slug: string;
  name: string;
  category: ConnectorCategory | string;
  description: string;
  version: string;
  status: ConnectorStatus;
  iconSlug: string;
  href?: string;
}
interface GqlConfigField {
  name: string;
  label: string;
  fieldType: string;
  required: boolean;
  placeholder: string;
  options: string[];
  secret: boolean;
}

interface GqlConnectorType {
  id: string;
  name: string;
  description: string;
  category: string;
  iconSlug: string;
  version: string;
  status: string;
  enterpriseOnly: boolean;
  configFields: GqlConfigField[];
  docsUrl: string;
  href: string | null;
}

interface GqlCatalogResponse {
  settings: {
    integrationsCatalog: {
      connectors: GqlConnectorType[];
      total: number;
    };
  };
}

const CATALOG_QUERY = `query IntegrationsCatalog {
  settings {
    integrationsCatalog {
      connectors {
        id
        name
        description
        category
        iconSlug
        version
        status
        enterpriseOnly
        configFields { name label fieldType required placeholder options secret }
        docsUrl
        href
      }
      total
    }
  }
}`;

function toFieldType(s: string): ConfigField["field_type"] {
  return (s === "text" || s === "url" || s === "password" || s === "select")
    ? s
    : "text";
}

function fromGqlConnector(c: GqlConnectorType): ConnectorType {
  return {
    id: c.id,
    name: c.name,
    description: c.description,
    category: c.category,
    icon_slug: c.iconSlug,
    version: c.version,
    status: c.status as ConnectorStatus,
    enterprise_only: c.enterpriseOnly,
    config_fields: c.configFields.map((f) => ({
      name: f.name,
      label: f.label,
      field_type: toFieldType(f.fieldType),
      required: f.required,
      placeholder: f.placeholder || undefined,
      options: f.options.length > 0 ? f.options : undefined,
      secret: f.secret,
    })),
    docs_url: c.docsUrl,
    href: c.href,
  };
}

export async function getCatalog(): Promise<CatalogResponse> {
  const data = await gqlFetch<GqlCatalogResponse>("IntegrationsCatalog", CATALOG_QUERY, {});
  return {
    connectors: data.settings.integrationsCatalog.connectors.map(fromGqlConnector),
    total: data.settings.integrationsCatalog.total,
  };
}

function toIntegration(c: ConnectorType): Integration {
  return {
    slug: c.id,
    name: c.name,
    category: c.category,
    description: c.description,
    version: c.version,
    status: c.status,
    iconSlug: c.icon_slug,
    ...(c.href ? { href: c.href } : {}),
  };
}

export async function fetchConnectors(): Promise<Integration[]> {
  try {
    const data = await getCatalog();
    return data.connectors.map(toIntegration);
  } catch {
    return [];
  }
}

let _cached: Promise<Integration[]> | null = null;

function getCachedCatalog(): Promise<Integration[]> {
  if (!_cached) _cached = fetchConnectors();
  return _cached;
}

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
