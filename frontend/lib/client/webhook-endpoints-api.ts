"use client";

import { apiClient } from "./api-client";

export type WebhookProvider =
  | "github"
  | "gitlab"
  | "bitbucket"
  | "azure_devops"
  | "jenkins";

export interface WebhookEndpointMasked {
  id: string;
  provider: WebhookProvider;
  last4: string;
  createdAt: string;
  updatedAt: string;
  rotatedAt: string | null;
}

export interface WebhookEndpointWithSecret extends WebhookEndpointMasked {
  secret: string;
}

interface ListResponse {
  endpoints: WebhookEndpointMasked[];
  providers: WebhookProvider[];
}

const CSRF_COOKIE_NAME = "__Host-csrf";

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;
  for (const pair of document.cookie.split(";").map((p) => p.trim())) {
    const [k, ...rest] = pair.split("=");
    if (k === CSRF_COOKIE_NAME) return rest.join("=");
  }
  return null;
}

async function gqlFetch<T>(operationName: string, query: string, variables: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  const csrf = readCsrfCookie();
  if (csrf !== null) headers["X-CSRF-Token"] = csrf;

  const res = await fetch("/api/v1/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ operationName, query, variables }),
    credentials: "include",
  });
  const body = (await res.json()) as { data?: T; errors?: { message: string }[] };
  if (body.errors && body.errors.length > 0) {
    throw new Error(body.errors[0].message);
  }
  if (!body.data) {
    throw new Error(`${operationName} returned no data`);
  }
  return body.data;
}

// ---------------------------------------------------------------------------
// Webhook endpoints list — served via GraphQL
// ---------------------------------------------------------------------------

const WEBHOOK_ENDPOINTS_QUERY = `query WebhookEndpoints {
  settings {
    webhookEndpoints {
      endpoints { id provider maskedSecret createdAt updatedAt rotatedAt }
      providers
    }
  }
}`;

interface GqlWebhookEndpointEntry {
  id: string;
  provider: string;
  maskedSecret: string;
  createdAt: string | null;
  updatedAt: string | null;
  rotatedAt: string | null;
}

interface GqlWebhookEndpointsResponse {
  settings: {
    webhookEndpoints: {
      endpoints: GqlWebhookEndpointEntry[];
      providers: string[];
    };
  };
}

function fromGqlEntry(e: GqlWebhookEndpointEntry): WebhookEndpointMasked {
  return {
    id: e.id,
    provider: e.provider as WebhookProvider,
    last4: e.maskedSecret,
    createdAt: e.createdAt ?? "",
    updatedAt: e.updatedAt ?? "",
    rotatedAt: e.rotatedAt,
  };
}

export async function listWebhookEndpoints(): Promise<ListResponse> {
  const data = await gqlFetch<GqlWebhookEndpointsResponse>(
    "WebhookEndpoints",
    WEBHOOK_ENDPOINTS_QUERY,
    {},
  );
  return {
    endpoints: data.settings.webhookEndpoints.endpoints.map(fromGqlEntry),
    providers: data.settings.webhookEndpoints.providers as WebhookProvider[],
  };
}

// ---------------------------------------------------------------------------
// Mutations — remain on REST
// ---------------------------------------------------------------------------

export async function createWebhookEndpoint(
  provider: WebhookProvider,
): Promise<WebhookEndpointWithSecret> {
  return apiClient<WebhookEndpointWithSecret>("/api/v1/settings/webhooks", {
    method: "POST",
    body: { provider },
  });
}

export async function rotateWebhookEndpoint(
  id: string,
): Promise<WebhookEndpointWithSecret> {
  return apiClient<WebhookEndpointWithSecret>(
    `/api/v1/settings/webhooks/${encodeURIComponent(id)}/rotate`,
    { method: "POST" },
  );
}

export async function deleteWebhookEndpoint(id: string): Promise<void> {
  await apiClient<void>(
    `/api/v1/settings/webhooks/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  );
}
