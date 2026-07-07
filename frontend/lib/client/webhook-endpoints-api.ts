"use client";

import { apiClient } from "./api-client";
import { gqlFetch } from "./graphql-fetch.ts"

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
