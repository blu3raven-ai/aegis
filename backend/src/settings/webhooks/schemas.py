"""Pydantic schemas for the webhook endpoints CRUD surface."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Provider = Literal["github", "gitlab", "bitbucket", "azure_devops", "jenkins"]


class WebhookEndpointCreate(BaseModel):
    provider: Provider


class WebhookEndpointMasked(BaseModel):
    """Read-side representation — secret is never returned."""

    id: str
    provider: Provider
    last4: str = Field(min_length=4, max_length=4)
    createdAt: str
    updatedAt: str
    rotatedAt: str | None = None


class WebhookEndpointWithSecret(WebhookEndpointMasked):
    """Returned ONCE on create / rotate so the operator can copy the
    plaintext to the provider's webhook settings. Every subsequent read
    returns :class:`WebhookEndpointMasked` instead."""

    secret: str = Field(min_length=32)


class WebhookEndpointListResponse(BaseModel):
    """Wrapper for the list endpoint — pairs the configured endpoints with
    the catalogue of supported provider ids so the UI can render the
    "Add endpoint" picker without a second round trip."""

    endpoints: list[WebhookEndpointMasked]
    providers: list[Provider]
