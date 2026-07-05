"""Per-org BYO LLM credential storage and retrieval."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import LlmConfig
from src.security.crypto import decrypt, encrypt


@dataclass
class LlmConfigDTO:
    org_id: str
    api_key: str
    api_base_url: str
    model: str
    scan_token_budget: int
    daily_token_budget: int
    enabled: bool


@dataclass
class LlmConfigUpsert:
    org_id: str
    api_key: str
    api_base_url: str
    model: str
    scan_token_budget: int = 100_000
    daily_token_budget: int = 1_000_000
    enabled: bool = False


def upsert_llm_config(upsert: LlmConfigUpsert) -> None:
    async def _q(session: AsyncSession) -> None:
        row = (
            await session.execute(
                select(LlmConfig).where(LlmConfig.org_id == upsert.org_id)
            )
        ).scalar_one_or_none()
        api_key_enc = encrypt(upsert.api_key)
        if row is None:
            session.add(
                LlmConfig(
                    org_id=upsert.org_id,
                    api_key_enc=api_key_enc,
                    api_base_url=upsert.api_base_url,
                    model=upsert.model,
                    scan_token_budget=upsert.scan_token_budget,
                    daily_token_budget=upsert.daily_token_budget,
                    enabled=upsert.enabled,
                )
            )
        else:
            row.api_key_enc = api_key_enc
            row.api_base_url = upsert.api_base_url
            row.model = upsert.model
            row.scan_token_budget = upsert.scan_token_budget
            row.daily_token_budget = upsert.daily_token_budget
            row.enabled = upsert.enabled

    run_db(_q)


def fetch_llm_config(org_id: str) -> LlmConfigDTO | None:
    async def _q(session: AsyncSession) -> LlmConfigDTO | None:
        row = (
            await session.execute(
                select(LlmConfig).where(LlmConfig.org_id == org_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        api_key = decrypt(row.api_key_enc) or ""
        return LlmConfigDTO(
            org_id=row.org_id,
            api_key=api_key,
            api_base_url=row.api_base_url,
            model=row.model,
            scan_token_budget=row.scan_token_budget,
            daily_token_budget=row.daily_token_budget,
            enabled=row.enabled,
        )

    return run_db(_q)


def fetch_public_llm_config(org_id: str) -> dict | None:
    async def _q(session: AsyncSession) -> dict | None:
        row = (
            await session.execute(
                select(LlmConfig).where(LlmConfig.org_id == org_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "org_id": row.org_id,
            "api_base_url": row.api_base_url,
            "model": row.model,
            "scan_token_budget": row.scan_token_budget,
            "daily_token_budget": row.daily_token_budget,
            "enabled": row.enabled,
            "configured": True,
        }

    return run_db(_q)


def delete_llm_config(org_id: str) -> bool:
    """Remove the org's stored LLM config. Returns True if a row was deleted."""
    async def _q(session: AsyncSession) -> bool:
        row = (
            await session.execute(
                select(LlmConfig).where(LlmConfig.org_id == org_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        return True

    return run_db(_q)
