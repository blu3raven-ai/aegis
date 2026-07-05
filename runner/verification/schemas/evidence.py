"""Unified Evidence schema crossing the LLM boundary."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceKind(str, Enum):
    SOURCE = "source"
    SINK = "sink"
    GATE = "gate"
    SECRET = "secret"
    CONTEXT = "context"
    ADVISORY = "advisory"
    IMPORT_SITE = "import_site"
    MANIFEST = "manifest"
    TOOL_CALL_LOG = "tool_call_log"
    RUNTIME_LOG = "runtime_log"


_EXTERNAL_KINDS = frozenset({EvidenceKind.ADVISORY, EvidenceKind.TOOL_CALL_LOG, EvidenceKind.RUNTIME_LOG})


class Evidence(BaseModel):
    """External kinds require ``source``; file-grounded kinds require ``file`` + ``line``."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    kind: EvidenceKind
    snippet: str = Field(min_length=1)

    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    source: str | None = None

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> "Evidence":
        kind = EvidenceKind(self.kind) if isinstance(self.kind, str) else self.kind
        if kind in _EXTERNAL_KINDS:
            if not self.source:
                raise ValueError(f"kind={kind.value} requires 'source'")
        else:
            if not self.file or self.line is None:
                raise ValueError(f"kind={kind.value} requires both 'file' and 'line'")
        return self

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Evidence":
        accepted = {k: raw[k] for k in ("kind", "snippet", "file", "line", "source") if k in raw}
        return cls(**accepted)


def coerce_evidence_list(items: list[dict[str, Any]]) -> list[Evidence]:
    """Convert dicts to Evidence; silently skip malformed entries."""
    out: list[Evidence] = []
    for item in items:
        try:
            out.append(Evidence.from_dict(item))
        except Exception:  # noqa: BLE001
            continue
    return out
