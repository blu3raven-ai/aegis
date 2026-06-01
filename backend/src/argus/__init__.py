"""Argus connector package.

Provides ArgusConnector (real) and NullArgusConnector (heuristic fallback).
Use get_argus_connector() to obtain the correct implementation based on env.

Open-core boundary: Aegis works fully without Argus. All connector methods
have heuristic fallbacks that activate when ARGUS_ENDPOINT / ARGUS_API_KEY
are absent or when the remote is unreachable.
"""
from src.argus.connector import (
    ArgusConnector,
    Decision,
    Explanation,
    NullArgusConnector,
    RiskScore,
    get_argus_connector,
)

__all__ = [
    "ArgusConnector",
    "Decision",
    "Explanation",
    "NullArgusConnector",
    "RiskScore",
    "get_argus_connector",
]
