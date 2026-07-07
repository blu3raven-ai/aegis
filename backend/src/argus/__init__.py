"""Argus connector package.

Provides ArgusConnector, which runs in disabled mode (heuristic fallback) when
Argus is unconfigured and makes HTTPS calls when configured. Use
get_argus_connector() to build one from env.

Open-core boundary: Aegis works fully without Argus. All connector methods
have heuristic fallbacks that activate when ARGUS_ENDPOINT / ARGUS_API_KEY
are absent or when the remote is unreachable.
"""
from src.argus.connector import (
    ArgusConnector,
    Explanation,
    RiskScore,
    get_argus_connector,
)

__all__ = [
    "ArgusConnector",
    "Explanation",
    "RiskScore",
    "get_argus_connector",
]
