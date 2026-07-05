"""Parse ``PREVIOUS_DIGESTS`` env JSON and look up a previous digest.

Port of the inline python3 block in scanners/container/run.sh that maps an
image reference to its previous digest. Both the exact reference and the
``ref`` stripped of its ``:tag`` are honoured — the backend may send either
form."""
from __future__ import annotations

import json
import logging
from typing import Mapping

logger = logging.getLogger(__name__)


def parse_previous_digests(raw: str | None) -> dict[str, str]:
    """Return a dict[image_ref -> digest] from ``PREVIOUS_DIGESTS`` JSON.

    Returns an empty dict when the env is unset, empty, malformed, or shaped
    as anything other than a JSON object. Logs (but does not raise) on
    malformed input — a misconfigured retry payload must not abort the scan.
    """
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning(
            "[!] PREVIOUS_DIGESTS is not valid JSON; treating as empty: %s", e
        )
        return {}
    if not isinstance(data, dict):
        logger.warning(
            "[!] PREVIOUS_DIGESTS must be a JSON object; got %s",
            type(data).__name__,
        )
        return {}
    out: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(key, str) and isinstance(value, str) and value:
            out[key] = value
    return out


def lookup_previous_digest(
    image_ref: str, previous: Mapping[str, str]
) -> str | None:
    """Return the previous digest for ``image_ref`` or None.

    Matches either the full reference (``host/repo:tag``) or the reference
    stripped of its tag (``host/repo``). Mirrors the bash inline python3
    helper that walks the dict checking both forms.
    """
    if not previous:
        return None
    direct = previous.get(image_ref)
    if direct:
        return direct
    if ":" in image_ref and not image_ref.startswith("sha256:"):
        name = image_ref.rsplit(":", 1)[0]
        candidate = previous.get(name)
        if candidate:
            return candidate
    return None


def normalize_digest(value: str | None) -> str | None:
    """Strip whitespace and a leading ``sha256:`` to enable direct comparison.

    The SBOM hash is stored as ``sha256:<hex>`` while the registry HEAD path
    returns the same form; comparing the bare hex avoids false negatives if
    one side accidentally omits the prefix.
    """
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if v.lower().startswith("sha256:"):
        v = v[len("sha256:") :]
    return v.lower() or None


def digests_match(a: str | None, b: str | None) -> bool:
    """Return True when ``a`` and ``b`` reduce to the same hex digest."""
    na = normalize_digest(a)
    nb = normalize_digest(b)
    return bool(na) and bool(nb) and na == nb


__all__ = (
    "parse_previous_digests",
    "lookup_previous_digest",
    "normalize_digest",
    "digests_match",
)
