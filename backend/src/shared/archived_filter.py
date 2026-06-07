"""Helpers for the archived-row default-exclusion pattern.

Apply ``exclude_archived(query, model)`` to user-facing read queries that
should hide archived rows. Use ``include_archived(query)`` as a marker
when the caller intentionally wants archived rows (it's a no-op so the
audit trail is grep-able).
"""
from __future__ import annotations

from typing import TypeVar

from sqlalchemy.sql import Select

Q = TypeVar("Q", bound=Select)


def exclude_archived(query: Q, model: type) -> Q:
    """Append ``model.archived == False`` to the WHERE clause."""
    return query.where(model.archived == False)  # noqa: E712


def include_archived(query: Q) -> Q:
    """Marker no-op — explicit acknowledgement the caller wants archived rows.

    Use for compliance/audit endpoints that intentionally return archived rows.
    The function exists to make audit-pass `grep` easier: callers that omit
    the filter entirely will appear missing both markers.
    """
    return query


def only_archived(query: Q, model: type) -> Q:
    """Append ``model.archived == True`` to the WHERE clause.

    Use for explicit archived-row views (e.g. ``GET /findings?archived=true``).
    Separate from ``include_archived(query)`` which is a true no-op marker.
    """
    return query.where(model.archived == True)  # noqa: E712
