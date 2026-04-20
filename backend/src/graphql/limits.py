"""GraphQL query depth and complexity limits."""
from __future__ import annotations

MAX_QUERY_DEPTH = 5
MAX_PER_PAGE = 100


def check_query_depth(query: str, max_depth: int = MAX_QUERY_DEPTH) -> None:
    """Reject queries that exceed max nesting depth."""
    depth = 0
    max_seen = 0
    in_string = False
    prev_char = ""
    for char in query:
        if char == '"' and prev_char != "\\":
            in_string = not in_string
        elif not in_string:
            if char == "{":
                depth += 1
                max_seen = max(max_seen, depth)
            elif char == "}":
                depth -= 1
        prev_char = char
    if max_seen > max_depth:
        raise ValueError(
            f"Query depth {max_seen} exceeds maximum allowed depth of {max_depth}"
        )


def clamp_per_page(per_page: int | None) -> int:
    """Clamp per_page to safe range."""
    if per_page is None:
        return 25
    return max(1, min(per_page, MAX_PER_PAGE))
