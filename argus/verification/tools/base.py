"""Tool registry + dispatch for the agent loop."""
from __future__ import annotations

import dataclasses
import json
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


_MAX_RESULT_CHARS = 4_000


@dataclasses.dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema, draft-07 subset
    handler: Callable[[dict[str, Any]], str]

    def to_openai_spec(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclasses.dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "result": self.result,
            "error": self.error,
        }


class ToolRegistry:
    def __init__(self, tools: list[Tool]) -> None:
        names = [t.name for t in tools]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate tool names: {sorted(dupes)}")
        self._tools: dict[str, Tool] = {t.name: t for t in tools}

    def to_openai_spec(self) -> list[dict[str, Any]]:
        return [t.to_openai_spec() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def execute(self, name: str, arguments: dict[str, Any]) -> ToolCallRecord:
        """Invoke a tool by name; never raises — errors return as ToolCallRecord."""
        tool = self._tools.get(name)
        if tool is None:
            return ToolCallRecord(
                name=name,
                arguments=arguments,
                result="",
                error=f"unknown tool '{name}'. Available: {sorted(self._tools)}",
            )
        try:
            result = tool.handler(arguments)
        except Exception as exc:  # noqa: BLE001
            logger.debug("tool %s raised: %s", name, exc)
            return ToolCallRecord(
                name=name,
                arguments=arguments,
                result="",
                error=f"{type(exc).__name__}: {exc}",
            )
        if not isinstance(result, str):
            result = json.dumps(result, default=str)
        if len(result) > _MAX_RESULT_CHARS:
            result = result[: _MAX_RESULT_CHARS - 1] + "…"
        return ToolCallRecord(name=name, arguments=arguments, result=result)
