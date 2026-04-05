"""
tool_registry.py — Central registry for all agent tools.

Each tool is described by a ToolSpec and backed by a callable.
The registry validates calls and routes execution.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict                  # {param_name: type_hint_str}
    fn: Callable[..., str]
    category: str = "misc"
    safe: bool = True                   # False = requires extra confirmation


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    # ------------------------------------------------------------------ registration
    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec
        logger.debug("Tool registered: %s [%s]", spec.name, spec.category)

    def register_all(self, specs: list[ToolSpec]) -> None:
        for s in specs:
            self.register(s)

    # ------------------------------------------------------------------ execution
    def execute(self, name: str, raw_input: str, timeout: int = 60) -> str:
        """
        Execute a named tool with the provided raw input string.
        Input may be a plain path/string or a JSON object.
        Returns a string observation.
        """
        import json, signal, textwrap

        spec = self._tools.get(name)
        if spec is None:
            available = ", ".join(sorted(self._tools))
            return f"ERROR: Unknown tool '{name}'. Available tools: {available}"

        # Parse input
        try:
            if raw_input.strip().startswith("{"):
                kwargs = json.loads(raw_input)
            else:
                # Single positional arg — use first key in schema
                first_key = next(iter(spec.input_schema))
                kwargs = {first_key: raw_input.strip()}
        except Exception as exc:
            return f"ERROR: Could not parse tool input: {exc}"

        # Execute with timeout
        def _handler(signum, frame):
            raise TimeoutError(f"Tool '{name}' timed out after {timeout}s")

        try:
            signal.signal(signal.SIGALRM, _handler)
            signal.alarm(timeout)
            result = spec.fn(**kwargs)
            signal.alarm(0)
            return str(result) if result is not None else "(no output)"
        except TimeoutError as exc:
            return f"TIMEOUT: {exc}"
        except Exception as exc:
            logger.exception("Tool '%s' raised an exception", name)
            return f"ERROR running '{name}': {type(exc).__name__}: {exc}"
        finally:
            signal.alarm(0)

    # ------------------------------------------------------------------ introspection
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "category": s.category,
                "description": s.description,
                "input_schema": s.input_schema,
            }
            for s in self._tools.values()
        ]

    def tool_catalog(self) -> str:
        """Human-readable tool list for inclusion in prompts."""
        lines = ["Available tools:"]
        by_cat: dict[str, list[ToolSpec]] = {}
        for s in self._tools.values():
            by_cat.setdefault(s.category, []).append(s)
        for cat, specs in sorted(by_cat.items()):
            lines.append(f"\n[{cat.upper()}]")
            for s in specs:
                params = ", ".join(f"{k}: {v}" for k, v in s.input_schema.items())
                lines.append(f"  {s.name}({params}) — {s.description}")
        return "\n".join(lines)

    def has_tool(self, name: str) -> bool:
        return name in self._tools
