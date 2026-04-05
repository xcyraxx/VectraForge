"""
memory.py — Structured in-memory knowledge store for the CTF agent.

Tracks discovered artifacts, tested hypotheses, retrieved writeup techniques,
and all observations so the LLM always has relevant context.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    category: str          # artifact | string | endpoint | vuln | technique | hypothesis
    key: str
    value: Any
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = ""       # which tool produced this


class AgentMemory:
    """Central knowledge repository for a single challenge run."""

    def __init__(self, max_entries: int = 200):
        self._max = max_entries
        self._store: dict[str, list[MemoryEntry]] = defaultdict(list)
        self._flags: list[str] = []
        self._tested_inputs: list[str] = []
        self._failed_tools: list[str] = []

    # ------------------------------------------------------------------ write
    def add(
        self,
        category: str,
        key: str,
        value: Any,
        confidence: float = 1.0,
        source: str = "",
    ) -> None:
        entries = self._store[category]
        # deduplicate by key
        if any(e.key == key for e in entries):
            return
        entry = MemoryEntry(category, key, value, confidence, source=source)
        entries.append(entry)
        total = sum(len(v) for v in self._store.values())
        if total > self._max:
            self._evict_oldest()
        logger.debug("Memory +[%s] %s", category, key[:80])

    def record_flag_candidate(self, flag: str) -> None:
        if flag not in self._flags:
            self._flags.append(flag)
            logger.info("Flag candidate recorded: %s", flag)

    def record_tested_input(self, inp: str) -> None:
        if inp not in self._tested_inputs:
            self._tested_inputs.append(inp[-200:])  # cap length

    def record_failed_tool(self, tool: str) -> None:
        if tool not in self._failed_tools:
            self._failed_tools.append(tool)

    # ------------------------------------------------------------------ read
    def get_category(self, category: str) -> list[MemoryEntry]:
        return self._store.get(category, [])

    def search(self, keyword: str) -> list[MemoryEntry]:
        keyword_lower = keyword.lower()
        results = []
        for entries in self._store.values():
            for e in entries:
                if keyword_lower in str(e.key).lower() or keyword_lower in str(e.value).lower():
                    results.append(e)
        return results

    def all_entries(self) -> list[MemoryEntry]:
        out = []
        for entries in self._store.values():
            out.extend(entries)
        return sorted(out, key=lambda e: e.timestamp)

    # ------------------------------------------------------------------ summary
    def build_summary(self) -> str:
        """Render a compact text summary suitable for LLM context injection."""
        lines = ["=== AGENT MEMORY SUMMARY ==="]

        for cat, entries in self._store.items():
            if not entries:
                continue
            lines.append(f"\n[{cat.upper()}]")
            for e in entries[-10:]:  # most recent 10 per category
                val_str = str(e.value)[:120].replace("\n", " ")
                lines.append(f"  • {e.key}: {val_str}")

        if self._flags:
            lines.append("\n[FLAG CANDIDATES]")
            for f in self._flags:
                lines.append(f"  ★ {f}")

        if self._tested_inputs:
            lines.append(f"\n[TESTED INPUTS] ({len(self._tested_inputs)} total)")
            for inp in self._tested_inputs[-5:]:
                lines.append(f"  - {inp[:80]}")

        if self._failed_tools:
            lines.append(f"\n[FAILED TOOLS] {', '.join(self._failed_tools)}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ persistence
    def save(self, path: Path) -> None:
        data = {
            cat: [vars(e) for e in entries]
            for cat, entries in self._store.items()
        }
        data["_flags"] = self._flags
        data["_tested_inputs"] = self._tested_inputs
        data["_failed_tools"] = self._failed_tools
        path.write_text(json.dumps(data, indent=2))
        logger.debug("Memory saved → %s", path)

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text())
        self._flags = data.pop("_flags", [])
        self._tested_inputs = data.pop("_tested_inputs", [])
        self._failed_tools = data.pop("_failed_tools", [])
        for cat, entries in data.items():
            for e in entries:
                self._store[cat].append(MemoryEntry(**e))

    # ------------------------------------------------------------------ private
    def _evict_oldest(self) -> None:
        oldest: Optional[tuple[str, int]] = None
        oldest_ts = "9"
        for cat, entries in self._store.items():
            if entries and entries[0].timestamp < oldest_ts:
                oldest_ts = entries[0].timestamp
                oldest = (cat, 0)
        if oldest:
            self._store[oldest[0]].pop(oldest[1])
