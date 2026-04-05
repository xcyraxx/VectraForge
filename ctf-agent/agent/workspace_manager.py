"""
workspace_manager.py — Per-challenge isolated workspace lifecycle.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class WorkspaceManager:
    """Creates and manages an isolated directory for each challenge run."""

    def __init__(self, base_dir: str = "workspace/challenges"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.current: Optional[Path] = None

    # ------------------------------------------------------------------ lifecycle
    def init(self, challenge_name: str) -> Path:
        slug = self._slugify(challenge_name)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        ws = self.base_dir / f"{slug}_{ts}"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "artifacts").mkdir()
        (ws / "outputs").mkdir()
        (ws / "logs").mkdir()
        self.current = ws
        logger.info("Workspace initialised: %s", ws)
        return ws

    def copy_challenge_files(self, *file_paths: str) -> list[Path]:
        """Copy challenge files into the workspace and return new paths."""
        if not self.current:
            raise RuntimeError("Workspace not initialised")
        copied = []
        for fp in file_paths:
            src = Path(fp)
            if not src.exists():
                logger.warning("Challenge file not found: %s", fp)
                continue
            dst = self.current / src.name
            shutil.copy2(src, dst)
            copied.append(dst)
            logger.info("Copied %s → %s", src, dst)
        return copied

    def artifact_path(self, name: str) -> Path:
        if not self.current:
            raise RuntimeError("Workspace not initialised")
        return self.current / "artifacts" / name

    def output_path(self, name: str) -> Path:
        if not self.current:
            raise RuntimeError("Workspace not initialised")
        return self.current / "outputs" / name

    def log_path(self, name: str) -> Path:
        if not self.current:
            raise RuntimeError("Workspace not initialised")
        return self.current / "logs" / name

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _slugify(name: str) -> str:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        return safe[:48]

    def file_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
