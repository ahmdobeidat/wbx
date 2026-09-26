"""Shared source-tree walking. One definition of 'what is a source file' and
'what do we skip' so every stage agrees.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

# Directories that are never the challenge's own code.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", ".idea", ".vscode", "dist", "build", ".pytest_cache",
    "site-packages", "bower_components",
}

# extension -> language
EXT_LANG = {
    ".php": "php",
    ".phtml": "php",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".rb": "ruby",
    ".erb": "ruby",
    ".java": "java",
}

# Text files worth grepping for flags/secrets even when not a "source" language.
AUX_EXT = {".env", ".txt", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".md", ".html"}


def iter_source_files(root: str | Path) -> Iterator[Path]:
    """Yield code files under root, skipping dependency and VCS dirs."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in EXT_LANG:
                yield p


def iter_text_files(root: str | Path) -> Iterator[Path]:
    """Yield code + auxiliary text files (for flag/secret hunting)."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            suf = p.suffix.lower()
            if suf in EXT_LANG or suf in AUX_EXT or fn in {".env", "Dockerfile", "docker-compose.yml"}:
                yield p


def lang_of(path: str | Path) -> str | None:
    return EXT_LANG.get(Path(path).suffix.lower())


def rel(path: str | Path, root: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)
