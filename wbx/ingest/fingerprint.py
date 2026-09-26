"""Detect languages present and the web framework in use.

Framework detection matters because it tells the route mapper where to look
and tells the scorer which entrypoint patterns are meaningful.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .walk import iter_source_files, lang_of, rel

# manifest filename -> (framework hints via content check)
_MANIFESTS = {
    "composer.json": "php",
    "requirements.txt": "python",
    "Pipfile": "python",
    "pyproject.toml": "python",
    "package.json": "javascript",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
}

# substring in a manifest -> framework label
_FRAMEWORK_HINTS = {
    "laravel/framework": "laravel",
    "symfony/": "symfony",
    "slim/slim": "slim",
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "express": "express",
    "koa": "koa",
    "next": "nextjs",
    "sinatra": "sinatra",
    "rails": "rails",
    "spring-boot": "spring",
    "springframework": "spring",
}


def fingerprint(root: str | Path) -> tuple[dict[str, int], list[str]]:
    """Return (languages{lang: file_count}, frameworks[])."""
    root = Path(root)
    counts: Counter[str] = Counter()
    for p in iter_source_files(root):
        lg = lang_of(p)
        if lg:
            counts[lg] += 1

    frameworks: list[str] = []
    for name, _lang in _MANIFESTS.items():
        for mpath in root.rglob(name):
            if any(part in {"node_modules", "vendor", ".git"} for part in mpath.parts):
                continue
            try:
                text = mpath.read_text(errors="replace").lower()
            except OSError:
                continue
            for needle, label in _FRAMEWORK_HINTS.items():
                if needle in text and label not in frameworks:
                    frameworks.append(label)

    return dict(counts), frameworks
