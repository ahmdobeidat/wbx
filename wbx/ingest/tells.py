"""Find the CTF tells: flag strings, flag files, and hardcoded secrets.

These are the highest-signal facts in a challenge. A sink that sits three lines
from `$flag` or reads `/flag.txt` is almost certainly the intended bug, so the
scorer weights proximity to these heavily.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .walk import iter_text_files, rel

# Flag-format regexes seen across CTFs (Arab CS, wargames, HTB style, generic).
FLAG_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9_]{2,12}\{[^}\n]{1,120}\}"),   # HTB{...}, ACSC{...}, flag{...}
    re.compile(r"\bflag\b", re.IGNORECASE),
]

# References to a flag *file* on the box (the flag isn't in source, it's read at runtime).
FLAG_FILE_PATTERNS = [
    re.compile(r"/flag(?:\.txt|\.php)?\b"),
    re.compile(r"\breadflag\b", re.IGNORECASE),
    re.compile(r"\bgetenv\(\s*['\"]FLAG['\"]", re.IGNORECASE),
    re.compile(r"\benviron\[?\s*['\"]FLAG['\"]", re.IGNORECASE),
]

SECRET_PATTERNS = [
    (re.compile(r"(?i)(secret|api[_-]?key|token|password|passwd|jwt[_-]?secret)\s*[:=]\s*['\"]([^'\"\n]{4,})['\"]"), "assigned_secret"),
    (re.compile(r"(?i)\b(SECRET_KEY|APP_KEY|JWT_SECRET|ADMIN_PASSWORD)\b"), "secret_name"),
]

MAX_BYTES = 512 * 1024  # skip files bigger than this; CTF source is small


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(errors="replace")
    except (OSError, UnicodeError):
        return None


def find_tells(root: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (flag_hits, secret_hits)."""
    flag_hits: list[dict[str, Any]] = []
    secret_hits: list[dict[str, Any]] = []

    for path in iter_text_files(root):
        text = _read(path)
        if text is None:
            continue
        r = rel(path, root)
        for lineno, line in enumerate(text.splitlines(), start=1):
            # literal flag values (most valuable)
            for pat in FLAG_PATTERNS[:1]:
                m = pat.search(line)
                if m:
                    flag_hits.append({"file": r, "line": lineno, "kind": "flag_literal", "value": m.group(0)[:120]})
            # flag-file references
            for pat in FLAG_FILE_PATTERNS:
                if pat.search(line):
                    flag_hits.append({"file": r, "line": lineno, "kind": "flag_file_ref", "value": line.strip()[:120]})
                    break
            # secrets
            for pat, kind in SECRET_PATTERNS:
                m = pat.search(line)
                if m:
                    secret_hits.append({"file": r, "line": lineno, "kind": kind, "value": line.strip()[:120]})
                    break

    # de-dupe (file,line,kind)
    flag_hits = _dedupe(flag_hits)
    secret_hits = _dedupe(secret_hits)
    return flag_hits, secret_hits


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for it in items:
        key = (it["file"], it["line"], it["kind"])
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out
