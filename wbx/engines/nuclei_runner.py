"""Nuclei: live-target confirmation layer (DAST), NOT part of the offline scan.

wbx scan reads source and never touches the network. Nuclei is the complementary
step: once static review has pointed you at the challenge's tech and surface, run
nuclei against the *authorized live challenge instance* to fingerprint it and
confirm known-CVE / misconfig / exposure templates. Kept in its own subcommand so
the offline guarantee of `scan` is never violated.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

# wbx framework label -> nuclei tag(s) to focus templates on the detected stack
FRAMEWORK_TAGS = {
    "laravel": ["laravel"], "symfony": ["symfony"], "slim": ["php"],
    "flask": ["flask"], "django": ["django"], "fastapi": ["fastapi"],
    "express": ["expressjs", "nodejs"], "koa": ["nodejs"], "nextjs": ["nextjs"],
    "sinatra": ["ruby"], "rails": ["rails"], "spring": ["springboot", "java"],
}


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def tags_for_frameworks(frameworks: list[str]) -> list[str]:
    tags: list[str] = []
    for fw in frameworks:
        for t in FRAMEWORK_TAGS.get(fw, []):
            if t not in tags:
                tags.append(t)
    return tags


def run_nuclei(
    target: str,
    templates: str | None = None,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
    timeout: int = 600,
) -> list[dict[str, Any]]:
    """Run nuclei against a live authorized target. Returns parsed JSONL hits.

    Offline note: nuclei needs its templates pre-fetched (it will try to update on
    first run). `-disable-update-check` keeps it from phoning home mid-run.
    """
    if not nuclei_available():
        return []
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-disable-update-check", "-no-color"]
    if templates:
        cmd += ["-t", templates]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if severity:
        cmd += ["-severity", ",".join(severity)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return []

    hits: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        hits.append({
            "template_id": obj.get("template-id", obj.get("templateID", "")),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "tags": info.get("tags", []),
            "matched_at": obj.get("matched-at", obj.get("host", "")),
            "type": obj.get("type", ""),
        })
    return hits
