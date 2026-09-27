"""Run Semgrep with wbx's local CTF rulepacks and normalize the JSON output.

Offline by contract: --metrics=off and --disable-version-check mean no network
call ever leaves this process. Rules come only from the local rules/ dir.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..models import DataflowStep, Finding
from ..ingest.walk import SKIP_DIRS

# Rules dir shipped with wbx: <repo>/rules/semgrep
_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "semgrep"


class SemgrepError(RuntimeError):
    """Raised when semgrep is present but a scan genuinely fails. Never swallowed
    into an empty result -- a failed scan must not masquerade as a clean one."""


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _severity(sev: str) -> str:
    return {"ERROR": "ERROR", "WARNING": "WARNING", "INFO": "INFO"}.get(sev.upper(), "WARNING")


def _extract_dataflow(extra: dict[str, Any]) -> tuple[list[DataflowStep], str | None, str | None]:
    """Pull a taint trace out of semgrep's dataflow_trace if present."""
    steps: list[DataflowStep] = []
    source = None
    sink = None
    trace = extra.get("dataflow_trace")
    if not trace:
        return steps, source, sink

    def _loc(node: dict[str, Any]) -> DataflowStep | None:
        loc = node.get("location") or {}
        path = loc.get("path")
        line = (loc.get("start") or {}).get("line")
        if path and line:
            return DataflowStep(file=path, line=line, content=node.get("content", "") or "")
        return None

    src = trace.get("taint_source")
    if isinstance(src, list) and src:
        for item in src:
            if isinstance(item, dict):
                ds = _loc(item)
                if ds:
                    steps.append(ds)
                    source = ds.content or source
    for inter in trace.get("intermediate_vars", []) or []:
        if isinstance(inter, dict):
            ds = _loc(inter)
            if ds:
                steps.append(ds)
    snk = trace.get("taint_sink")
    if isinstance(snk, list) and snk:
        for item in snk:
            if isinstance(item, dict):
                ds = _loc(item)
                if ds:
                    steps.append(ds)
                    sink = ds.content or sink
    return steps, source, sink


def _to_finding(result: dict[str, Any], root: Path) -> Finding:
    extra = result.get("extra", {}) or {}
    meta = extra.get("metadata", {}) or {}
    path = result.get("path", "")
    try:
        rel_path = str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        rel_path = path
    start_line = (result.get("start") or {}).get("line", 0)

    dataflow, source, sink = _extract_dataflow(extra)
    # rebase dataflow paths to relative
    for step in dataflow:
        try:
            step.file = str(Path(step.file).resolve().relative_to(root.resolve()))
        except (ValueError, OSError):
            pass

    return Finding(
        rule_id=result.get("check_id", "unknown"),
        engine="semgrep",
        lang=meta.get("lang", "") or (meta.get("languages", [""])[0] if meta.get("languages") else ""),
        vuln_class=meta.get("vuln_class", "uncategorized"),
        file=rel_path,
        line=start_line,
        message=extra.get("message", "").strip(),
        snippet=(extra.get("lines", "") or "").strip()[:500],
        severity=_severity(extra.get("severity", "WARNING")),
        confidence=str(meta.get("confidence", "MEDIUM")).upper(),
        source=source,
        sink=sink,
        dataflow=dataflow,
        exploitation_note=meta.get("exploitation", "") or "",
        metadata={
            "references": meta.get("references", []),
            "cwe": meta.get("cwe", ""),
            "hint": bool(meta.get("hint", False)),
        },
    )


def run_semgrep(
    root: str | Path,
    rules_dir: str | Path | None = None,
    timeout: int = 300,
    retries: int = 2,
) -> list[Finding]:
    """Scan `root` with local rules.

    Returns [] only when semgrep is not installed (a documented, explicit state).
    A genuine scan failure (crash, empty output, unparseable JSON, error exit) is
    retried up to `retries` times and then raises SemgrepError -- it is never
    silently turned into an empty result, because an empty result reads as
    'clean' and that is exactly the lie that makes a scanner unreliable.

    Exit codes: semgrep returns 0 (no blocking findings) or 1 (blocking findings)
    on a successful run; anything else is an error.
    """
    if not semgrep_available():
        return []
    root = Path(root)
    rules = Path(rules_dir) if rules_dir else _RULES_DIR

    cmd = [
        "semgrep",
        "--config", str(rules),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--quiet",
    ]
    for d in sorted(SKIP_DIRS):
        cmd += ["--exclude", d]
    cmd.append(str(root))

    last_err = "unknown"
    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            last_err = f"timeout after {timeout}s"
            continue
        except OSError as e:
            last_err = f"could not launch semgrep: {e}"
            continue

        if proc.returncode not in (0, 1):
            last_err = f"exit {proc.returncode}; stderr: {proc.stderr.strip()[:300]}"
            continue
        if not proc.stdout.strip():
            last_err = f"empty stdout (exit {proc.returncode}); stderr: {proc.stderr.strip()[:300]}"
            continue
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            last_err = f"unparseable JSON: {e}"
            continue

        return [_to_finding(r, root) for r in data.get("results", [])]

    raise SemgrepError(
        f"semgrep scan of {root} failed after {retries + 1} attempts: {last_err}"
    )
