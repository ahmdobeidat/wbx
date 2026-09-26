"""Run CodeQL for deep inter-procedural taint on the languages it supports.

CodeQL does NOT support PHP, so PHP is never routed here. This is the opt-in
`--deep` pass: DB creation is slow and, for compiled languages, can fail without
a build. Every failure path returns [] so a broken deep pass never sinks a scan.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..models import DataflowStep, Finding

# CodeQL-analyzable languages we care about (PHP excluded on purpose).
CODEQL_LANGS = {"python", "javascript", "ruby", "java"}

# Standard security query suites per language, addressed by pack:suite so CodeQL
# resolves them from the offline pack cache (no download). security-extended is
# security-focused with high recall and skips code-quality noise (unused vars etc).
_STD_SUITE = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
}

_CUSTOM_QL = Path(__file__).resolve().parents[2] / "rules" / "codeql"


def codeql_available() -> bool:
    return shutil.which("codeql") is not None


def _create_db(root: Path, lang: str, db_dir: Path, timeout: int) -> bool:
    cmd = [
        "codeql", "database", "create", str(db_dir),
        "--language", lang,
        "--source-root", str(root),
        "--overwrite",
        "--quiet",
    ]
    if lang == "java":
        cmd += ["--build-mode", "none"]  # best-effort extraction without compiling
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0 and db_dir.exists()
    except (subprocess.TimeoutExpired, OSError):
        return False


def _analyze(db_dir: Path, lang: str, out_sarif: Path, timeout: int) -> bool:
    # prefer custom queries if the user shipped any for this language
    custom = _CUSTOM_QL / lang
    query_target = str(custom) if custom.is_dir() and any(custom.glob("*.ql")) else _STD_SUITE.get(lang, "")
    if not query_target:
        return False
    cmd = [
        "codeql", "database", "analyze", str(db_dir), query_target,
        "--format", "sarif-latest",
        "--output", str(out_sarif),
        "--quiet",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0 and out_sarif.exists()
    except (subprocess.TimeoutExpired, OSError):
        return False


def _parse_sarif(sarif_path: Path, lang: str, root: Path) -> list[Finding]:
    try:
        data = json.loads(sarif_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    findings: list[Finding] = []
    for run in data.get("runs", []):
        # build ruleId -> metadata map for severity/tags
        rule_meta: dict[str, dict[str, Any]] = {}
        for rule in (run.get("tool", {}).get("driver", {}).get("rules", []) or []):
            rule_meta[rule.get("id", "")] = rule

        for res in run.get("results", []):
            rule_id = res.get("ruleId", "codeql")
            msg = (res.get("message", {}) or {}).get("text", "")
            locs = res.get("locations", []) or []
            if not locs:
                continue
            phys = (locs[0].get("physicalLocation", {}) or {})
            uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
            line = (phys.get("region", {}) or {}).get("startLine", 0)

            dataflow = _parse_codeflows(res, root)
            findings.append(Finding(
                rule_id=rule_id,
                engine="codeql",
                lang=lang,
                vuln_class=_map_class(rule_id),
                file=uri,
                line=line,
                message=msg.strip(),
                severity="ERROR",
                confidence="HIGH",   # codeql taint paths are high-confidence by construction
                source=(dataflow[0].content if dataflow else None),
                sink=(dataflow[-1].content if dataflow else None),
                dataflow=dataflow,
                metadata={"codeql_rule": rule_id},
            ))
    return findings


def _parse_codeflows(res: dict[str, Any], root: Path) -> list[DataflowStep]:
    steps: list[DataflowStep] = []
    for cf in res.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            for loc in tf.get("locations", []) or []:
                phys = ((loc.get("location", {}) or {}).get("physicalLocation", {}) or {})
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine", 0)
                snippet = ((phys.get("region", {}) or {}).get("snippet", {}) or {}).get("text", "")
                if uri and line:
                    steps.append(DataflowStep(file=uri, line=line, content=(snippet or "").strip()))
            if steps:
                return steps  # first thread flow is enough for a hint
    return steps


# Map noisy CodeQL rule ids to our vuln_class taxonomy (best-effort substring match).
_CLASS_KEYS = [
    ("sql", "sql_injection"),
    ("command", "command_injection"),
    ("code-injection", "python_eval_exec"),
    ("path-injection", "path_traversal"),
    ("tainted-path", "path_traversal"),
    ("ssrf", "ssrf"),
    ("request-forgery", "ssrf"),
    ("deserial", "insecure_deserialization"),
    ("unsafe-deserialization", "insecure_deserialization"),
    ("xxe", "xxe"),
    ("prototype", "prototype_pollution"),
    ("xss", "xss"),
    ("redirect", "open_redirect"),
]


def _map_class(rule_id: str) -> str:
    rid = rule_id.lower()
    for key, cls in _CLASS_KEYS:
        if key in rid:
            return cls
    return "uncategorized"


def run_codeql(root: str | Path, langs: list[str], timeout: int = 900) -> list[Finding]:
    """Deep pass. `langs` filtered to CodeQL-supported set. Returns [] on any failure."""
    if not codeql_available():
        return []
    root = Path(root)
    targets = [lg for lg in langs if lg in CODEQL_LANGS]
    if not targets:
        return []

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="wbx-codeql-") as tmp:
        tmp_path = Path(tmp)
        for lang in targets:
            db_dir = tmp_path / f"db-{lang}"
            if not _create_db(root, lang, db_dir, timeout):
                continue
            sarif = tmp_path / f"{lang}.sarif"
            if not _analyze(db_dir, lang, sarif, timeout):
                continue
            findings.extend(_parse_sarif(sarif, lang, root))
    return findings
