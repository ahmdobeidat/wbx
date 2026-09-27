"""Psalm taint analysis: inter-procedural (cross-file) taint for PHP.

This fills the single biggest gap in wbx: CodeQL cannot analyze PHP, and Semgrep
OSS taint is intra-file, so a multi-file PHP flow (user input in one file reaching
a sink in another) was invisible to real dataflow and only caught by heuristics.
Psalm's --taint-analysis builds a source->sink data-flow graph across the whole
call graph, exactly what PHP challenges need.

Best-effort like the CodeQL deep pass: any failure returns [] rather than sinking
the scan (Semgrep remains the reliable PHP baseline).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..models import DataflowStep, Finding

# Psalm taint issue name -> wbx vuln_class
_PSALM_CLASS = {
    "TaintedUnserialize": "php_object_injection",
    "TaintedInclude": "php_lfi",
    "TaintedSql": "php_sqli",
    "TaintedHtml": "xss",
    "TaintedTextWithQuotes": "xss",
    "TaintedShell": "php_command_injection",
    "TaintedExec": "php_command_injection",
    "TaintedCallable": "php_command_injection",
    "TaintedEval": "php_eval",
    "TaintedFile": "path_traversal",
    "TaintedHeader": "open_redirect",
    "TaintedRedirect": "open_redirect",
    "TaintedSSRF": "ssrf",
    "TaintedLdap": "sql_injection",
    "TaintedXpath": "sql_injection",
    "TaintedCookie": "xss",
    "TaintedCredentials": "hardcoded_secret",
    "TaintedSystemSecret": "hardcoded_secret",
}


def psalm_available() -> bool:
    return shutil.which("psalm") is not None


def _has_php(root: Path) -> bool:
    for _ in root.rglob("*.php"):
        return True
    return False


def _write_config(abs_src: str, cfg_path: Path) -> None:
    # Psalm errors if an <ignoreFiles> directory does not exist, so only list the
    # dependency dirs that are actually present.
    ignore = [d for d in ("vendor", "node_modules") if (Path(abs_src) / d).is_dir()]
    ignore_block = ""
    if ignore:
        entries = "".join(f'      <directory name="{abs_src}/{d}"/>\n' for d in ignore)
        ignore_block = "    <ignoreFiles>\n" + entries + "    </ignoreFiles>\n"
    cfg_path.write_text(
        '<?xml version="1.0"?>\n'
        '<psalm errorLevel="8" resolveFromConfigFile="false" '
        'findUnusedBaselineEntry="false" findUnusedCode="false">\n'
        "  <projectFiles>\n"
        f'    <directory name="{abs_src}"/>\n'
        + ignore_block +
        "  </projectFiles>\n"
        "</psalm>\n"
    )


def _parse_codeflow(res: dict[str, Any], root: Path) -> list[DataflowStep]:
    steps: list[DataflowStep] = []
    for cf in res.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            for loc in tf.get("locations", []) or []:
                phys = ((loc.get("location", {}) or {}).get("physicalLocation", {}) or {})
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine", 0)
                if uri and line:
                    steps.append(DataflowStep(file=_rel(uri, root), line=line))
            if steps:
                return steps
    return steps


def _rel(uri: str, root: Path) -> str:
    try:
        return str(Path(uri).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return uri


def _parse_sarif(sarif_path: Path, root: Path) -> list[Finding]:
    try:
        data = json.loads(sarif_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])}
        for res in run.get("results", []):
            rid = res.get("ruleId")
            rule = rules.get(rid, {})
            name = rule.get("name") or ""
            vuln_class = _PSALM_CLASS.get(name, "uncategorized")
            locs = res.get("locations", []) or []
            if not locs:
                continue
            phys = (locs[0].get("physicalLocation", {}) or {})
            uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
            line = (phys.get("region", {}) or {}).get("startLine", 0)
            dataflow = _parse_codeflow(res, root)
            findings.append(Finding(
                rule_id=f"psalm.{name or rid}",
                engine="psalm",
                lang="php",
                vuln_class=vuln_class,
                file=_rel(uri, root),
                line=line,
                message=(res.get("message", {}) or {}).get("text", "").strip(),
                severity="ERROR",
                confidence="HIGH",   # psalm taint is a proven cross-file data-flow path
                source=(dataflow[0].content if dataflow else None),
                sink=(dataflow[-1].content if dataflow else None),
                dataflow=dataflow,
                metadata={"psalm_rule": name or rid},
            ))
    return findings


def run_psalm(root: str | Path, timeout: int = 300) -> list[Finding]:
    """Run Psalm taint analysis over PHP source. Returns [] on any failure/absence."""
    if not psalm_available():
        return []
    root = Path(root)
    if not _has_php(root):
        return []
    abs_src = str(root.resolve())

    with tempfile.TemporaryDirectory(prefix="wbx-psalm-") as tmp:
        cfg = Path(tmp) / "psalm.xml"
        _write_config(abs_src, cfg)
        sarif = Path(tmp) / "out.sarif"
        cmd = [
            "psalm",
            "--taint-analysis",
            f"--config={cfg}",
            "--no-cache",
            "--no-progress",
            f"--report={sarif}",
            f"--root={abs_src}",
        ]
        try:
            # psalm exits non-zero when it reports issues; we key off the SARIF file.
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=tmp)
        except (subprocess.TimeoutExpired, OSError):
            return []
        if not sarif.exists():
            return []
        return _parse_sarif(sarif, root)
