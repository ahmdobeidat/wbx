"""The scan pipeline as a single callable, so both the CLI and the test harness
drive the exact same path (no gate rebuilding its own flow -- that trap has bitten
us before)."""
from __future__ import annotations

from pathlib import Path

from .brain import detect_chains, enrich_and_rank, merge_findings
from .engines import run_codeql, run_semgrep
from .ingest import build_surface_map
from .models import ScanResult
from .scaffolds import generate_scaffolds


def scan(
    root: str | Path,
    deep: bool = False,
    semgrep_rules: str | Path | None = None,
    chain_templates: str | Path | None = None,
    scaffold_dir: str | Path | None = None,
    codeql_timeout: int = 900,
) -> ScanResult:
    root = str(root)
    surface = build_surface_map(root)

    findings = run_semgrep(root, rules_dir=semgrep_rules)
    if deep:
        langs = list(surface.languages.keys())
        findings += run_codeql(root, langs, timeout=codeql_timeout)

    findings = merge_findings(findings)
    findings = enrich_and_rank(findings, surface)
    chains = detect_chains(findings, template_dir=chain_templates)

    if scaffold_dir is not None:
        generate_scaffolds(findings, scaffold_dir)

    return ScanResult(root=root, surface=surface, findings=findings, chains=chains)
