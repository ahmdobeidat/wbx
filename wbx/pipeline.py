"""The scan pipeline as a single callable, so both the CLI and the test harness
drive the exact same path (no gate rebuilding its own flow -- that trap has bitten
us before)."""
from __future__ import annotations

from pathlib import Path

from .brain import (
    apply_chain_bonus,
    apply_reachability,
    detect_chains,
    enrich_and_rank,
    find_access_control_hints,
    merge_findings,
)
from .engines import run_codeql, run_psalm, run_semgrep
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

    raw = run_semgrep(root, rules_dir=semgrep_rules)
    if deep:
        langs = list(surface.languages.keys())
        # CodeQL for py/js/rb/java inter-procedural taint...
        raw += run_codeql(root, langs, timeout=codeql_timeout)
        # ...and Psalm for PHP, which CodeQL cannot analyze (cross-file PHP taint).
        if "php" in langs:
            raw += run_psalm(root)

    # Split logic/access-control HINTS out of the confident findings so the ranked
    # list stays trustworthy. Hints are things SAST cannot confirm.
    hint_findings = [f for f in raw if f.metadata.get("hint")]
    findings = [f for f in raw if not f.metadata.get("hint")]

    findings = merge_findings(findings)
    findings = enrich_and_rank(findings, surface)
    chains = detect_chains(findings, template_dir=chain_templates)
    # findings on a detected flag-reaching chain get a within-tier ranking boost
    findings = apply_chain_bonus(findings, chains)
    # reachability: nudge reachable findings up within tier, flag rabbit holes
    cautions = apply_reachability(findings, surface, root)

    # access-control leads (missing auth guard on a route) -> hints channel
    hint_findings += find_access_control_hints(root, surface)
    hint_findings.sort(key=lambda x: (x.file, x.line, x.vuln_class))

    if scaffold_dir is not None:
        generate_scaffolds(findings, scaffold_dir)

    return ScanResult(
        root=root, surface=surface, findings=findings,
        chains=chains, hints=hint_findings, cautions=cautions,
    )
