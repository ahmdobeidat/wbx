"""Rule-based chain detection.

A chain template encodes a known CTF escalation ("LFI + log control = RCE",
"prototype pollution + template = RCE"). Each template lists ordered steps; a
step is satisfied by a finding whose vuln_class is in the step's `any_of`. A
template fires when every step can be matched to a *distinct* finding.

Templates live in rules/chain_templates/*.yaml so the library grows per event
without touching code. This is the compounding edge.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import Chain, Finding

_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "rules" / "chain_templates"


def _load_templates(template_dir: Path) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    if not template_dir.is_dir():
        return templates
    for path in sorted(template_dir.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict):
            templates.append(doc)
        elif isinstance(doc, list):
            templates.extend(t for t in doc if isinstance(t, dict))
    return templates


def _match_template(tmpl: dict[str, Any], findings: list[Finding]) -> Chain | None:
    steps = tmpl.get("requires", [])
    if not steps:
        return None
    used: set[int] = set()
    matched: list[Finding] = []
    for step in steps:
        classes = set(step.get("any_of", []))
        # pick the highest-scoring unused finding whose class fits this step
        candidates = sorted(
            [(i, f) for i, f in enumerate(findings)
             if i not in used and f.vuln_class in classes],
            key=lambda t: t[1].score, reverse=True,
        )
        if not candidates:
            return None
        idx, f = candidates[0]
        used.add(idx)
        matched.append(f)

    base = sum(f.score for f in matched)
    bonus = float(tmpl.get("bonus", 5))
    return Chain(
        template_id=tmpl.get("id", "chain"),
        name=tmpl.get("name", "unnamed chain"),
        impact=tmpl.get("impact", ""),
        findings=matched,
        playbook=tmpl.get("playbook", "").strip(),
        score=round(base + bonus, 2),
    )


def detect_chains(findings: list[Finding], template_dir: str | Path | None = None) -> list[Chain]:
    tdir = Path(template_dir) if template_dir else _TEMPLATE_DIR
    templates = _load_templates(tdir)
    chains: list[Chain] = []
    for tmpl in templates:
        chain = _match_template(tmpl, findings)
        if chain:
            chains.append(chain)
    chains.sort(key=lambda c: c.score, reverse=True)
    return chains
