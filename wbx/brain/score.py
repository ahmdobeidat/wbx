"""Deterministic, explainable ranking.

The competition bans AI, so the ranker is pure arithmetic over observable
signals. Every point added is recorded in Finding.ctf_signals with a human
reason, so the report can show *why* something ranked where it did. No black box.
"""
from __future__ import annotations

from ..models import Finding, SurfaceMap

# How dangerous is each class as a route to the flag (RCE-class ranks highest).
_CLASS_DANGER = {
    # direct/likely RCE
    "php_object_injection": 10,
    "insecure_deserialization": 10,
    "java_deserialization": 10,
    "python_pickle": 10,
    "ruby_yaml_load": 10,
    "python_yaml_load": 10,
    "command_injection": 10,
    "node_command_injection": 10,
    "php_command_injection": 10,
    "python_eval_exec": 10,
    "php_eval": 10,
    "php_preg_replace_eval": 10,
    "ssti": 9,
    "prototype_pollution": 8,
    # file/data disclosure -> often flag
    "php_lfi": 8,
    "php_rfi": 9,
    "path_traversal": 7,
    "sql_injection": 7,
    "php_sqli": 7,
    "nosql_injection": 6,
    "xxe": 6,
    "ssrf": 6,
    # auth / logic
    "jwt_none_alg": 7,
    "auth_bypass": 7,
    "php_type_juggling": 6,
    "mass_assignment": 5,
    "file_upload": 6,
    "open_redirect": 3,
    "xss": 3,
    "hardcoded_secret": 4,
    "uncategorized": 2,
}

# Impact tier per vuln_class. The tier BASE dominates the score so a higher-impact
# bug reliably outranks a lower-impact one regardless of how much evidence the
# engines gathered for the weaker bug. Evidence bonuses only order findings WITHIN
# a tier. This is the robust CTF-triage principle: an RCE primitive is the intended
# path far more often than a disclosure/decoy sitting next to it.
#   T1 = direct code/command execution    T2 = injection / auth-logic to flag
#   T3 = file/data disclosure & SSRF      T4 = lower-impact / weak-signal
_TIER = {
    # --- Tier 1: direct RCE ---
    "php_object_injection": 1, "insecure_deserialization": 1, "java_deserialization": 1,
    "python_pickle": 1, "ruby_yaml_load": 1, "python_yaml_load": 1,
    "command_injection": 1, "node_command_injection": 1, "php_command_injection": 1,
    "python_eval_exec": 1, "php_eval": 1, "php_preg_replace_eval": 1, "ssti": 1,
    # --- Tier 2: injection / auth-logic that reaches the flag directly ---
    # php_lfi is here (not Tier 3): PHP LFI reads the flag directly and commonly
    # escalates to RCE via wrappers/log poisoning, unlike generic path traversal.
    "sql_injection": 2, "php_sqli": 2, "nosql_injection": 2, "prototype_pollution": 2,
    "php_rfi": 2, "jwt_none_alg": 2, "auth_bypass": 2, "php_type_juggling": 2,
    "php_lfi": 2,
    # --- Tier 3: disclosure / traversal / SSRF / needs-a-chain ---
    "path_traversal": 3, "ssrf": 3, "xxe": 3, "file_upload": 3,
    # --- Tier 4: lower impact ---
    "mass_assignment": 4, "open_redirect": 4, "xss": 4, "hardcoded_secret": 4,
    "uncategorized": 4,
}
# Tier bases spaced so the top tier is never displaced by evidence (max evidence
# ~24 < the 35-point Tier1->Tier2 gap). Lower gaps are narrower on purpose: a
# strongly-evidenced disclosure bug may edge a weak lower-tier one, which is fine.
_TIER_BASE = {1: 100, 2: 65, 3: 40, 4: 18}

_SEVERITY_PTS = {"ERROR": 3, "WARNING": 2, "INFO": 0}
_CONFIDENCE_PTS = {"HIGH": 3, "MEDIUM": 1, "LOW": 0}

# proximity window (lines) for "sits near a flag/secret"
_PROX_WINDOW = 8


def _proximity_hit(finding: Finding, hits: list[dict], window: int = _PROX_WINDOW) -> dict | None:
    for h in hits:
        if h.get("file") == finding.file and abs(int(h.get("line", -999)) - finding.line) <= window:
            return h
    return None


def _sort(findings: list[Finding]) -> None:
    """Deterministic ordering: score desc, then a stable (file, line, rule) key so
    a scan of the same tree always prints findings in the same order."""
    findings.sort(key=lambda x: (-x.score, x.file, x.line, x.rule_id))


def enrich_and_rank(findings: list[Finding], surface: SurfaceMap) -> list[Finding]:
    """Attach ctf_signals + score to each finding and return sorted desc by score."""
    route_files = {r["file"] for r in surface.routes}
    entry_files = set(surface.entrypoints)

    for f in findings:
        signals: dict = {}

        tier = _TIER.get(f.vuln_class, 4)
        base = _TIER_BASE[tier]
        signals["impact_tier"] = {"pts": base, "why": f"tier {tier} ({f.vuln_class})"}
        score = float(base)

        sev = _SEVERITY_PTS.get(f.severity, 1)
        if sev:
            signals["severity"] = {"pts": sev, "why": f"severity={f.severity}"}
            score += sev

        conf = _CONFIDENCE_PTS.get(f.confidence, 1)
        if conf:
            signals["confidence"] = {"pts": conf, "why": f"confidence={f.confidence}"}
            score += conf

        # reaches user input (a taint source was resolved)
        if f.source or f.dataflow:
            signals["tainted"] = {"pts": 4, "why": "resolved taint source -> reaches user input"}
            score += 4

        # a deep engine (codeql / psalm) proved a source->sink dataflow path
        if f.engine in ("codeql", "psalm"):
            signals["dataflow_path"] = {"pts": 3, "why": f"{f.engine} proved a dataflow path"}
            score += 3

        # both engines flagged this bug -> strong corroboration
        if f.metadata.get("corroborated_by"):
            signals["corroborated"] = {"pts": 5, "why": "semgrep + codeql agree"}
            score += 5

        # sits on a route / entrypoint file
        if f.file in route_files:
            signals["on_route"] = {"pts": 3, "why": "in a file that declares a route"}
            score += 3
        elif f.file in entry_files:
            signals["entrypoint"] = {"pts": 2, "why": "in an app entrypoint file"}
            score += 2

        # proximity to a flag literal or flag-file reference
        fh = _proximity_hit(f, surface.flag_hits)
        if fh:
            pts = 4 if fh.get("kind") == "flag_literal" else 2
            signals["near_flag"] = {"pts": pts, "why": f"{fh.get('kind')} within {_PROX_WINDOW} lines"}
            score += pts

        # proximity to a secret
        sh = _proximity_hit(f, surface.secret_hits)
        if sh:
            signals["near_secret"] = {"pts": 2, "why": f"{sh.get('kind')} within {_PROX_WINDOW} lines"}
            score += 2

        f.ctf_signals = signals
        f.score = round(score, 2)

    _sort(findings)
    return findings


def apply_chain_bonus(findings: list[Finding], chains) -> list[Finding]:
    """Reward findings that participate in a detected escalation chain: a bug on a
    known path to the flag is more likely the intended one than a standalone decoy.
    Runs after chain detection, then re-sorts. Bonus stays within-tier by design."""
    in_chain = {f.location for c in chains for f in c.findings}
    for f in findings:
        if f.location in in_chain and "in_chain" not in f.ctf_signals:
            f.ctf_signals["in_chain"] = {"pts": 6, "why": "part of a flag-reaching chain"}
            f.score = round(f.score + 6, 2)
    _sort(findings)
    return findings


# Classes that describe the same underlying bug across engines/languages. When
# two findings fall in the same family at the same location they are one bug.
_FAMILIES = {
    "deserialization": {
        "php_object_injection", "insecure_deserialization", "python_pickle",
        "python_yaml_load", "ruby_yaml_load", "java_deserialization",
    },
    "code_exec": {"python_eval_exec", "php_eval"},
    "cmd_exec": {"command_injection", "node_command_injection", "php_command_injection"},
    "sqli": {"sql_injection", "php_sqli"},
    "file_read": {"php_lfi", "php_rfi", "path_traversal"},
}


def _family(vuln_class: str) -> str:
    for fam, members in _FAMILIES.items():
        if vuln_class in members:
            return fam
    return vuln_class  # its own family


# Generic umbrella labels; when merging, prefer the language-specific sibling so
# the scaffold generator picks the right PoC template.
_GENERIC = {
    "insecure_deserialization", "command_injection", "sql_injection",
    "path_traversal", "python_eval_exec",
}


def _more_specific(a: str, b: str) -> str:
    """Prefer the language-specific label, then higher danger, when merging."""
    a_generic, b_generic = a in _GENERIC, b in _GENERIC
    if a_generic != b_generic:
        return b if a_generic else a
    return a if _CLASS_DANGER.get(a, 0) >= _CLASS_DANGER.get(b, 0) else b


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate reports of the same bug across engines/rules.

    Two findings merge when they are in the same vuln-class *family*, same file,
    and within 3 lines. The merged record keeps the more specific class label and
    absorbs a CodeQL dataflow path as corroboration -- semgrep + codeql agreeing
    is itself strong signal, surfaced via metadata.corroborated_by.
    """
    merged: list[Finding] = []
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.vuln_class)):
        placed = False
        for m in merged:
            if (m.file == f.file and _family(m.vuln_class) == _family(f.vuln_class)
                    and abs(m.line - f.line) <= 3):
                m.vuln_class = _more_specific(m.vuln_class, f.vuln_class)
                deep = ("codeql", "psalm")
                if (f.engine in deep and m.engine not in deep) or (f.dataflow and not m.dataflow):
                    m.engine = f.engine if f.engine in deep else m.engine
                    m.confidence = f.confidence if f.confidence == "HIGH" else m.confidence
                    m.dataflow = f.dataflow or m.dataflow
                    m.source = f.source or m.source
                    m.sink = f.sink or m.sink
                corroborators = set(m.metadata.get("corroborated_by", []))
                corroborators.add(f.rule_id)
                m.metadata["corroborated_by"] = sorted(corroborators)
                placed = True
                break
        if not placed:
            merged.append(f)
    return merged
