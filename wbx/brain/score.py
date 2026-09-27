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

_SEVERITY_PTS = {"ERROR": 3, "WARNING": 2, "INFO": 1}
_CONFIDENCE_PTS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# proximity window (lines) for "sits near a flag/secret"
_PROX_WINDOW = 8


def _proximity_hit(finding: Finding, hits: list[dict], window: int = _PROX_WINDOW) -> dict | None:
    for h in hits:
        if h.get("file") == finding.file and abs(int(h.get("line", -999)) - finding.line) <= window:
            return h
    return None


def enrich_and_rank(findings: list[Finding], surface: SurfaceMap) -> list[Finding]:
    """Attach ctf_signals + score to each finding and return sorted desc by score."""
    route_files = {r["file"] for r in surface.routes}
    entry_files = set(surface.entrypoints)

    for f in findings:
        signals: dict = {}
        score = 0.0

        # class danger is the DOMINANT signal: in CTF the intended-bug class matters
        # more than where it sits. Weighted x2 so contextual bonuses (route/entry)
        # act as tiebreakers, not as things that lift a low-danger bug over an RCE.
        danger = _CLASS_DANGER.get(f.vuln_class, 2)
        signals["class_danger"] = {"pts": danger * 2, "why": f"{f.vuln_class} danger weight (x2)"}
        score += danger * 2

        sev = _SEVERITY_PTS.get(f.severity, 1)
        signals["severity"] = {"pts": sev, "why": f"severity={f.severity}"}
        score += sev

        conf = _CONFIDENCE_PTS.get(f.confidence, 1)
        signals["confidence"] = {"pts": conf, "why": f"confidence={f.confidence}"}
        score += conf

        # reaches user input (a taint source was resolved)
        if f.source or f.dataflow:
            signals["tainted"] = {"pts": 4, "why": "resolved taint source -> reaches user input"}
            score += 4

        # engine agreement / codeql taint path is strong evidence
        if f.engine == "codeql":
            signals["codeql_path"] = {"pts": 3, "why": "codeql proved a dataflow path"}
            score += 3

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
            pts = 6 if fh.get("kind") == "flag_literal" else 4
            signals["near_flag"] = {"pts": pts, "why": f"{fh.get('kind')} within {_PROX_WINDOW} lines"}
            score += pts

        # proximity to a secret
        sh = _proximity_hit(f, surface.secret_hits)
        if sh:
            signals["near_secret"] = {"pts": 3, "why": f"{sh.get('kind')} within {_PROX_WINDOW} lines"}
            score += 3

        f.ctf_signals = signals
        f.score = round(score, 2)

    findings.sort(key=lambda x: (x.score, x.severity == "ERROR"), reverse=True)
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
                if (f.engine == "codeql" and m.engine != "codeql") or (f.dataflow and not m.dataflow):
                    m.engine = f.engine if f.engine == "codeql" else m.engine
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
