"""The data spine. Every stage of the pipeline speaks these types.

Kept dependency-free (stdlib dataclasses) so the schema never breaks because
of a library bump mid-competition.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# Canonical vulnerability classes. Rules tag findings with one of these so the
# scorer, chain engine, and scaffold generator can reason about them without
# parsing free text. Add here first, then reference from rules.
VULN_CLASSES = {
    # PHP-leaning
    "php_object_injection",
    "php_type_juggling",
    "php_lfi",
    "php_rfi",
    "php_preg_replace_eval",
    "php_command_injection",
    "php_eval",
    "php_sqli",
    # Python-leaning
    "ssti",
    "python_pickle",
    "python_eval_exec",
    "python_yaml_load",
    "path_traversal",
    "ssrf",
    "command_injection",
    "sql_injection",
    # Node-leaning
    "prototype_pollution",
    "nosql_injection",
    "jwt_none_alg",
    "node_command_injection",
    # Ruby-leaning
    "ruby_yaml_load",
    "mass_assignment",
    # Java-leaning
    "java_deserialization",
    # Cross-cutting
    "xxe",
    "insecure_deserialization",
    "hardcoded_secret",
    "xss",
    "open_redirect",
    "auth_bypass",
    "file_upload",
}


@dataclass
class DataflowStep:
    file: str
    line: int
    content: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """One potential vulnerability located in source."""

    rule_id: str
    engine: str                 # "semgrep" | "codeql"
    lang: str
    vuln_class: str
    file: str                   # relative to challenge root
    line: int
    message: str
    snippet: str = ""
    severity: str = "WARNING"   # ERROR | WARNING | INFO (semgrep-style)
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    source: Optional[str] = None
    sink: Optional[str] = None
    dataflow: list[DataflowStep] = field(default_factory=list)
    ctf_signals: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    exploitation_note: str = ""
    scaffold: Optional[str] = None   # relative path to generated PoC, if any
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Chain:
    """A ranked sequence of findings that composes into higher impact."""

    template_id: str
    name: str
    impact: str
    findings: list[Finding]
    playbook: str = ""
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "impact": self.impact,
            "playbook": self.playbook,
            "score": self.score,
            "findings": [f.location for f in self.findings],
        }


@dataclass
class SurfaceMap:
    """What the app exposes: entrypoints, routes, and the CTF tells."""

    languages: dict[str, int] = field(default_factory=dict)   # lang -> file count
    frameworks: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)      # files that look like entry
    routes: list[dict[str, Any]] = field(default_factory=list)  # {method, path, handler, file, line}
    flag_hits: list[dict[str, Any]] = field(default_factory=list)  # {file, line, kind, value}
    secret_hits: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    surface: SurfaceMap
    findings: list[Finding] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "surface": self.surface.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "chains": [c.to_dict() for c in self.chains],
        }
