"""Turn a finding into a runnable PoC skeleton the operator finishes by hand.

Scaffolds talk to the *live challenge instance* you are authorized to solve; the
scanner itself never touches a network. Each template has clear TODO markers for
the challenge-specific bits the tool can't know (exact param, gadget class).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Finding

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# vuln_class -> template filename
TEMPLATE_FOR_CLASS = {
    "ssti": "ssti.py.tmpl",
    "php_object_injection": "php_deserialize.py.tmpl",
    # NB: no generic "insecure_deserialization" mapping -- language is unknown, so
    # emitting a PHP or Python PoC would be wrong. Merge prefers the specific class.
    "python_pickle": "python_pickle.py.tmpl",
    "jwt_none_alg": "jwt_none.py.tmpl",
    "prototype_pollution": "prototype_pollution.py.tmpl",
    "php_lfi": "lfi.py.tmpl",
    "path_traversal": "lfi.py.tmpl",
    "command_injection": "command_injection.py.tmpl",
    "node_command_injection": "command_injection.py.tmpl",
    "php_command_injection": "command_injection.py.tmpl",
    "sql_injection": "sqli.py.tmpl",
    "php_sqli": "sqli.py.tmpl",
    "php_type_juggling": "type_juggling.py.tmpl",
}


def _render(template: str, ctx: dict[str, Any]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("{{" + k + "}}", str(v))
    return out


def generate_scaffolds(findings: list[Finding], out_dir: str | Path, limit: int = 8) -> dict[str, str]:
    """Emit PoC skeletons for the top findings that have a template.

    Returns {finding.location: scaffold_path}. Mutates finding.scaffold.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    produced: dict[str, str] = {}
    made = 0
    for f in findings:
        if made >= limit:
            break
        tmpl_name = TEMPLATE_FOR_CLASS.get(f.vuln_class)
        if not tmpl_name:
            continue
        tmpl_path = _TEMPLATE_DIR / tmpl_name
        if not tmpl_path.is_file():
            continue
        ctx = {
            "VULN_CLASS": f.vuln_class,
            "LOCATION": f.location,
            "FILE": f.file,
            "LINE": f.line,
            "RULE": f.rule_id,
            "SINK": f.sink or "(see source)",
            "SOURCE": f.source or "(user input)",
            "NOTE": f.exploitation_note or "See finding message.",
        }
        rendered = _render(tmpl_path.read_text(), ctx)
        safe_loc = f.location.replace("/", "_").replace(":", "_")
        dest = out / f"poc_{f.vuln_class}_{safe_loc}.py"
        dest.write_text(rendered)
        rel = str(dest)
        f.scaffold = rel
        produced[f.location] = rel
        made += 1
    return produced
