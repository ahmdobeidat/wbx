"""Unit tests for the deterministic brain: merge families, scoring signals, tells."""
from __future__ import annotations

from wbx.brain.score import enrich_and_rank, merge_findings
from wbx.brain.chain import detect_chains
from wbx.models import Finding, SurfaceMap


def _f(vuln_class, file="a.php", line=10, engine="semgrep", **kw):
    return Finding(rule_id=kw.get("rule_id", "r"), engine=engine, lang="php",
                   vuln_class=vuln_class, file=file, line=line,
                   message="m", severity=kw.get("severity", "ERROR"),
                   confidence=kw.get("confidence", "MEDIUM"),
                   source=kw.get("source"), dataflow=kw.get("dataflow", []))


def test_merge_collapses_family_and_keeps_specific_label():
    generic = _f("insecure_deserialization", line=9, engine="codeql", confidence="HIGH")
    specific = _f("python_pickle", file="a.php", line=9, engine="semgrep")
    merged = merge_findings([generic, specific])
    assert len(merged) == 1
    assert merged[0].vuln_class == "python_pickle"        # specific label wins
    assert "r" in merged[0].metadata.get("corroborated_by", [])


def test_merge_keeps_distinct_bugs_apart():
    a = _f("php_sqli", file="a.php", line=10)
    b = _f("php_lfi", file="a.php", line=50)
    assert len(merge_findings([a, b])) == 2


def test_scoring_rewards_taint_and_flag_proximity():
    near = _f("php_lfi", file="x.php", line=10, source="$_GET")
    far = _f("php_lfi", file="y.php", line=10)
    surface = SurfaceMap(flag_hits=[{"file": "x.php", "line": 12, "kind": "flag_literal"}])
    ranked = enrich_and_rank([far, near], surface)
    assert ranked[0] is near                              # taint + flag proximity ranks first
    assert "near_flag" in ranked[0].ctf_signals
    assert "tainted" in ranked[0].ctf_signals


def test_chain_requires_distinct_findings_per_step():
    # upload+lfi chain needs BOTH a file_upload and an lfi finding
    only_lfi = enrich_and_rank([_f("php_lfi")], SurfaceMap())
    chains = detect_chains(only_lfi)
    ids = {c.template_id for c in chains}
    assert "lfi_to_rce" in ids
    assert "upload_plus_lfi_rce" not in ids              # missing the upload step

    both = enrich_and_rank([_f("php_lfi", line=10), _f("file_upload", file="up.php", line=5)], SurfaceMap())
    ids2 = {c.template_id for c in detect_chains(both)}
    assert "upload_plus_lfi_rce" in ids2
