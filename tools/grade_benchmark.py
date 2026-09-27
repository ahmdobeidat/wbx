#!/usr/bin/env python3
"""Mechanical grader: run wbx against an external benchmark set and score it
against the authors' ANSWER.yaml keys. No eyeballing -- the verdict is arithmetic.

Usage:
    python tools/grade_benchmark.py ./wbx-benchmark [--deep]

For each challenge it reports:
  - recall:  did wbx surface the intended bug's class at the intended file?
  - rank:    position of that finding in the ranked list (TOP1 / TOP3 / LOW / MISS)
  - decoy:   did any decoy outrank the intended finding?
  - chain:   did a chain fire whose steps involve the intended bug family?
Then an aggregate scorecard.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# import wbx from the sibling repo
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wbx.pipeline import scan  # noqa: E402
from wbx.engines import SemgrepError  # noqa: E402

# generic author vocabulary -> wbx vuln_class set that legitimately represents it
VOCAB_MAP: dict[str, set[str]] = {
    "SSTI": {"ssti"},
    "SQLi": {"sql_injection", "php_sqli"},
    "NoSQLi": {"nosql_injection"},
    "command_injection": {"command_injection", "node_command_injection", "php_command_injection"},
    "code_injection": {"code_injection", "python_eval_exec", "php_eval"},
    "LFI": {"php_lfi", "path_traversal", "php_rfi"},
    "path_traversal": {"path_traversal", "php_lfi"},
    "RFI": {"php_rfi", "php_lfi"},
    "php_object_injection": {"php_object_injection", "insecure_deserialization"},
    "python_pickle": {"python_pickle", "insecure_deserialization"},
    "yaml_deserialization": {"python_yaml_load", "ruby_yaml_load", "insecure_deserialization"},
    "java_deserialization": {"java_deserialization", "insecure_deserialization"},
    "prototype_pollution": {"prototype_pollution"},
    "jwt_none": {"jwt_none_alg"},
    "type_juggling": {"php_type_juggling"},
    "mass_assignment": {"mass_assignment"},
    "idor": {"idor"},
    "access_control": {"access_control", "idor"},
    "SSRF": {"ssrf"},
    "XXE": {"xxe"},
    "open_redirect": {"open_redirect"},
    "XSS": {"xss"},
    "file_upload": {"file_upload"},
    "auth_bypass": {"auth_bypass", "php_type_juggling", "jwt_none_alg", "access_control"},
    "hardcoded_secret": {"hardcoded_secret"},
}

# which wbx families does an intended vuln belong to (for chain-relevance check)
FAMILY_OF = {
    "php_object_injection": "deserialization", "insecure_deserialization": "deserialization",
    "python_pickle": "deserialization", "python_yaml_load": "deserialization",
    "ruby_yaml_load": "deserialization", "java_deserialization": "deserialization",
    "php_lfi": "file_read", "php_rfi": "file_read", "path_traversal": "file_read",
    "sql_injection": "sqli", "php_sqli": "sqli",
}


def _classes_for(vocab: str) -> set[str]:
    if vocab not in VOCAB_MAP:
        print(f"  WARN: unknown vocab token '{vocab}' -- treating as literal", file=sys.stderr)
        return {vocab}
    return VOCAB_MAP[vocab]


def grade_one(chal_dir: Path, deep: bool) -> dict:
    ans = yaml.safe_load((chal_dir / "ANSWER.yaml").read_text())
    intended = ans["intended"]
    want_classes = _classes_for(intended["vuln"])
    want_file = Path(intended["file"]).name

    try:
        result = scan(chal_dir / "source", deep=deep)
    except SemgrepError as e:
        # a failed scan is NOT a miss -- surface it distinctly so a transient
        # never gets silently scored as "intended bug not found".
        return {
            "name": ans["name"], "language": ans.get("language", "?"),
            "difficulty": ans.get("difficulty", "?"), "intended": intended["vuln"],
            "requires_deep": intended.get("requires_deep", False),
            "verdict": "SCAN_ERROR", "rank": None, "total_findings": 0,
            "decoy_above": False, "chain_relevant": False, "top3": [], "error": str(e),
        }
    findings = result.findings

    # find the rank of the first finding that matches intended class + file
    hit_rank = None
    for i, f in enumerate(findings, 1):
        if f.vuln_class in want_classes and Path(f.file).name == want_file:
            hit_rank = i
            break
    # relaxed hit: class anywhere (right bug, maybe wrong file attribution)
    hit_class_only = any(f.vuln_class in want_classes for f in findings)

    # decoy outranking: any decoy class that appears ABOVE the intended hit
    decoy_classes: set[str] = set()
    for d in ans.get("decoys", []) or []:
        decoy_classes |= _classes_for(d["vuln"])
    decoy_above = False
    if hit_rank:
        for f in findings[: hit_rank - 1]:
            if f.vuln_class in decoy_classes:
                decoy_above = True
                break

    # chain relevance: a fired chain that includes a finding of the intended family
    want_family = {FAMILY_OF.get(c, c) for c in want_classes}
    chain_relevant = False
    for c in result.chains:
        for f in c.findings:
            if FAMILY_OF.get(f.vuln_class, f.vuln_class) in want_family or f.vuln_class in want_classes:
                chain_relevant = True
                break

    # logic/access-control bugs are surfaced as HINTS, not confident findings.
    hint_hit = any(h.vuln_class in want_classes for h in result.hints)

    if hit_rank == 1:
        verdict = "TOP1"
    elif hit_rank and hit_rank <= 3:
        verdict = "TOP3"
    elif hit_rank:
        verdict = "LOW"
    elif hit_class_only:
        verdict = "WRONG_FILE"
    elif hint_hit:
        verdict = "HINT"   # correctly caught, in the manual-review channel
    else:
        verdict = "MISS"

    # for decoy-inversion challenges: did the rabbit-hole caution fire?
    has_unreachable_decoy = any(
        d.get("reachable_from_route") is False for d in (ans.get("decoys", []) or [])
    )

    return {
        "name": ans["name"],
        "language": ans.get("language", "?"),
        "difficulty": ans.get("difficulty", "?"),
        "intended": intended["vuln"],
        "requires_deep": intended.get("requires_deep", False),
        "verdict": verdict,
        "rank": hit_rank,
        "total_findings": len(findings),
        "decoy_above": decoy_above,
        "chain_relevant": chain_relevant,
        "caution_fired": bool(result.cautions),
        "expects_caution": has_unreachable_decoy,
        "top3": [(f.vuln_class, f.file + ":" + str(f.line), f.score) for f in findings[:3]],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("benchmark_dir")
    ap.add_argument("--deep", action="store_true")
    args = ap.parse_args()

    chal_root = Path(args.benchmark_dir) / "challenges"
    if not chal_root.is_dir():
        print(f"no challenges/ under {args.benchmark_dir}", file=sys.stderr)
        return 2

    chals = sorted(p for p in chal_root.iterdir() if p.is_dir() and (p / "ANSWER.yaml").exists())
    if not chals:
        print("no challenges with ANSWER.yaml found", file=sys.stderr)
        return 2

    rows = [grade_one(c, args.deep) for c in chals]

    mode = "DEEP (semgrep+codeql)" if args.deep else "FAST (semgrep only)"
    print(f"\n=== wbx benchmark scorecard [{mode}] ===\n")
    hdr = f"{'challenge':<24} {'lang':<6} {'diff':<7} {'intended':<18} {'verdict':<11} {'rank':<5} {'caution':<8} {'chain':<6}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        rank = str(r["rank"]) if r["rank"] else "-"
        # caution column: OK if fired-when-expected or not-fired-when-not-expected
        if r.get("expects_caution"):
            caution = "FIRED" if r.get("caution_fired") else "MISSING!"
        else:
            caution = "-"
        print(f"{r['name']:<24} {r['language']:<6} {r['difficulty']:<7} {r['intended']:<18} "
              f"{r['verdict']:<11} {rank:<5} {caution:<8} "
              f"{'yes' if r['chain_relevant'] else '-':<6}")

    n = len(rows)
    found = sum(1 for r in rows if r["verdict"] in {"TOP1", "TOP3", "LOW", "WRONG_FILE", "HINT"})
    top1 = sum(1 for r in rows if r["verdict"] == "TOP1")
    top3 = sum(1 for r in rows if r["verdict"] in {"TOP1", "TOP3"})
    misses = [r for r in rows if r["verdict"] == "MISS"]
    wrongfile = [r for r in rows if r["verdict"] == "WRONG_FILE"]
    scan_errors = [r for r in rows if r["verdict"] == "SCAN_ERROR"]
    decoy_probs = [r for r in rows if r["decoy_above"]]

    hints = sum(1 for r in rows if r["verdict"] == "HINT")
    inversions = [r for r in rows if r.get("expects_caution")]
    # inversion handled = the real (reachable) bug surfaced in top-3, OR a rabbit-hole
    # caution pointed away from the decoy. Either way the operator is not misled.
    inv_ok = sum(1 for r in inversions
                 if r["verdict"] in {"TOP1", "TOP3"} or r.get("caution_fired"))

    print(f"\nrecall (found intended bug):     {found}/{n}   (of which {hints} via hints channel)")
    print(f"precision (intended ranked #1):  {top1}/{n}")
    print(f"precision (intended in top 3):   {top3}/{n}")
    print(f"chain relevant fired:            {sum(1 for r in rows if r['chain_relevant'])}/{n}")
    if inversions:
        print(f"decoy-inversion handled:         {inv_ok}/{len(inversions)} "
              f"(intended surfaced or rabbit-hole caution)")

    if scan_errors:
        print("\nSCAN ERRORS (scan failed, NOT a miss -- investigate):")
        for r in scan_errors:
            print(f"  - {r['name']}: {r.get('error', '')[:160]}")
    if misses:
        print("\nMISSES (intended bug not found at all):")
        for r in misses:
            print(f"  - {r['name']} ({r['language']}, {r['difficulty']}, {r['intended']}, "
                  f"requires_deep={r['requires_deep']})")
    if wrongfile:
        print("\nWRONG_FILE (right class, wrong location):")
        for r in wrongfile:
            print(f"  - {r['name']} ({r['intended']})")
    if decoy_probs:
        print("\nDECOY OUTRANKED INTENDED (precision hazard):")
        for r in decoy_probs:
            print(f"  - {r['name']}: top3={r['top3']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
