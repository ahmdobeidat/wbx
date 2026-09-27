"""wbx command line. Deterministic, offline. One command mid-comp: `wbx scan ./chal`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import json as _json

from .engines import (
    SemgrepError,
    codeql_available,
    nuclei_available,
    run_nuclei,
    semgrep_available,
    tags_for_frameworks,
)
from .pipeline import scan
from .report import render_json, render_markdown, render_terminal


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    if not semgrep_available():
        print("warning: semgrep not on PATH; Semgrep findings will be empty.", file=sys.stderr)
    if args.deep and not codeql_available():
        print("warning: --deep requested but codeql not on PATH; skipping deep pass.", file=sys.stderr)

    out_dir = Path(args.out) if args.out else root.parent / f"{root.name}-wbx"
    scaffold_dir = None if args.no_scaffolds else out_dir / "scaffolds"

    try:
        result = scan(root, deep=args.deep, scaffold_dir=scaffold_dir)
    except SemgrepError as e:
        print(f"error: scan failed (not a clean result): {e}", file=sys.stderr)
        print("The scan did NOT complete. Do not treat the absence of findings as safe.",
              file=sys.stderr)
        return 3

    # always write full md + json artifacts
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.md").write_text(render_markdown(result))
    (out_dir / "report.json").write_text(render_json(result))

    if args.format == "json":
        print(render_json(result))
    elif args.format == "md":
        print(render_markdown(result))
    else:
        print(render_terminal(result, top=args.top))
        print(f"\nfull report: {out_dir/'report.md'}  |  json: {out_dir/'report.json'}")
        if scaffold_dir and any(scaffold_dir.glob("*.py")):
            print(f"scaffolds:   {scaffold_dir}/")

    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Live-target confirmation with nuclei. Runs against the AUTHORIZED challenge
    instance only -- this is DAST, separate from the offline `scan`."""
    if not nuclei_available():
        print("error: nuclei not on PATH. Install it and pre-fetch templates.", file=sys.stderr)
        return 2

    tags = list(args.tags) if args.tags else []
    if args.report:
        try:
            data = _json.loads(Path(args.report).read_text())
            fw = data.get("surface", {}).get("frameworks", [])
            derived = tags_for_frameworks(fw)
            if derived:
                print(f"derived nuclei tags from scan frameworks {fw}: {derived}", file=sys.stderr)
                tags += [t for t in derived if t not in tags]
        except (OSError, ValueError) as e:
            print(f"warning: could not read report {args.report}: {e}", file=sys.stderr)

    severity = list(args.severity) if args.severity else None
    print(f"running nuclei against {args.url} "
          f"(tags={tags or 'all'}, severity={severity or 'all'})...", file=sys.stderr)
    hits = run_nuclei(args.url, templates=args.templates, tags=tags or None,
                      severity=severity, timeout=args.timeout)

    if args.format == "json":
        print(_json.dumps(hits, indent=2))
        return 0

    if not hits:
        print("no nuclei matches (templates fetched? target reachable? try --severity).")
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    hits.sort(key=lambda h: order.get(h.get("severity", "unknown"), 5))
    for h in hits:
        print(f"[{h['severity']:>8}] {h['template_id']:<40} {h['matched_at']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wbx", description="White-box web CTF static analysis.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a source tree")
    s.add_argument("path", help="path to the challenge source directory")
    s.add_argument("--deep", action="store_true", help="also run CodeQL (slow, py/js/rb/java only)")
    s.add_argument("--out", help="output dir (default: <path>-wbx next to source)")
    s.add_argument("--format", choices=["terminal", "md", "json"], default="terminal")
    s.add_argument("--top", type=int, default=15, help="findings shown in terminal table")
    s.add_argument("--no-scaffolds", action="store_true", help="do not generate PoC scaffolds")
    s.set_defaults(func=_cmd_scan)

    v = sub.add_parser("verify", help="live-target confirmation with nuclei (authorized instance only)")
    v.add_argument("url", help="URL of the authorized challenge instance to scan")
    v.add_argument("--report", help="a prior wbx scan report.json; derives nuclei tags from detected frameworks")
    v.add_argument("--tags", nargs="*", help="nuclei tags to focus templates (e.g. laravel cve)")
    v.add_argument("--severity", nargs="*", help="filter by severity (critical high medium low info)")
    v.add_argument("--templates", help="path to a nuclei templates dir/file")
    v.add_argument("--format", choices=["terminal", "json"], default="terminal")
    v.add_argument("--timeout", type=int, default=600)
    v.set_defaults(func=_cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
