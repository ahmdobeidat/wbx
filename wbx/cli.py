"""wbx command line. Deterministic, offline. One command mid-comp: `wbx scan ./chal`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engines import codeql_available, semgrep_available
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

    result = scan(root, deep=args.deep, scaffold_dir=scaffold_dir)

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
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
