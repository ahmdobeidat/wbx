#!/usr/bin/env python3
"""Scan a tree of applications/challenges and tabulate wbx's top findings.

Usage:
    python tools/scan_tree.py <dir> [--deep]

Treats each immediate child (or grandchild, when children are grouping folders)
that contains source as one target. Prints a table of languages + top findings.
Used to evaluate wbx against a corpus of real-world targets.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wbx.pipeline import scan  # noqa: E402
from wbx.engines import SemgrepError  # noqa: E402

SRC_EXT = {".php", ".py", ".js", ".ts", ".rb", ".java", ".jsx", ".mjs"}


def has_source(d: Path) -> bool:
    for p in d.rglob("*"):
        if p.suffix.lower() in SRC_EXT and not {"node_modules", "vendor"} & set(p.parts):
            return True
    return False


def targets(root: Path) -> list[Path]:
    out: list[Path] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        subs = [c for c in sorted(child.iterdir()) if c.is_dir()]
        if subs:  # grouping folder (e.g. year/challenge): descend to the challenges
            out += [c for c in subs if has_source(c)]
        elif has_source(child):
            out.append(child)
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: scan_tree.py <dir> [--deep]", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    deep = "--deep" in sys.argv
    tgts = targets(root)

    print(f"{'target':<48} {'langs':<14} top findings")
    print("-" * 120)
    found = 0
    for t in tgts:
        try:
            r = scan(t, deep=deep)
        except SemgrepError as e:
            print(f"{str(t.relative_to(root))[:46]:<48} SCAN_ERROR: {e}")
            continue
        langs = ",".join(f"{k}:{v}" for k, v in sorted(r.surface.languages.items(), key=lambda x: -x[1]))[:13]
        top = " | ".join(f"{f.vuln_class}@{Path(f.file).name}:{f.line}({f.score})" for f in r.findings[:3])
        hints = f"  hints={len(r.hints)}" if r.hints else ""
        print(f"{str(t.relative_to(root))[:46]:<48} {langs:<14} {top[:58]}{hints}")
        if r.findings:
            found += 1
    print("-" * 120)
    print(f"scanned {len(tgts)} targets; {found} produced findings  (mode: {'deep' if deep else 'fast'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
