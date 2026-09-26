"""Render a ScanResult. Terminal output uses rich if present, plain text otherwise
(never let a missing library block a scan mid-comp).
"""
from __future__ import annotations

import json

from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def _signal_summary(signals: dict) -> str:
    parts = []
    for key, val in signals.items():
        if isinstance(val, dict):
            parts.append(f"{key}+{val.get('pts')}")
    return " ".join(parts)


def render_markdown(result: ScanResult) -> str:
    s = result.surface
    lines: list[str] = []
    lines.append(f"# wbx report: `{result.root}`\n")
    langs = ", ".join(f"{k}({v})" for k, v in sorted(s.languages.items(), key=lambda x: -x[1]))
    lines.append(f"- **Languages:** {langs or 'none detected'}")
    lines.append(f"- **Frameworks:** {', '.join(s.frameworks) or 'none detected'}")
    lines.append(f"- **Routes found:** {len(s.routes)}  |  **Entrypoints:** {len(s.entrypoints)}")
    lines.append(f"- **Flag tells:** {len(s.flag_hits)}  |  **Secret tells:** {len(s.secret_hits)}")
    lines.append("")

    if result.chains:
        lines.append("## Candidate chains (start here)\n")
        for i, c in enumerate(result.chains, 1):
            locs = " -> ".join(f.location for f in c.findings)
            lines.append(f"### {i}. {c.name}  _(score {c.score})_")
            lines.append(f"- **Impact:** {c.impact}")
            lines.append(f"- **Path:** {locs}")
            if c.playbook:
                lines.append(f"\n```\n{c.playbook}\n```")
            lines.append("")

    lines.append("## Findings (ranked)\n")
    if not result.findings:
        lines.append("_No findings._")
    for i, f in enumerate(result.findings, 1):
        lines.append(f"### {i}. [{f.score}] {f.vuln_class} — `{f.location}`")
        lines.append(f"- **Rule:** `{f.rule_id}` ({f.engine}, {f.lang}, {f.severity}/{f.confidence})")
        if f.message:
            lines.append(f"- **Why:** {f.message}")
        if f.source or f.sink:
            lines.append(f"- **Flow:** source `{f.source or '?'}` -> sink `{f.sink or '?'}`")
        if f.ctf_signals:
            lines.append(f"- **Signals:** {_signal_summary(f.ctf_signals)}")
        if f.exploitation_note:
            lines.append(f"- **Exploit:** {f.exploitation_note}")
        if f.scaffold:
            lines.append(f"- **Scaffold:** `{f.scaffold}`")
        if f.snippet:
            lines.append(f"\n```\n{f.snippet}\n```")
        lines.append("")
    return "\n".join(lines)


def render_terminal(result: ScanResult, top: int = 15) -> str:
    """Compact colorized terminal summary. Falls back to plain if rich absent."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
    except ImportError:
        return _render_plain(result, top)

    from io import StringIO
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)

    s = result.surface
    langs = ", ".join(f"{k}({v})" for k, v in sorted(s.languages.items(), key=lambda x: -x[1]))
    header = (
        f"[bold]{result.root}[/bold]\n"
        f"langs: {langs or '-'}   frameworks: {', '.join(s.frameworks) or '-'}\n"
        f"routes: {len(s.routes)}   flags: {len(s.flag_hits)}   secrets: {len(s.secret_hits)}"
    )
    console.print(Panel(header, title="wbx scan", border_style="cyan"))

    if result.chains:
        console.print("\n[bold red]>> Candidate chains (start here)[/bold red]")
        for i, c in enumerate(result.chains, 1):
            locs = " -> ".join(f.location for f in c.findings)
            console.print(f"  [bold]{i}. {c.name}[/bold]  [dim]score {c.score}[/dim]")
            console.print(f"     impact: {c.impact}")
            console.print(f"     path:   {locs}")

    table = Table(title="\nRanked findings", show_lines=False, header_style="bold magenta")
    table.add_column("#", justify="right")
    table.add_column("score", justify="right")
    table.add_column("class")
    table.add_column("location")
    table.add_column("eng")
    table.add_column("why", overflow="fold", max_width=48)
    for i, f in enumerate(result.findings[:top], 1):
        color = "red" if f.score >= 20 else ("yellow" if f.score >= 12 else "white")
        table.add_row(
            str(i), f"[{color}]{f.score}[/{color}]", f.vuln_class, f.location,
            f.engine, (f.message[:80] or f.rule_id),
        )
    console.print(table)
    if len(result.findings) > top:
        console.print(f"[dim]... {len(result.findings) - top} more (see markdown/json report)[/dim]")
    return buf.getvalue()


def _render_plain(result: ScanResult, top: int) -> str:
    lines = [f"wbx scan: {result.root}"]
    for i, f in enumerate(result.findings[:top], 1):
        lines.append(f"{i:>3}. [{f.score:>5}] {f.vuln_class:<24} {f.location:<40} {f.engine}")
    return "\n".join(lines)
