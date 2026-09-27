"""Ground-truth harness: every fixture asserts recall (the planted bug fires),
precision (the intended bug ranks #1), and chains (the right template matches).
Benign fixtures assert the tool stays quiet.

Drives wbx.pipeline.scan directly -- the exact path the CLI runs -- so the test
can never pass by exercising a flow that differs from what ships.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from wbx.pipeline import scan

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "challenges"


def _fixtures() -> list[Path]:
    return sorted(p for p in CORPUS.iterdir() if p.is_dir() and (p / "expected.yaml").exists())


def _load_expected(fixture: Path) -> dict:
    return yaml.safe_load((fixture / "expected.yaml").read_text())


@pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.name)
def test_fixture(fixture: Path):
    exp = _load_expected(fixture)
    source = fixture / "source"
    result = scan(source, deep=False)
    classes = {f.vuln_class for f in result.findings}

    # --- recall: each planted bug must appear at its file ---
    for want in exp.get("expect_findings", []):
        wc = want["vuln_class"]
        matches = [f for f in result.findings if f.vuln_class == wc]
        assert matches, f"{fixture.name}: expected a {wc} finding, got classes {classes}"
        if "file" in want:
            wf = want["file"]
            assert any(f.file.endswith(Path(wf).name) for f in matches), (
                f"{fixture.name}: {wc} not found in {wf}; found in {[m.file for m in matches]}"
            )

    # --- precision: intended bug ranks #1 ---
    top = exp.get("expect_top_class", "unset")
    if top is None:
        # benign: nothing should rank as a real finding
        assert not result.findings or all(f.severity != "ERROR" for f in result.findings), (
            f"{fixture.name}: benign fixture produced ERROR findings: "
            f"{[(f.vuln_class, f.location) for f in result.findings if f.severity=='ERROR']}"
        )
    elif top != "unset":
        assert result.findings, f"{fixture.name}: no findings at all"
        assert result.findings[0].vuln_class == top, (
            f"{fixture.name}: expected top class {top}, got "
            f"{[(f.vuln_class, f.score) for f in result.findings[:3]]}"
        )

    # --- chains ---
    want_chain = exp.get("expect_chain")
    if want_chain:
        chain_ids = {c.template_id for c in result.chains}
        assert want_chain in chain_ids, (
            f"{fixture.name}: expected chain {want_chain}, got {chain_ids}"
        )

    # --- negative control: forbidden classes must not appear ---
    for forbidden in exp.get("expect_no_classes", []):
        assert forbidden not in classes, (
            f"{fixture.name}: false positive {forbidden} in benign fixture"
        )

    # --- hints (logic/access-control leads, kept out of findings) ---
    hint_classes = {h.vuln_class for h in result.hints}
    for want in exp.get("expect_hints", []):
        assert want in hint_classes, (
            f"{fixture.name}: expected hint {want}, got hints {hint_classes}"
        )
        # a hint must NOT leak into the confident findings list
        assert want not in classes, (
            f"{fixture.name}: hint class {want} leaked into confident findings"
        )

    # --- rabbit-hole / reachability caution ---
    if exp.get("expect_caution"):
        assert result.cautions, f"{fixture.name}: expected a caution, got none"
