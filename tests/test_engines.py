"""Reliability tests for the engine runners: a failed scan must never be silently
turned into an empty (clean-looking) result."""
from __future__ import annotations

from pathlib import Path

import pytest

from wbx.engines import SemgrepError, run_semgrep, semgrep_available

pytestmark = pytest.mark.skipif(not semgrep_available(), reason="semgrep not on PATH")


def test_failed_scan_raises_not_empty(tmp_path: Path):
    # a rules dir whose only rule is invalid YAML makes semgrep exit with an error;
    # the runner must raise SemgrepError, not return [] (which would read as clean).
    bad_rules = tmp_path / "rules"
    bad_rules.mkdir()
    (bad_rules / "broken.yaml").write_text("rules:\n  - id: nope\n    languages: [python]\n")  # missing pattern/message
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")

    with pytest.raises(SemgrepError):
        run_semgrep(target, rules_dir=bad_rules, retries=1)


def test_clean_scan_returns_empty_list(tmp_path: Path):
    # a valid scan of clean code returns [] normally (not an error)
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.py").write_text("def add(a, b):\n    return a + b\n")
    findings = run_semgrep(target)  # real wbx rules, clean file
    assert findings == []
