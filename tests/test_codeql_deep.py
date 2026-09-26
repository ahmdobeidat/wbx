"""CodeQL deep-pass integration test. Opt-in (slow: builds a CodeQL DB).

Run with:  WBX_TEST_DEEP=1 pytest tests/test_codeql_deep.py
Skipped by default so the normal suite stays fast.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from wbx.engines.codeql_runner import codeql_available, run_codeql

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "challenges"

pytestmark = [
    pytest.mark.skipif(not os.environ.get("WBX_TEST_DEEP"), reason="set WBX_TEST_DEEP=1 to run"),
    pytest.mark.skipif(not codeql_available(), reason="codeql not on PATH"),
]


def test_codeql_finds_python_deserialization():
    findings = run_codeql(CORPUS / "python-pickle-01" / "source", ["python"], timeout=600)
    classes = {f.vuln_class for f in findings}
    assert "insecure_deserialization" in classes or "python_pickle" in classes, (
        f"codeql deep pass found none of the expected deserialization classes: {classes}"
    )
    # every codeql finding should be high-confidence with a resolved sink line
    for f in findings:
        assert f.engine == "codeql"
        assert f.line > 0
