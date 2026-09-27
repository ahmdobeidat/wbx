# wbx

White-box web CTF static-analysis. Point it at challenge source, get a ranked
list of the likely-intended bug, the chain to the flag, and a PoC scaffold to
finish by hand.

**Deterministic and offline at runtime.** No LLM, no network call during a scan.
Built with AI, but what you run in the arena is plain static analysis, which is
what a "no AI" competition allows.

## What it does

```
source tree -> Ingest -> Scan (Semgrep + CodeQL) -> Score -> Chain -> Report + Scaffolds
```

- **Ingest** fingerprints languages/frameworks, maps routes/entrypoints, and finds
  the CTF tells (flag strings, `/flag` references, hardcoded secrets).
- **Scan** runs Semgrep CTF rulepacks (fast, all 5 languages) and, with `--deep`,
  inter-procedural taint: **CodeQL** for Python/JS/Ruby/Java and **Psalm
  `--taint-analysis`** for PHP (CodeQL cannot analyze PHP, so Psalm fills the
  cross-file PHP gap).
- **Score** ranks findings by an impact-tier model (RCE > injection/auth >
  disclosure > low) with evidence and reachability ordering within a tier. Top of
  the list = start here, and a **rabbit-hole caution** fires when the top finding
  sits in code no route reaches (decoy robustness).
- **Chain** matches findings against a library of known CTF escalations
  (`LFI+upload=RCE`, `SQLi->secret->auth`, `deserialization=RCE`, ...).
- **Hints** surface logic / access-control leads (IDOR, missing-auth) in a
  SEPARATE "manual-review" section, never mixed with confident findings, because
  static analysis cannot decide authorization.
- **Report** prints a terminal summary and writes `report.md` + `report.json`,
  plus runnable PoC scaffolds under `scaffolds/`.
- **Verify** (`wbx verify <url>`) is a separate, live step: nuclei against the
  authorized challenge instance to confirm known-CVE / exposure, seeded by the
  frameworks the static scan detected. `scan` itself never touches the network.

## Usage

```bash
wbx scan ./challenge                 # fast Semgrep pass, terminal report
wbx scan ./challenge --deep          # add CodeQL (py/js/rb/java) + Psalm (php) taint
wbx scan ./challenge --format md     # markdown to stdout
wbx scan ./challenge --out ./results # choose output dir

# live confirmation against the AUTHORIZED challenge instance (DAST, not offline):
wbx verify http://TARGET:PORT --report ./challenge-wbx/report.json
wbx verify http://TARGET:PORT --tags laravel cve --severity critical high
```

Output (default `<path>-wbx/`): `report.md`, `report.json`, `scaffolds/*.py`.

## Install

```bash
uv venv && source .venv/bin/activate
uv pip install -e .
```

Requires `semgrep` on PATH (fast pass) and, for `--deep`, `codeql`. See
[docs/OFFLINE-SETUP.md](docs/OFFLINE-SETUP.md) before an offline event.

Or run everything in the bundled container:

```bash
docker build -t wbx .
docker run --rm -v "$PWD/challenge:/target:ro" wbx scan /target
```

## The corpus is the point

`corpus/challenges/` holds ground-truth fixtures: each has vulnerable source and
an `expected.yaml` naming the planted bug, its file, the intended top class, and
the chain. `pytest` asserts every rule fires where the bug is (recall), the
intended bug ranks #1 (precision), the right chain matches, and benign fixtures
stay quiet. **A rule with no corpus case backing it is not done.** This is what
stops the tool from lying to us: it is tested against known answers before the
clock starts.

```bash
pytest                       # fast: Semgrep + brain, all fixtures
WBX_TEST_DEEP=1 pytest       # also exercises the CodeQL deep pass
```

## Extending

- **New Semgrep rule:** add to `rules/semgrep/<lang>/`, tag `metadata.vuln_class`
  (must be in `wbx/models.py:VULN_CLASSES`), then add a corpus fixture that proves it.
- **New chain:** drop a YAML in `rules/chain_templates/` (steps = `any_of` classes).
- **New scaffold:** add a template in `wbx/scaffolds/templates/` and map its class
  in `wbx/scaffolds/generator.py`.

PWN is a separate project.
