# wbx

A white-box web application security testing tool. Point it at an application's
source code and it returns a ranked list of likely vulnerabilities, the exploit
chains they compose into, and a PoC scaffold for each so you can confirm them fast.

**Deterministic and offline.** The `scan` stage makes no network calls and uses no
LLM at runtime, it is plain static analysis over source, so results are
reproducible and safe to run against code you cannot send anywhere.

## What it does

```
source tree -> Ingest -> Scan (Semgrep + CodeQL + Psalm) -> Score -> Chain -> Report + Scaffolds
```

- **Ingest** fingerprints languages/frameworks, maps routes/entrypoints, and locates
  high-signal markers (secrets, sensitive file references).
- **Scan** runs curated Semgrep rulepacks (fast, PHP/Python/JS/Ruby/Java) and, with
  `--deep`, inter-procedural taint analysis: **CodeQL** for Python/JS/Ruby/Java and
  **Psalm `--taint-analysis`** for PHP (CodeQL cannot analyze PHP, so Psalm fills the
  cross-file PHP gap).
- **Score** ranks findings by an impact-tier model (RCE > injection/auth-bypass >
  disclosure > low) with evidence and reachability ordering within a tier. A
  **reachability caution** fires when the top finding sits in code no route reaches,
  so a high-impact bug in dead code does not send you down a dead end.
- **Chain** matches findings against a library of known exploit chains
  (`LFI + upload = RCE`, `SQLi -> leaked secret -> auth bypass`,
  `insecure deserialization = RCE`, ...).
- **Hints** surface logic / access-control leads (IDOR, missing authorization) in a
  SEPARATE manual-review section, never mixed with confident findings, because static
  analysis cannot decide an application's authorization policy.
- **Report** prints a terminal summary and writes `report.md` + `report.json`, plus
  runnable PoC scaffolds under `scaffolds/`.
- **Verify** (`wbx verify <url>`) is a separate, live (DAST) step: nuclei against a
  target you are authorized to test, to confirm known-CVE / exposure, seeded by the
  frameworks the static scan detected. `scan` itself never touches the network.

## Usage

```bash
wbx scan ./app                 # fast Semgrep pass, terminal report
wbx scan ./app --deep          # add CodeQL (py/js/rb/java) + Psalm (php) taint
wbx scan ./app --format md     # markdown to stdout
wbx scan ./app --out ./results # choose output dir

# live confirmation against a target you are AUTHORIZED to test (DAST, not offline):
wbx verify https://target.example --report ./app-wbx/report.json
wbx verify https://target.example --tags laravel cve --severity critical high
```

Output (default `<path>-wbx/`): `report.md`, `report.json`, `scaffolds/*.py`.

## Install

```bash
uv venv && source .venv/bin/activate
uv pip install -e .
```

Requires `semgrep` on PATH (fast pass). For `--deep`: `codeql` (py/js/rb/java) and
`psalm` (php). For `wbx verify`: `nuclei`. See
[docs/OFFLINE-SETUP.md](docs/OFFLINE-SETUP.md) for userspace install instructions.

Or run everything in the bundled container:

```bash
docker build -t wbx .
docker run --rm -v "$PWD/app:/target:ro" wbx scan /target
```

## Ground-truth test corpus

`corpus/challenges/` holds ground-truth fixtures: each has vulnerable source and an
`expected.yaml` naming the planted vulnerability, its file, the expected top class,
and any chain. `pytest` asserts every rule fires where the bug is (recall), the
intended bug ranks #1 (precision), the right chain matches, access-control leads land
in the hints channel, and benign fixtures stay quiet. **A rule with no corpus case
backing it is not considered done** — this is what stops the tool from reporting a
clean result it cannot justify.

```bash
pytest                       # fast: Semgrep + ranking, all fixtures
WBX_TEST_DEEP=1 pytest       # also exercises the CodeQL deep pass
```

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for results against an independent,
blind test set and against public real-world targets.

## Extending

- **New Semgrep rule:** add to `rules/semgrep/<lang>/`, tag `metadata.vuln_class`
  (must be in `wbx/models.py:VULN_CLASSES`), then add a corpus fixture that proves it.
- **New chain:** drop a YAML in `rules/chain_templates/` (steps = `any_of` classes).
- **New scaffold:** add a template in `wbx/scaffolds/templates/` and map its class in
  `wbx/scaffolds/generator.py`.
- **New nuclei template:** add to `rules/nuclei/` (used by `wbx verify`).

## Scope and authorization

Use `wbx verify` only against systems you are explicitly authorized to test. The
static `scan` is read-only and offline. This is a tool for authorized security
assessment and defensive source review.
