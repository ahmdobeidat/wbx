# Offline setup (do this BEFORE the competition)

The comp bans AI and often the network. wbx runs offline by design, but its two
engines need their rules/queries cached locally first.

## Semgrep
Rules ship in this repo (`rules/semgrep/`). Semgrep is invoked with
`--metrics=off --disable-version-check`, so no network call is made during a scan.
Nothing to prefetch beyond installing semgrep.

Verify:
```bash
semgrep --validate --config rules/semgrep/ --metrics=off
```

## CodeQL (`--deep`)
CodeQL needs the per-language query packs in the local cache
(`~/.codeql/packages/`). Prefetch them while you still have network:

```bash
codeql pack download codeql/python-queries codeql/javascript-queries \
                     codeql/ruby-queries codeql/java-queries
```

Check what is already cached:
```bash
codeql resolve packs | grep -E "python-queries|javascript-queries|ruby-queries|java-queries"
```

Notes:
- CodeQL does **not** support PHP. PHP challenges use the Semgrep pass only.
- Java DB creation uses `--build-mode none` (no compile needed) but extraction is
  best-effort; if a Java challenge ships a build, results improve with a real build.
- The deep pass returns nothing (never crashes) if a pack is missing, so verify
  the cache beforehand rather than discovering it mid-scan.

## Docker
`docker build -t wbx .` bakes semgrep + codeql + the rules into one image so the
only runtime need is the target source mounted read-only.
