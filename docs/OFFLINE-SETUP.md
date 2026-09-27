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

## Psalm (PHP deep taint, `--deep`)
CodeQL cannot analyze PHP, so `--deep` uses Psalm's inter-procedural taint analysis
for PHP. Psalm needs a PHP runtime. No root required:

```bash
# static PHP (userspace), composer, then psalm
curl -sL -o /tmp/php.tgz https://dl.static-php.dev/static-php-cli/common/php-8.3.32-cli-linux-x86_64.tar.gz
mkdir -p ~/.local/opt/php && tar xzf /tmp/php.tgz -C ~/.local/opt/php
cp ~/.local/opt/php/php ~/.local/bin/php
curl -sL https://getcomposer.org/installer | ~/.local/bin/php -- --install-dir=$HOME/.local/bin --filename=composer
mkdir -p ~/.local/opt/psalm && cd ~/.local/opt/psalm
~/.local/bin/php ~/.local/bin/composer require vimeo/psalm
printf '#!/bin/bash\nexec "$HOME/.local/bin/php" "$HOME/.local/opt/psalm/vendor/bin/psalm" "$@"\n' > ~/.local/bin/psalm
chmod +x ~/.local/bin/psalm
```

wbx auto-detects `psalm` on PATH; if absent, `--deep` just skips the PHP taint pass
(Semgrep remains the PHP baseline). Verify: `psalm --version`.

## Nuclei (live `verify`)
`wbx verify` shells out to nuclei against the authorized live instance. Pre-fetch
templates while you have network:

```bash
nuclei -update-templates      # populates ~/nuclei-templates
```

Nuclei is DAST and only runs in `verify`, never during `scan`. Point it only at
targets you are authorized to test (the challenge instance).
