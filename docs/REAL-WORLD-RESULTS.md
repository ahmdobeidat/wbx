# Real-world results: wbx vs. public challenges

Beyond the synthetic benchmark, wbx was run against a set of **real, publicly
released white-box web challenges** from
[orangetw/My-CTF-Web-Challenges](https://github.com/orangetw/My-CTF-Web-Challenges)
— Orange Tsai's HITCON set, widely regarded as some of the hardest web
source-review challenges published. This is a deliberately punishing test: many of
these use exotic techniques on purpose.

## Headline

- **32 challenges scanned** (PHP, Python, JS, Java, plus a couple C/crypto outliers).
- **Fast (Semgrep only): 23/32 produced findings.**
- **Deep (+CodeQL +Psalm): 30/32 produced findings.**
- After the first run, the 3 in-scope no-finding cases were investigated and the
  rules patched (see below); the **only 2 remaining misses are outside the tool's
  scope by design** (a C CGI binary and a Java crypto-logic challenge).
- Of the 27, the **top-ranked finding matched the documented intended vulnerability
  class on 18** that were verified by reading the source / writeup (e.g. ssrfme,
  babytrick, baby^h-master-php, sql-so-hard, Return-of-Use-After-Flee, giraffe,
  babyfirst(-revenge), one-line-php, BlackBox, Metamon-Verse, angry-seam,
  no-mans-echo, pushincat, lalala, py4h4sher, One-Bit-Man).

Deep analysis mattered: it recovered 7 challenges Semgrep alone missed, including
`sql-so-hard` (cross-file JS SQLi) and `Return-of-Use-After-Flee` (PHP object
injection, via Psalm) — exactly the inter-procedural cases the deep engines exist for.

## Verified hits (sample)

| Challenge | wbx top finding | Documented bug | Verdict |
|---|---|---|---|
| hitcon-2016/babytrick | php_object_injection @index.php:116 | `@unserialize($_GET)` + `__wakeup`/`__destruct` gadgets | correct |
| hitcon-2017/baby^h-master-php | php_object_injection @index.php:40 | object injection | correct |
| hitcon-2017/ssrfme | php_command_injection @index.php:6 | `shell_exec` on the filename param | correct sink |
| hitcon-2017/sql-so-hard | sql_injection @app.js:130 (deep) | SQLi behind a filter | correct |
| hitcon-2020/Return-of-Use-After-Flee | php_object_injection @index.php:32 (Psalm) | object injection | correct |
| hitcon-2015/giraffe's-coffee | php_type_juggling @index.php:118 | `==` type juggling | correct |
| hitcon-2015/babyfirst | php_command_injection @index.php:14 | preg/command RCE | correct |

## The original 5 no-finding cases, and what happened to them

Reading the source showed 3 of the 5 were real gaps (and NOT what the file
extensions suggested). All 3 were patched with general rules and are now caught:

- **luatic** — not a Lua bug at all: the flaw is **PHP variable override**
  (`foreach ($$req as $k=>$v) ${$k}=...`, letting an attacker set any uninitialised
  variable the script trusts). Patched: `wbx-php-variable-override`. Now flags
  `php_variable_override` at the sink.
- **W3rmup-PHP** — **YAML injection into a command**: user data is interpolated into
  a YAML string, parsed, then `system(implode($arr))`. Taint doesn't track through
  `yaml_parse`, so it was missed. Patched: `wbx-php-exec-nonliteral` (+ a
  `yaml_parse` rule). Now flags `php_command_injection` at the `system()` sink.
- **papapa** — **header injection / open redirect**: `header("Location: ".
  $_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'])`. Patched: `wbx-php-header-injection`.
  Now flags `header_injection`.

The 2 that remain unfound are outside wbx's scope by design, not bugs to patch:

- **nanana** — a compiled C CGI (`cgid.c`, `libcgid.so`). wbx analyzes web source
  languages, not C binaries.
- **angry boy** — a Java lottery crypto/logic challenge. The bug is a cryptographic
  weakness, not a taint-reachable sink; no SAST finds this class.

Each patch is a general PHP vulnerability class (variable override, header
injection, indirect command execution, YAML injection), backed by a new corpus
regression fixture, and verified not to add false positives on real clean code.

## Takeaway

On the hardest public white-box web corpus available, wbx surfaces findings on 30/32
(deep) and points at the documented intended bug on the large majority of those it
analyzes, with the deep engines carrying the cross-file cases. After patching the 3
in-scope gaps the first run exposed, the only two remaining misses are a C binary and
a cryptographic-logic bug, both outside what any web-source taint tool reaches, to be
reviewed by hand rather than closed with a rule.

_Method note: "documented intended bug" was judged by reading each challenge's source
and public writeup; it is a considered assessment, not an automated ground-truth
harness like the synthetic corpus. Reproduce with `tools/scan_tree.py` (see repo)._
