# Real-world results: wbx vs. public challenges

Beyond the synthetic benchmark, wbx was run against a set of **real, publicly
released white-box web challenges** from
[orangetw/My-CTF-Web-Challenges](https://github.com/orangetw/My-CTF-Web-Challenges)
— Orange Tsai's HITCON set, widely regarded as some of the hardest web
source-review challenges published. This is a deliberately punishing test: many of
these use exotic techniques on purpose.

## Headline

- **32 challenges scanned** (PHP, Python, JS, Java, plus a couple C/crypto outliers).
- **Fast (Semgrep only): 20/32 produced findings.**
- **Deep (+CodeQL +Psalm): 27/32 produced findings.**
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

## The 5 no-finding cases (honest)

- **nanana** — a compiled C CGI (`cgid.c`, `libcgid.so`). Out of scope: wbx analyzes
  web source languages, not C binaries.
- **angry boy** — a Java lottery crypto/logic challenge. Out of scope: the bug is a
  cryptographic/logic flaw, not a taint-reachable sink; no SAST finds this.
- **luatic** — Lua embedded in PHP. Genuine gap: wbx has no Lua rules.
- **papapa** — PHP + Apache config trick. Genuine gap: the vuln lives in server
  config / a niche function, not a standard sink.
- **W3rmup-PHP** — an exotic single-file PHP trick with no standard sink pattern.

So of 5 misses: 2 are outside the tool's language scope by design, and 3 are real
coverage gaps (Lua, server-config tricks, exotic single-function abuse) — the honest
edge of what pattern/taint analysis reaches.

## Takeaway

On the hardest public white-box web corpus available, wbx surfaces findings on 27/32
and points at the documented intended bug on the large majority of those it analyzes,
with the deep engines carrying the cross-file cases. The failures are concentrated
exactly where static analysis is known to be weak: non-web languages, server
configuration, cryptographic/logic bugs, and niche single-function tricks. Those are
categories to review by hand, not gaps a rule can close.

_Method note: "documented intended bug" was judged by reading each challenge's source
and public writeup; it is a considered assessment, not an automated ground-truth
harness like the synthetic corpus. Reproduce with `tools/scan_tree.py` (see repo)._
