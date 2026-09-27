# wbx nuclei templates

Confirmation templates for the live `wbx verify` step. These map to the vulnerability
classes wbx finds in source, so a static finding can be confirmed on a target you are
authorized to test:

| Template | Confirms |
|---|---|
| `wbx-source-disclosure` | exposed `.git` / `.env` / manifests / backups (source & secret leak) |
| `wbx-debug-consoles` | Werkzeug / Symfony profiler / Spring actuator / Laravel Ignition |
| `wbx-ssti-fuzz` | server-side template injection (query fuzzing, math-eval oracle) |
| `wbx-lfi-fuzz` | local file inclusion / path traversal (traversal + php:// wrappers) |
| `wbx-sqli-error-fuzz` | error-based SQL injection (DB error signatures) |

Fuzzing templates require nuclei's DAST mode:

```bash
wbx verify https://target.example --wbx-templates        # all bundled templates
nuclei -u https://target.example/?id=1 -t rules/nuclei/ -dast
```

Use only against systems you are authorized to test.
