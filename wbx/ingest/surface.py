"""Map the attack surface: entrypoints and routes.

This is deliberately regex/heuristic based, not a full parser. In CTF the point
is speed and 'where does user input enter', not a perfect AST. A missed route
costs a scoring nudge, not a missed bug (rules run over the whole tree anyway).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .walk import iter_source_files, lang_of, rel

# Files whose name screams "entrypoint".
_ENTRY_NAMES = {
    "index.php", "index.js", "app.py", "app.js", "main.py", "server.js",
    "wsgi.py", "manage.py", "routes.php", "web.php", "api.php", "app.rb",
    "config.ru", "application.py", "__init__.py",
}

# route-declaration regexes per language. Each captures (method?, path).
_ROUTE_RES = {
    "python": [
        # Flask: @app.route("/x", methods=["POST"])  /  @bp.route(...)
        re.compile(r"@\w+\.route\(\s*['\"]([^'\"]+)['\"](?:.*?methods\s*=\s*\[([^\]]*)\])?", re.DOTALL),
        # FastAPI: @app.get("/x")
        re.compile(r"@\w+\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        # Django urls: path("x/", view)  / re_path(r"^x$", view)
        re.compile(r"\b(?:path|re_path|url)\(\s*[r]?['\"]([^'\"]+)['\"]"),
    ],
    "javascript": [
        # Express: app.get('/x', handler) / router.post(...)
        re.compile(r"\b\w+\.(get|post|put|delete|patch|all|use)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    ],
    "php": [
        # Slim/Laravel-ish: $app->get('/x', ...) / Route::post('/x', ...)
        re.compile(r"(?:->|::)(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    ],
    "ruby": [
        # Sinatra: get '/x' do  / Rails routes: get 'x', to: ...
        re.compile(r"\b(get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"]", re.IGNORECASE),
    ],
    "java": [
        # Spring: @GetMapping("/x") @RequestMapping("/x")
        re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]", re.IGNORECASE),
    ],
}

MAX_BYTES = 512 * 1024


def _norm_route(groups: tuple[str, ...]) -> tuple[str, str]:
    """Normalize a regex match into (method, path). Handles the two capture orders."""
    parts = [g for g in groups if g]
    method = "ANY"
    path = ""
    for g in parts:
        gs = g.strip()
        if gs.lower() in {"get", "post", "put", "delete", "patch", "any", "all", "use", "match", "request"} or "," in gs:
            method = gs.upper().split(",")[0].strip().strip("'\" ")
        elif gs.startswith("/") or "/" in gs or not path:
            path = gs
    return method or "ANY", path


def map_surface(root: str | Path) -> tuple[list[str], list[dict[str, Any]]]:
    """Return (entrypoints[], routes[])."""
    root = Path(root)
    entrypoints: list[str] = []
    routes: list[dict[str, Any]] = []

    for p in iter_source_files(root):
        lg = lang_of(p)
        if not lg:
            continue
        r = rel(p, root)
        if p.name in _ENTRY_NAMES:
            entrypoints.append(r)
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(errors="replace")
        except (OSError, UnicodeError):
            continue

        for pat in _ROUTE_RES.get(lg, []):
            for m in pat.finditer(text):
                method, path = _norm_route(m.groups())
                if not path:
                    continue
                line = text[: m.start()].count("\n") + 1
                routes.append({"method": method, "path": path, "file": r, "line": line})

    # de-dupe routes
    seen = set()
    uniq = []
    for rt in routes:
        key = (rt["method"], rt["path"], rt["file"], rt["line"])
        if key not in seen:
            seen.add(key)
            uniq.append(rt)
    return entrypoints, uniq
