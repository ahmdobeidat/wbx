"""Logic / access-control HINTS.

SAST cannot decide an application's authorization policy (research is unanimous on
this: a static tool cannot know whether user A may read object B). So instead of
pretending to find these bugs, wbx surfaces *leads*: places a human should look.
These never enter the confident `findings` list -- they go in `hints`.

Heuristic here: a route handler that shows no visible auth/session guard anywhere
in its file is a candidate for broken access control. Noisy by nature, hence a hint.
IDOR leads come from the tagged semgrep rules; this module covers missing-auth.
"""
from __future__ import annotations

from pathlib import Path

from ..models import Finding, SurfaceMap
from ..ingest.walk import iter_source_files, lang_of, rel
from .score import _TIER, _sort

# Tokens that indicate SOME auth/session/authorization mechanism is present in a file.
# Deliberately broad: presence means "don't flag"; we only hint when NONE appear.
_AUTH_TOKENS = (
    "login_required", "current_user", "session", "request.user", "req.user",
    "isadmin", "is_admin", "authenticate", "authoriz", "@auth", "before_action",
    "jwt_required", "verify_token", "verifytoken", "requireauth", "ensureauth",
    "checkauth", "check_auth", "permission", "hasrole", "has_role", "getuser",
    "@login", "passport", "ensureloggedin", "access_control", "acl",
    "csrf", "token_required", "auth_required",
)

# Route paths that scream "sensitive" get flagged even if we're conservative.
_SENSITIVE = ("admin", "delete", "update", "edit", "user", "account", "profile",
              "settings", "manage", "internal", "config")

MAX_BYTES = 512 * 1024


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            return ""
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _is_sensitive(route: dict) -> bool:
    return (any(s in route["path"].lower() for s in _SENSITIVE)
            or route["method"] not in ("GET", "ANY", "USE"))


def find_access_control_hints(root: str | Path, surface: SurfaceMap) -> list[Finding]:
    """Flag sensitive routes with no visible auth guard in their own window.

    Route-level (not file-level): a file can guard some routes and leave one open,
    which is the common CTF broken-access-control shape. For each route we look at
    a window around its declaration (a few lines above for decorators/middleware,
    down to the next route) for any auth/session token; absence on a sensitive
    route is a lead.
    """
    root = Path(root)
    hints: list[Finding] = []
    by_file: dict[str, list[dict]] = {}
    for rt in surface.routes:
        by_file.setdefault(rt["file"], []).append(rt)

    for rel_file, routes in by_file.items():
        text = _read(root / rel_file)
        if not text:
            continue
        lines = text.splitlines()
        routes = sorted(routes, key=lambda r: r.get("line", 0))
        route_lines = [r.get("line", 1) for r in routes]

        for idx, rt in enumerate(routes):
            if not _is_sensitive(rt):
                continue
            rl = rt.get("line", 1)                              # 1-based
            prev_rl = route_lines[idx - 1] if idx > 0 else 0
            next_rl = route_lines[idx + 1] if idx + 1 < len(route_lines) else len(lines) + 1
            # a few lines above for decorators (not into the previous route), down to
            # the next route (not past it, so a sibling route's guard never leaks in)
            start = max(prev_rl + 1, rl - 3)
            end = min(next_rl - 1, rl + 15)
            window = "\n".join(lines[start - 1:end]).lower()
            if any(tok in window for tok in _AUTH_TOKENS):
                continue  # this route has a guard nearby
            hints.append(Finding(
                rule_id="wbx-logic-missing-auth",
                engine="wbx-logic",
                lang=lang_of(rel_file) or "",
                vuln_class="access_control",
                file=rel_file,
                line=rt.get("line", 1),
                message=(
                    f"Sensitive route {rt['method']} {rt['path']} shows no auth/session "
                    f"guard in its handler while other routes may be guarded. Possible "
                    f"broken access control. SAST cannot confirm -- verify by hand."
                ),
                severity="INFO",
                confidence="LOW",
                metadata={"hint": True, "cwe": "CWE-862", "route": rt["path"]},
                exploitation_note="Request the route with no session/token; if it works, it's broken access control.",
            ))
    return hints


# --- Reachability (decoy / rabbit-hole robustness) ---------------------------
# The intended bug reaches the flag; a rabbit hole often sits in code no route
# reaches. We approximate reachability: route/entrypoint files, plus files they
# reference by name (include/require/import/use). A finding outside this set on the
# top spot earns a caution -- we can't prove it's a decoy, but we flag it and point
# to a reachable alternative. This uses the include graph, so a real helper-file bug
# (reached via include) is still counted reachable and is NOT penalised.

def _reachable_files(root: Path, surface: SurfaceMap) -> set[str]:
    root = Path(root)
    seed = {r["file"] for r in surface.routes} | set(surface.entrypoints)
    if not seed:
        # no routes mapped: treat everything as reachable (no signal to act on)
        return {rel(p, root) for p in iter_source_files(root)}
    all_files = {rel(p, root): p for p in iter_source_files(root)}
    stems = {Path(f).stem: f for f in all_files}
    reachable = set(seed)
    frontier = list(seed)
    for _ in range(2):  # 2 hops is plenty for CTF-sized apps
        nxt = []
        for f in frontier:
            p = root / f
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for stem, target in stems.items():
                if len(stem) < 3:
                    continue
                if target not in reachable and stem in text:
                    reachable.add(target)
                    nxt.append(target)
        frontier = nxt
        if not frontier:
            break
    return reachable


def apply_reachability(findings: list[Finding], surface: SurfaceMap, root: str | Path) -> list[str]:
    """Add a within-tier bonus for reachable findings, and return rabbit-hole
    cautions. Mutates findings (score/signals) and re-sorts."""
    reachable = _reachable_files(Path(root), surface)
    for f in findings:
        if f.file in reachable and "reachable" not in f.ctf_signals:
            f.ctf_signals["reachable"] = {"pts": 4, "why": "reachable from a mapped route/entrypoint"}
            f.score = round(f.score + 4, 2)
    _sort(findings)

    cautions: list[str] = []
    if findings:
        top = findings[0]
        top_tier = _TIER.get(top.vuln_class, 4)
        if top_tier <= 2 and top.file not in reachable and surface.routes:
            alt = next((f for f in findings if f.file in reachable), None)
            msg = (f"Top finding ({top.vuln_class} at {top.location}) is in a file no "
                   f"mapped route appears to reach -- it may be a rabbit hole.")
            if alt:
                msg += f" A reachable alternative to check first: {alt.vuln_class} at {alt.location}."
            cautions.append(msg)
    return cautions
