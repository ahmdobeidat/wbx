"""Assemble the SurfaceMap from the sub-detectors."""
from __future__ import annotations

from pathlib import Path

from ..models import SurfaceMap
from .fingerprint import fingerprint
from .surface import map_surface
from .tells import find_tells


def build_surface_map(root: str | Path) -> SurfaceMap:
    languages, frameworks = fingerprint(root)
    entrypoints, routes = map_surface(root)
    flag_hits, secret_hits = find_tells(root)
    return SurfaceMap(
        languages=languages,
        frameworks=frameworks,
        entrypoints=entrypoints,
        routes=routes,
        flag_hits=flag_hits,
        secret_hits=secret_hits,
    )
