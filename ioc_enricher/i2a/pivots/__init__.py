from __future__ import annotations

import os

from ...cache import Cache
from .base import PivotProvider, PivotResult, Relation
from .demo import DemoPivot
from .scanners import Censys, Fofa
from .vt import VTRelations
from .web import CrtSh, UrlScan

ALL_PIVOTS: list[type[PivotProvider]] = [CrtSh, UrlScan, VTRelations, Censys, Fofa]
PIVOT_NAMES = {"crtsh": CrtSh, "urlscan": UrlScan, "vt": VTRelations, "vt-relations": VTRelations,
               "censys": Censys, "fofa": Fofa}


def build_pivots(cache: Cache, demo: bool = False, only: set[str] | None = None):
    """Instantiate pivot sources that are usable (key present or key optional)."""
    if demo:
        return [DemoPivot(None, cache)], []
    wanted = {PIVOT_NAMES[n].name for n in only} if only else None
    active, skipped = [], []
    for cls in ALL_PIVOTS:
        if wanted and cls.name not in wanted:
            continue
        p = cls(os.environ.get(cls.env_var) if cls.env_var else None, cache)
        if p.available:
            active.append(p)
        else:
            skipped.append(cls.name)
    return active, skipped


__all__ = ["PivotProvider", "PivotResult", "Relation", "build_pivots", "DemoPivot"]
