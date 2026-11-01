from __future__ import annotations

import os

from ..cache import Cache
from .base import Provider
from .demo import DemoProvider
from .reputation import AbuseIPDB, Shodan, VirusTotal
from .threatintel import OTX, MalwareBazaar, ThreatFox, URLhaus

ALL_PROVIDERS: list[type[Provider]] = [
    VirusTotal, AbuseIPDB, Shodan, OTX, ThreatFox, URLhaus, MalwareBazaar,
]


def build_providers(cache: Cache, demo: bool = False, only: set[str] | None = None) -> tuple[list[Provider], list[str]]:
    """Instantiate providers that have credentials. Returns (providers, skipped_names)."""
    if demo:
        return [DemoProvider(None, cache)], []
    active, skipped = [], []
    for cls in ALL_PROVIDERS:
        if only and cls.name not in only:
            continue
        p = cls(os.environ.get(cls.env_var), cache)
        (active if p.available else skipped).append(p if p.available else cls.name)
    return active, skipped
