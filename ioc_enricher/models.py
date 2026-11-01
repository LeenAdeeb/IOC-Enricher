"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class IOC:
    value: str
    type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | email

    @property
    def is_hash(self) -> bool:
        return self.type in {"md5", "sha1", "sha256"}


@dataclass
class ProviderResult:
    """Normalised output of a single provider lookup."""

    provider: str
    ok: bool = True
    found: bool = False
    error: str | None = None
    malicious_score: int | None = None  # 0-100, provider-specific meaning normalised
    tags: set[str] = field(default_factory=set)
    malware: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)  # explicit actor mentions
    techniques: set[str] = field(default_factory=set)  # ATT&CK IDs
    context: dict[str, Any] = field(default_factory=dict)
    link: str | None = None
    native: str = ""  # provider's own result, shown as-is in reports

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("tags", "malware", "actors", "techniques"):
            d[k] = sorted(d[k])
        return d


@dataclass
class Enrichment:
    ioc: IOC
    results: list[ProviderResult] = field(default_factory=list)
    verdict: str = "unknown"
    risk_score: int = 0
    basis: dict = field(default_factory=dict)  # how the IOC-Enricher score was derived
    not_applicable: list[str] = field(default_factory=list)  # providers that don't support this type

    def merged(self, attr: str) -> set[str]:
        out: set[str] = set()
        for r in self.results:
            out |= getattr(r, attr)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc.value,
            "type": self.ioc.type,
            "ioc_enricher": {"score": self.risk_score, "verdict": self.verdict, **self.basis},
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "not_applicable": self.not_applicable,
            "malware": sorted(self.merged("malware")),
            "actors": sorted(self.merged("actors")),
            "techniques": sorted(self.merged("techniques")),
            "tags": sorted(self.merged("tags")),
            "providers": [r.to_dict() for r in self.results],
        }
