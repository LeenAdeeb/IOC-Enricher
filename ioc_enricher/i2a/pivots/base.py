"""Pivot provider base: turn one node into typed relations to other nodes."""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

from ...providers.base import Provider


@dataclass
class Relation:
    """src --rel--> dst, with provenance. Kinds are graph node kinds (ip, domain, ...)."""

    src_kind: str
    src_value: str
    rel: str
    dst_kind: str
    dst_value: str
    evidence: str  # observed | inferred
    source: str
    weight: float
    first_seen: str | None = None
    last_seen: str | None = None
    detail: str = ""
    link: str | None = None
    dst_attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class PivotResult:
    relations: list[Relation] = field(default_factory=list)
    node_attrs: dict[str, Any] = field(default_factory=dict)  # attributes learned about the pivoted node
    error: str | None = None
    source: str = ""


def kind_of(ioc_type: str) -> str:
    """IOC type -> graph node kind."""
    return {"ipv4": "ip", "ipv6": "ip", "md5": "hash", "sha1": "hash", "sha256": "hash"}.get(ioc_type, ioc_type)


def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


class PivotProvider(Provider):
    """A data source that can expand a node. Subclasses implement `_pivot`."""

    supported_kinds: set[str] = set()

    def supports_kind(self, kind: str) -> bool:
        return kind in self.supported_kinds

    def _pivot(self, kind: str, value: str) -> PivotResult:
        raise NotImplementedError

    def pivot(self, kind: str, value: str) -> PivotResult:
        key = f"pivot:{self.name}:{kind}:{value}"
        hit = self.cache.get(key)
        if hit is not None:
            return PivotResult([Relation(**r) for r in hit["relations"]], hit["node_attrs"], hit.get("error"), self.name)
        try:
            res = self._pivot(kind, value)
        except requests.RequestException as exc:
            return PivotResult(error=f"network error: {exc}", source=self.name)
        except Exception as exc:  # one broken source must never abort the investigation
            return PivotResult(error=f"{type(exc).__name__}: {exc}", source=self.name)
        res.source = self.name
        if res.error is None:
            self.cache.set(key, {"relations": [asdict(r) for r in res.relations],
                                 "node_attrs": res.node_attrs, "error": None})
        return res
