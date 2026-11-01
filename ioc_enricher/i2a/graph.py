"""Evidence-typed investigation graph.

Every edge records HOW we know the relationship:

* observed - read straight from a data source (a DNS record, a certificate, a scan result)
* inferred - derived by this tool (shared fingerprint, same cluster) and weaker
* reported - asserted by a third-party report/label (OTX pulse, vendor tag)

Node ids are ``kind:value``. ``weight`` on an edge is its reliability in (0, 1]; a node's
``path_weight`` is the product of edge weights along the strongest path from a seed, so
distant or weak pivots naturally fade out and stop being expanded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EVIDENCE_TYPES = ("observed", "inferred", "reported")


@dataclass
class Node:
    kind: str  # ip | domain | url | hash | email | certificate | malware | campaign | technique | asn | actor
    value: str
    attrs: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    path_weight: float = 1.0
    seed: bool = False
    guarded: str | None = None  # reason this node is not expanded (shared hosting, CDN, ...)
    roles: list[dict] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "value": self.value, "attrs": self.attrs,
                "depth": self.depth, "path_weight": round(self.path_weight, 3), "seed": self.seed,
                "guarded": self.guarded, "roles": self.roles}


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    evidence: str  # observed | inferred | reported
    source: str  # provider that produced it
    weight: float = 0.5
    first_seen: str | None = None
    last_seen: str | None = None
    detail: str = ""
    link: str | None = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["weight"] = round(self.weight, 3)
        return d


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._edge_keys: dict[tuple, Edge] = {}

    # -- nodes ----------------------------------------------------------
    def node(self, kind: str, value: str) -> Node | None:
        return self.nodes.get(f"{kind}:{value}")

    def add_node(self, kind: str, value: str, **attrs: Any) -> Node:
        n = self.nodes.get(f"{kind}:{value}")
        if n is None:
            n = Node(kind, value)
            self.nodes[n.id] = n
        for k, v in attrs.items():
            if v not in (None, "", [], {}):
                n.attrs[k] = v
        return n

    # -- edges ----------------------------------------------------------
    def add_edge(self, src: Node, dst: Node, rel: str, evidence: str, source: str, weight: float = 0.5,
                 first_seen: str | None = None, last_seen: str | None = None,
                 detail: str = "", link: str | None = None) -> Edge:
        assert evidence in EVIDENCE_TYPES, evidence
        key = (src.id, dst.id, rel, source)
        e = self._edge_keys.get(key)
        if e:  # merge repeated observations
            e.weight = max(e.weight, weight)
            e.first_seen = min(filter(None, [e.first_seen, first_seen]), default=None)
            e.last_seen = max(filter(None, [e.last_seen, last_seen]), default=None)
            return e
        e = Edge(src.id, dst.id, rel, evidence, source, weight, first_seen, last_seen, detail, link)
        self.edges.append(e)
        self._edge_keys[key] = e
        return e

    def edges_of(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id or e.dst == node_id]

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": [e.to_dict() for e in self.edges]}
