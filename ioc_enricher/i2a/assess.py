"""Stage 3: infrastructure role assessment (what is this node *doing*?) and clustering.

Roles are hypotheses with their evidence, never facts. Confidence is capped at Moderate
because nothing here inspects C2 protocol behaviour, malware configuration or beaconing.
"""
from __future__ import annotations

from collections import defaultdict

from ..models import Enrichment
from .graph import Graph, Node
from .guards import is_dynamic_dns

C2_TAGS = {"c2", "c&c", "cnc", "botnet_cc", "botnet c2", "beacon", "cobaltstrike", "cobalt strike", "rat"}
PAYLOAD_TAGS = {"malware_download", "payload_delivery", "dropper", "loader", "trojanized-installer", "exploit-kit"}
ROTATING_IPS_THRESHOLD = 5


def _label(n: int) -> str:
    return "Moderate" if n >= 3 else "Low"


def assess_nodes(graph: Graph, enrichments: dict[str, Enrichment]) -> None:
    for node in graph.nodes.values():
        node.roles = []
        edges = graph.edges_of(node.id)
        if node.guarded:
            node.roles.append({"role": "shared-infrastructure", "confidence": "Moderate",
                               "evidence": [node.guarded]})
        if node.kind in ("ip", "domain", "url", "hash"):
            enr = enrichments.get(node.value)
            _c2_and_payload(node, enr, edges, graph)
        if node.kind == "domain":
            _dns_behaviour(node, edges, graph)
        if node.kind == "certificate":
            covered = [e for e in edges if e.rel == "covers"]
            if len(covered) >= 2:
                node.roles.append({"role": "shared-certificate", "confidence": "Low",
                                   "evidence": [f"one certificate covers {len(covered)} related domain(s)"]})


def _c2_and_payload(node: Node, enr: Enrichment | None, edges, graph: Graph) -> None:
    c2, pay = [], []
    if enr:
        tags = {t.lower() for t in enr.merged("tags")}
        hit = sorted(tags & C2_TAGS)
        if hit:
            c2.append(f"tagged by sources: {', '.join(hit)}")
        for r in enr.results:
            if r.provider == "threatfox" and r.found:
                c2.append("listed in ThreatFox as a malware IOC")
            if r.provider == "urlhaus" and r.found:
                pay.append("listed in URLhaus as malware distribution")
            if r.provider == "malwarebazaar" and r.found:
                pay.append("hash is a known malware sample (MalwareBazaar)")
        ptags = sorted(tags & PAYLOAD_TAGS)
        if ptags:
            pay.append(f"tagged: {', '.join(ptags)}")
        if enr.risk_score >= 70 and enr.merged("malware") and node.kind in ("ip", "domain"):
            c2.append(f"malicious verdict with malware family: {', '.join(sorted(enr.merged('malware'))[:3])}")
    comm = [e for e in edges if e.rel == "communicates-with" and e.dst == node.id]
    if len(comm) >= 1 and node.kind in ("ip", "domain"):
        c2.append(f"{len(comm)} malicious sample(s) communicate with it ({', '.join(sorted({e.source for e in comm}))})")
    if c2:
        node.roles.append({"role": "c2-candidate", "confidence": _label(len(c2)), "evidence": c2})
    if pay:
        node.roles.append({"role": "payload-host", "confidence": _label(len(pay)), "evidence": pay})


def _dns_behaviour(node: Node, edges, graph: Graph) -> None:
    ips = {e.dst for e in edges if e.src == node.id and e.rel == "resolves-to"}
    ips |= {e.src for e in edges if e.dst == node.id and e.rel == "hosts" and e.src.startswith("ip:")}
    notes = []
    if is_dynamic_dns(node.value):
        notes.append("domain sits under a dynamic-DNS provider")
    if len(ips) >= ROTATING_IPS_THRESHOLD:
        notes.append(f"resolves to {len(ips)} different IPs (rotating or fast-flux behaviour possible)")
    dates = sorted(filter(None, [e.first_seen for e in edges if e.rel in ("resolves-to", "hosts")]))
    if notes:
        node.roles.append({"role": "dns-behaviour", "confidence": "Low", "evidence": notes})
    if dates:
        node.attrs["dns_first_seen"] = dates[0]


def clusters(graph: Graph, min_edge_weight: float = 0.4) -> list[dict]:
    """Connected components over strong, non-reported links between infrastructure nodes."""
    infra = {"ip", "domain", "url", "hash", "certificate"}
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e in graph.edges:
        a, b = graph.nodes.get(e.src), graph.nodes.get(e.dst)
        if not a or not b or a.kind not in infra or b.kind not in infra:
            continue
        if e.evidence == "reported" or e.weight < min_edge_weight or a.guarded or b.guarded:
            continue
        parent[find(a.id)] = find(b.id)
    comps: dict[str, list[str]] = defaultdict(list)
    for nid in list(parent):
        comps[find(nid)].append(nid)
    out = []
    for members in sorted((m for m in comps.values() if len(m) >= 2), key=lambda m: (-len(m), sorted(m)[0])):
        nodes = [graph.nodes[m] for m in members]
        out.append({
            "id": len(out) + 1,
            "members": sorted(members),
            "size": len(members),
            "seeds": sorted(n.value for n in nodes if n.seed),
            "c2_candidates": sorted(n.value for n in nodes if any(r["role"] == "c2-candidate" for r in n.roles)),
            "shared_certificates": sorted(n.value for n in nodes if n.kind == "certificate"),
        })
    return out
