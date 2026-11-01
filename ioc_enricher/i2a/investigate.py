"""I2A investigation: IOC -> Infrastructure -> Actor.

Stage 1  Context      enrich the seed IOCs with the reputation providers
Stage 2  Pivot        expand through DNS, certificates, scans and samples (controlled depth)
Stage 3  Assess       label likely C2 / payload / shared infrastructure; cluster
Stage 5  Attribute    weighted, dimension-based actor hypotheses with alternatives

(The numbering follows the methodology document; Stage 4, sandbox/campaign correlation, is
represented by malware families and ATT&CK techniques reported by the sources.)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from ..attribution import Attributor
from ..engine import enrich
from ..ioc import classify, defang
from ..models import IOC, Enrichment
from ..providers.base import Provider
from . import assess
from .graph import Graph, Node
from .guards import (SHARED_HOSTING_DOMAIN_THRESHOLD, is_mega_domain, is_public_ip, shared_asn_name)
from .pivots.base import PivotProvider, Relation, kind_of, valid_ip

PIVOTABLE = {"ip", "domain", "hash", "certificate"}
ENRICHABLE = {"ip", "domain", "hash", "url"}


@dataclass
class Settings:
    depth: int = 2  # pivot hops from the seeds
    max_nodes: int = 150  # hard cap on graph size
    fanout: int = 15  # max new nodes accepted from one pivot
    min_weight: float = 0.25  # nodes whose path weight is below this are shown but not expanded
    enrich_related: int = 8  # reputation-enrich this many strongest related nodes
    allow_private: bool = False  # demo mode only: treat documentation-range IPs as routable


@dataclass
class Investigation:
    seeds: list[IOC]
    settings: Settings
    graph: Graph = field(default_factory=Graph)
    enrichments: dict[str, Enrichment] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    clusters: list[dict] = field(default_factory=list)
    summaries: list[dict] = field(default_factory=list)
    pivot_stats: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------------------
def _first_seen(enr: Enrichment) -> str | None:
    dates = []
    for r in enr.results:
        v = r.context.get("first_seen")
        if v:
            dates.append(str(v)[:10])
    return min(dates) if dates else None


def register_enrichment(g: Graph, enr: Enrichment, seed: bool, depth: int = 0, pw: float = 1.0) -> Node:
    """Put an enriched IOC on the graph together with the malware/campaign/technique it is reported with."""
    kind = kind_of(enr.ioc.type)
    node = g.add_node(kind, enr.ioc.value)
    node.seed = node.seed or seed
    if seed:
        node.depth, node.path_weight = 0, 1.0
    node.attrs.update({k: v for k, v in {
        "verdict": enr.verdict, "score": enr.risk_score,
        "providers": {r.provider: (r.native if r.ok else f"ERROR: {r.error}") for r in enr.results},
        "tags": sorted(enr.merged("tags"))[:12], "reported_actors": sorted(enr.merged("actors")),
        "first_seen": _first_seen(enr),
    }.items() if v not in (None, "", [], {})})
    by_family: dict[str, set[str]] = {}
    campaigns: dict[str, set[str]] = {}
    for r in enr.results:
        for fam in r.malware:
            by_family.setdefault(fam, set()).add(r.provider)
        for name in r.context.get("pulse_names", [])[:3]:
            campaigns.setdefault(name, set()).add(r.provider)
    for fam, srcs in by_family.items():
        m = g.add_node("malware", fam)
        g.add_edge(node, m, "associated-with", "reported", "+".join(sorted(srcs)), 0.5, detail="malware family label")
    for name, srcs in campaigns.items():
        c = g.add_node("campaign", name)
        g.add_edge(node, c, "mentioned-in", "reported", "+".join(sorted(srcs)), 0.4, detail="threat report / pulse")
    if seed:
        for tid in sorted(enr.merged("techniques"))[:8]:
            t = g.add_node("technique", tid)
            g.add_edge(node, t, "uses", "reported", "reports", 0.3, detail="ATT&CK technique reported")
    return node


def _other(r: Relation, node: Node) -> tuple[str, str]:
    if r.src_kind == node.kind and r.src_value == node.value:
        return r.dst_kind, r.dst_value
    return r.src_kind, r.src_value


class _Run:
    def __init__(self, inv: Investigation, providers: list[Provider], pivots: list[PivotProvider],
                 progress: Callable[[str], None] | None):
        self.inv, self.g, self.s = inv, inv.graph, inv.settings
        self.providers, self.pivots, self.progress = providers, pivots, progress
        self.expanded: set[str] = set()
        self.cap_logged = False

    def say(self, msg: str) -> None:
        self.inv.log.append(msg)
        if self.progress:
            self.progress(msg)

    # -- stage 2 ----------------------------------------------------------
    def expand(self, node: Node, depth: int) -> list[Node]:
        self.expanded.add(node.id)
        if node.kind == "ip" and not (self.s.allow_private or is_public_ip(node.value)):
            self.say(f"skip: {node.value} is not a public IP and is never sent to external sources")
            return []
        rels: list[Relation] = []
        used = []
        for pv in self.pivots:
            if not pv.supports_kind(node.kind):
                continue
            self.say(f"pivot {node.kind}:{defang(node.value)} via {pv.name}")
            res = pv.pivot(node.kind, node.value)
            used.append(pv.name)
            if res.error:
                self.inv.errors.append(f"{pv.name} on {defang(node.value)}: {res.error}")
                continue
            for k, v in res.node_attrs.items():
                node.attrs.setdefault(k, v)
            rels.extend(res.relations)
        self.inv.pivot_stats[node.id] = {"sources": used, "relations": len(rels)}
        asn_name = shared_asn_name(node.attrs.get("asn"))
        if asn_name and not node.seed:
            node.guarded = (f"hosted in {asn_name} infrastructure (AS{node.attrs.get('asn')}): "
                            f"shared by many unrelated tenants")
            self.say(f"guard: {defang(node.value)} flagged as shared infrastructure ({asn_name}); not expanded")
            return []

        # fan-out guard: one IP serving dozens of domains is shared hosting, not a campaign.
        domains = {_other(r, node)[1] for r in rels if _other(r, node)[0] == "domain"}
        if node.kind == "ip" and len(domains) > SHARED_HOSTING_DOMAIN_THRESHOLD:
            node.guarded = f"high fan-out: {len(domains)} domains seen on this IP, likely shared hosting or CDN"
            node.attrs["hidden_domains"] = len(domains)
            node.attrs["sample_domains"] = sorted(domains)[:5]
            self.say(f"guard: {defang(node.value)} flagged as shared infrastructure ({len(domains)} domains); "
                     f"domains not added to the graph")
            return []

        rels.sort(key=lambda r: (-r.weight, _neg(r.last_seen)))
        # A source may return chains (domain -> certificate -> other domains). Process relations in
        # waves so each hop is anchored on a node that is already on the graph.
        local: dict[str, Node] = {node.id: node}
        accepted: set[tuple[str, str]] = set()
        new_nodes: list[Node] = []
        pending = list(rels)
        dropped = filtered = 0
        while pending:
            progressed, rest = False, []
            for r in pending:
                sid, did = f"{r.src_kind}:{r.src_value}", f"{r.dst_kind}:{r.dst_value}"
                anchor_id = sid if sid in local else did if did in local else None
                if anchor_id is None:
                    rest.append(r)
                    continue
                progressed = True
                anchor = local[anchor_id]
                okind, oval = (r.dst_kind, r.dst_value) if anchor_id == sid else (r.src_kind, r.src_value)
                existing = self.g.node(okind, oval)
                if existing is None:
                    if okind == "domain" and is_mega_domain(oval):
                        filtered += 1
                        continue
                    if okind == "ip" and not (self.s.allow_private or is_public_ip(oval)):
                        filtered += 1
                        continue
                    if (okind, oval) not in accepted and len(accepted) >= self.s.fanout:
                        dropped += 1
                        continue
                    if len(self.g.nodes) >= self.s.max_nodes:
                        if not self.cap_logged:
                            self.say(f"limit: max_nodes={self.s.max_nodes} reached, expansion truncated")
                            self.cap_logged = True
                        continue
                accepted.add((okind, oval))
                src = self.g.add_node(r.src_kind, r.src_value)
                dst = self.g.add_node(r.dst_kind, r.dst_value)
                other = dst if anchor_id == sid else src
                for k, v in r.dst_attrs.items():  # attributes describe the discovered node
                    if v not in (None, "", [], {}):
                        other.attrs.setdefault(k, v)
                pw = anchor.path_weight * r.weight
                fresh = other.id not in local and other.id not in self.expanded and not other.seed \
                    and other.depth == 0 and other.path_weight == 1.0
                if fresh:
                    other.depth, other.path_weight = depth, pw
                    new_nodes.append(other)
                elif not other.seed and pw > other.path_weight:
                    other.path_weight = pw
                local[other.id] = other
                self.g.add_edge(src, dst, r.rel, r.evidence, r.source, r.weight, r.first_seen, r.last_seen,
                                r.detail, r.link)
            pending = rest
            if not progressed:
                break
        if dropped or filtered:
            self.say(f"{defang(node.value)}: kept {len(accepted)}, dropped {dropped} (fan-out cap), "
                     f"ignored {filtered} well-known/private")
        return new_nodes

    def derive_hosts(self) -> list[Node]:
        """A URL or e-mail address is only a pointer: its host/domain is what can be pivoted on."""
        out = []
        for n in list(self.g.nodes.values()):
            if not n.seed or n.kind not in ("url", "email"):
                continue
            if n.kind == "url":
                host = (urlparse(n.value).hostname or "").lower()
                rel, w = "hosted-on", 0.9
            else:
                host = n.value.rsplit("@", 1)[-1].lower()
                rel, w = "sent-from-domain", 0.6
            if not host:
                continue
            kind = "ip" if valid_ip(host) else "domain"
            if kind == "domain" and is_mega_domain(host):
                self.say(f"ignored host {host} of {n.kind} seed (well-known domain)")
                continue
            if kind == "ip" and not (self.s.allow_private or is_public_ip(host)):
                continue
            existing = self.g.node(kind, host) is not None
            h = self.g.add_node(kind, host)
            if not existing:
                h.depth, h.path_weight = 1, w
            self.g.add_edge(n, h, rel, "observed", "ioc-parse", w, detail=f"{rel.replace('-', ' ')} (parsed from the IOC)")
            out.append(h)
        return out

    def pivot(self) -> None:
        frontier = [n for n in self.g.nodes.values() if n.seed and n.kind in PIVOTABLE] + self.derive_hosts()
        for depth in range(1, self.s.depth + 1):
            nxt: list[Node] = []
            for node in sorted(frontier, key=lambda n: -n.path_weight):
                if node.id in self.expanded or node.guarded:
                    continue
                if node.path_weight < self.s.min_weight:
                    continue
                nxt.extend(self.expand(node, depth))
            frontier = [n for n in nxt if n.kind in PIVOTABLE and n.path_weight >= self.s.min_weight and not n.guarded]
            if not frontier:
                break

    # -- stage 1 for related nodes -----------------------------------------
    def enrich_related(self) -> None:
        cands = [n for n in self.g.nodes.values()
                 if not n.seed and n.kind in ENRICHABLE and not n.guarded and n.value not in self.inv.enrichments]
        cands.sort(key=lambda n: -n.path_weight)
        iocs = [i for i in (classify(n.value) for n in cands[: self.s.enrich_related]) if i]
        if not iocs or not self.providers:
            return
        self.say(f"enriching {len(iocs)} strongest related node(s)")
        for enr in enrich(iocs, self.providers, self.progress):
            self.inv.enrichments[enr.ioc.value] = enr
            node = self.g.node(kind_of(enr.ioc.type), enr.ioc.value)
            register_enrichment(self.g, enr, seed=False)
            if node is not None:
                node.attrs["enriched"] = True


def _neg(s: str | None) -> tuple:
    return tuple(-ord(c) for c in (s or ""))


# ---------------------------------------------------------------------------------------
def investigate(seeds: list[IOC], providers: list[Provider], pivots: list[PivotProvider],
                settings: Settings | None = None, kb: dict | None = None,
                progress: Callable[[str], None] | None = None) -> Investigation:
    inv = Investigation(seeds=seeds, settings=settings or Settings())
    run = _Run(inv, providers, pivots, progress)

    # Stage 1: what is it?
    run.say(f"stage 1: enriching {len(seeds)} seed indicator(s)")
    for enr in enrich(seeds, providers, progress):
        inv.enrichments[enr.ioc.value] = enr
        register_enrichment(inv.graph, enr, seed=True)

    # Stage 2: what is it connected to?
    run.say(f"stage 2: pivoting (depth {inv.settings.depth}, fan-out {inv.settings.fanout}, "
            f"min path weight {inv.settings.min_weight})")
    run.pivot()
    run.enrich_related()

    # Stage 3: what are those nodes doing?
    run.say("stage 3: assessing roles and clustering")
    assess.assess_nodes(inv.graph, inv.enrichments)
    inv.clusters = assess.clusters(inv.graph)

    # Stage 5: who might be behind it?
    if kb is not None:
        from .summary import summarize
        run.say("stage 5: attribution")
        inv.summaries = summarize(inv, Attributor(kb))
    return inv
