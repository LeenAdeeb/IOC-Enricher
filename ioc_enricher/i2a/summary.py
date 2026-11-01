"""Per-seed intelligence summary: the three questions plus the analyst report table.

1. What is this IOC?          2. What is it connected to?          3. Who might be behind it?
"""
from __future__ import annotations

from ..attribution.scorer import Attributor, Candidate
from ..ioc import defang
from .graph import Graph, Node
from .pivots.base import kind_of

SKIP_KINDS = {"malware", "campaign", "technique", "asn", "actor"}


def _neighbors(g: Graph, node_id: str):
    for e in g.edges:
        if e.src == node_id:
            yield e, g.nodes[e.dst]
        elif e.dst == node_id:
            yield e, g.nodes[e.src]


def _earliest(g: Graph, nodes: list[Node], seed: Node, enr) -> dict | None:
    cands: list[tuple[str, str]] = []
    if enr:
        for r in enr.results:
            v = r.context.get("first_seen")
            if v:
                cands.append((str(v)[:10], r.provider))
    ids = {n.id for n in nodes}
    for e in g.edges:
        if e.first_seen and (e.src in ids or e.dst in ids) and e.evidence == "observed":
            cands.append((e.first_seen[:10], e.source))
    if not cands:
        return None
    date, src = min(cands)
    return {"date": date, "source": src}


def _related(g: Graph, seed: Node, members: list[Node]) -> list[dict]:
    ids = {n.id for n in members} | {seed.id}
    direct = {n.id for _, n in _neighbors(g, seed.id)}
    out = []
    for n in g.nodes.values():
        if n.id == seed.id or n.kind in SKIP_KINDS or (n.id not in ids and n.id not in direct):
            continue
        best = None
        for e, other in _neighbors(g, n.id):
            if other.id in ids and (best is None or e.weight > best.weight):
                best = e
        out.append({"kind": n.kind, "value": n.value, "path_weight": round(n.path_weight, 2),
                    "via": f"{best.rel} ({best.evidence}, {best.source})" if best else "",
                    "link_weight": round(best.weight, 2) if best else None,
                    "verdict": n.attrs.get("verdict"), "guarded": n.guarded,
                    "roles": [r["role"] for r in n.roles]})
    out.sort(key=lambda r: -r["path_weight"])
    return out


def _actions(seed: Node, enr, related: list[dict], cluster: dict | None, g: Graph, cands: list[Candidate]) -> list[str]:
    acts = []
    verdict = enr.verdict if enr else "unknown"
    if verdict in ("malicious", "suspicious"):
        acts.append(f"Alert/block on the seed {defang(seed.value)} ({verdict}); search proxy, DNS and EDR logs for prior contact.")
    c2 = [r for r in related if "c2-candidate" in r["roles"]]
    if c2:
        acts.append("Hunt for and consider blocking likely C2 nodes: " + ", ".join(defang(r["value"]) for r in c2[:8]) + ".")
    certs = [r["value"] for r in related if r["kind"] == "certificate"]
    if certs:
        acts.append("Hunt TLS logs (JA3/JA4, certificate transparency) for the shared certificate(s): " + ", ".join(certs[:4]) + ".")
    hashes = [r["value"] for r in related if r["kind"] == "hash"]
    if hashes or seed.kind == "hash":
        acts.append("Add the associated file hash(es) to EDR blocklists and run a retro-hunt.")
    guarded = [r for r in related if r["guarded"]] + ([{"value": seed.value}] if seed.guarded else [])
    if guarded:
        acts.append("Do not block shared infrastructure by IP (" + ", ".join(defang(r["value"]) for r in guarded[:4]) +
                    "); block by domain or URL instead, since unrelated sites share it.")
    weak = [r for r in related if (r["link_weight"] or 0) < 0.4 and not r["guarded"]]
    if weak:
        acts.append(f"Treat the {len(weak)} weakly linked node(s) as hunting leads only; do not auto-block them.")
    if cands:
        techs = sorted(enr.merged("techniques")) if enr else []
        if techs:
            acts.append("Review detection coverage for reported ATT&CK techniques: " + ", ".join(techs[:8]) + ".")
    acts.append("Re-run this investigation periodically: infrastructure and attribution assessments change as new data appears.")
    return acts


def summarize(inv, attributor: Attributor, top: int = 3) -> list[dict]:
    g = inv.graph
    cluster_of = {m: c for c in inv.clusters for m in c["members"]}
    cache: dict = {}
    out = []
    for seed_ioc in inv.seeds:
        seed = g.node(kind_of(seed_ioc.type), seed_ioc.value)
        enr = inv.enrichments.get(seed_ioc.value)
        if seed is None:
            continue
        cluster = cluster_of.get(seed.id)
        members = [g.nodes[m] for m in cluster["members"]] if cluster else [seed]
        key = cluster["id"] if cluster else f"solo:{seed.id}"
        if key not in cache:
            ens = [inv.enrichments[n.value] for n in members if n.value in inv.enrichments]
            weights = {n.value: (1.0 if n.seed else n.path_weight) for n in members}
            cache[key] = attributor.attribute(ens, top=5, weights=weights, seeds={n.value for n in members if n.seed})
        cands: list[Candidate] = cache[key]
        related = _related(g, seed, members)
        guards = sorted({f"{defang(r['value'])}: {r['guarded']}" for r in related if r["guarded"]}
                        | ({f"{defang(seed.value)} (seed): {seed.guarded}"} if seed.guarded else set()))
        counts: dict[str, int] = {}
        for r in related:
            counts[r["kind"]] = counts.get(r["kind"], 0) + 1
        groups: dict[str, list] = {}
        for r in related:
            groups.setdefault(r["kind"], [])
            if len(groups[r["kind"]]) < 8:
                groups[r["kind"]].append(r)

        what = {
            "verdict": enr.verdict if enr else "unknown", "score": enr.risk_score if enr else 0,
            "basis": enr.basis.get("basis") if enr else None,
            "provider_results": {r.provider: (r.native if r.ok else f"ERROR: {r.error}") for r in enr.results} if enr else {},
            "malware": sorted(enr.merged("malware")) if enr else [],
            "tags": sorted(enr.merged("tags"))[:12] if enr else [],
            "roles": seed.roles, "first_observed": _earliest(g, members, seed, enr),
        }
        connected = {
            "cluster": {"id": cluster["id"], "size": cluster["size"]} if cluster else None,
            "counts": counts, "related": groups, "guards": guards,
            "c2_candidates": [defang(r["value"]) for r in related if "c2-candidate" in r["roles"]],
        }
        alts = cands[1:]
        who = {
            "top": cands[0].to_dict(alts) if cands else None,
            "candidates": [c.to_dict(cands[:i] + cands[i + 1:]) for i, c in enumerate(cands[:top])],
            "note": ("No actor reached the evidence threshold. An IOC can be malicious without being attributable."
                     if not cands else "Hypotheses only: shared tooling, reused infrastructure and false flags can mislead."),
        }
        c0 = cands[0] if cands else None
        intel = [
            ("Initial IOC", f"{defang(seed.value)} ({seed_ioc.type})"),
            ("Reputation", f"{what['verdict'].title()} (IOC-Enricher score {what['score']}/100)"),
            ("First observed", (f"{what['first_observed']['date']} ({what['first_observed']['source']})"
                                if what["first_observed"] else "not available from the sources used")),
            ("Infrastructure", ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or
             ("not expanded: " + seed.guarded if seed.guarded else "no related infrastructure found")),
            ("C2 assessment", ("; ".join(connected["c2_candidates"][:6]) + " (hypothesis, not confirmed)")
             if connected["c2_candidates"] else "no node met the C2-candidate criteria"),
            ("Malware", ", ".join(sorted({m for n in members if n.value in inv.enrichments
                                          for m in inv.enrichments[n.value].merged('malware')})) or "none reported"),
            ("Campaign", ", ".join(sorted({c for n in members if n.value in inv.enrichments
                                           for r in inv.enrichments[n.value].results
                                           for c in r.context.get('pulse_names', [])[:2]}))[:300] or "none reported"),
            ("ATT&CK", ", ".join(sorted({t for n in members if n.value in inv.enrichments
                                         for t in inv.enrichments[n.value].merged('techniques')})) or "none reported"),
            ("Actor", f"{c0.group['name']} (hypothesis)" if c0 else "no candidate"),
            ("Confidence", f"{c0.label} ({c0.confidence}%)" if c0 else "n/a"),
            ("Evidence", f"{len(c0.evidence)} item(s) across dimensions: " + ", ".join(
                f"{d}={n}" for d, n in c0.dimensions().items() if n) if c0 else "n/a"),
            ("Defensive actions", f"{len(_actions(seed, enr, related, cluster, g, cands))} recommendation(s) below"),
        ]
        out.append({"ioc": seed.value, "type": seed_ioc.type, "what": what, "connected": connected, "who": who,
                    "intel": intel, "actions": _actions(seed, enr, related, cluster, g, cands)})
    return out
