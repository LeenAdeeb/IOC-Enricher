"""Orchestration: enrich IOCs, derive verdicts, correlate across indicators."""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

from .ioc import is_public_ip
from .models import IOC, Enrichment
from .providers.base import Provider


MALICIOUS_AT = 70
SUSPICIOUS_AT = 30


def verdict_for(enr: Enrichment) -> tuple[str, int, dict]:
    """The IOC-Enricher score: strongest provider signal + an agreement bonus.

    Each provider's own result is displayed untouched; only here are they mapped to a
    common 0-100 scale (`malicious_score`) so they can be compared. Providers that
    errored, found nothing, or give context only (Shodan) contribute no score.
    """
    contrib = {r.provider: r.malicious_score for r in enr.results
               if r.ok and r.malicious_score is not None}
    if not contrib:
        return "unknown", 0, {"basis": "no provider returned a usable score", "contributors": {}}
    top_provider = max(contrib, key=contrib.get)
    top = contrib[top_provider]
    hot = sum(1 for s in contrib.values() if s >= 50)
    bonus = 5 * (hot - 1) if hot > 1 else 0
    risk = min(100, top + bonus)
    verdict = "malicious" if risk >= MALICIOUS_AT else "suspicious" if risk >= SUSPICIOUS_AT else "clean"
    basis = {
        "basis": f"highest signal = {top_provider} ({top})" + (f" + {bonus} agreement ({hot} sources >= 50)" if bonus else ""),
        "contributors": contrib,
        "agreement_bonus": bonus,
    }
    return verdict, risk, basis


def enrich(iocs: list[IOC], providers: list[Provider],
           progress: Callable[[str], None] | None = None) -> list[Enrichment]:
    out: list[Enrichment] = []
    for ioc in iocs:
        enr = Enrichment(ioc)
        if ioc.type in ("ipv4", "ipv6") and not is_public_ip(ioc.value) and not _demo(providers):
            enr.verdict = "skipped (non-public IP)"
            out.append(enr)
            continue
        enr.not_applicable = [p.name for p in providers if not p.supports(ioc)]
        for p in providers:
            if p.supports(ioc):
                if progress:
                    progress(f"{ioc.value} -> {p.name}")
                enr.results.append(p.lookup(ioc))
        enr.verdict, enr.risk_score, enr.basis = verdict_for(enr)
        out.append(enr)
    return out


def _demo(providers: list[Provider]) -> bool:
    return any(p.name == "demo" for p in providers)


def correlate(enrichments: list[Enrichment], min_size: int = 2) -> list[dict]:
    """Cluster IOCs that share a malware family, actor name or ATT&CK technique.

    Shared infrastructure indicators are the backbone of campaign tracking: two
    domains and a hash that all resolve to the same family are likely one operation.
    """
    pivots: dict[tuple[str, str], set[str]] = defaultdict(set)
    for e in enrichments:
        for fam in e.merged("malware"):
            pivots[("malware", fam)].add(e.ioc.value)
        for a in e.merged("actors"):
            pivots[("actor", a)].add(e.ioc.value)
        for r in e.results:
            for k in ("asn", "org"):
                v = r.context.get(k)
                if v:
                    pivots[(k, str(v))].add(e.ioc.value)
    clusters = [
        {"pivot_type": t, "pivot": v, "iocs": sorted(members)}
        for (t, v), members in pivots.items()
        if len(members) >= min_size
    ]
    clusters.sort(key=lambda c: (-len(c["iocs"]), c["pivot_type"], c["pivot"]))
    return clusters
