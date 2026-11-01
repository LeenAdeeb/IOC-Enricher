"""Offline demo pivot source with a SYNTHETIC infrastructure network.

Everything uses reserved documentation ranges (RFC 5737) and example TLDs. It exists to show
the investigation workflow end to end without API keys; it describes no real infrastructure.
"""
from __future__ import annotations

from .base import PivotProvider, PivotResult, Relation

SRC = "demo"
CERT = "crtsh:900001"


def _r(sk, sv, rel, dk, dv, w=0.6, ev="observed", first="2026-03-02", last="2026-09-14", detail="", attrs=None):
    return Relation(sk, sv, rel, dk, dv, ev, SRC, w, first, last, detail or "synthetic demo data", None, attrs or {})


def _build() -> dict[tuple[str, str], PivotResult]:
    net: dict[tuple[str, str], PivotResult] = {}

    def put(kind, value, rels, attrs=None):
        net[(kind, value)] = PivotResult(rels, attrs or {})

    cert_attrs = {"issuer": "Demo CA", "serial": "0xD3M0", "not_before": "2026-03-01", "not_after": "2026-06-01",
                  "san_count": 3, "source": "demo"}
    # seed IP -> domains
    put("ip", "198.51.100.23", [
        _r("ip", "198.51.100.23", "hosts", "domain", "update-check.example.com", 0.6),
        _r("ip", "198.51.100.23", "hosts", "domain", "cdn-sync.example.net", 0.6),
    ], {"ports": [80, 443, 8443], "asn": 64496, "as_name": "DEMO-HOSTING (synthetic)"})
    # domain -> certificate (shared) -> sibling domains, plus historical IP
    put("domain", "update-check.example.com", [
        _r("domain", "update-check.example.com", "presents", "certificate", CERT, 0.7, attrs=cert_attrs),
        _r("certificate", CERT, "covers", "domain", "cdn-sync.example.net", 0.7),
        _r("certificate", CERT, "covers", "domain", "mail-relay.example.org", 0.7),
        _r("domain", "update-check.example.com", "resolves-to", "ip", "203.0.113.77", 0.6, last="2026-04-02"),
        _r("domain", "update-check.example.com", "redirects-to", "domain", "cdn-sync.example.net", 0.6),
    ])
    put("domain", "cdn-sync.example.net", [
        _r("domain", "cdn-sync.example.net", "resolves-to", "ip", "192.0.2.99", 0.6),
    ])
    put("domain", "mail-relay.example.org", [
        _r("domain", "mail-relay.example.org", "resolves-to", "ip", "192.0.2.99", 0.6),
    ])
    # Cobalt Strike IP sits on shared hosting: 60 unrelated domains -> guard rail must trigger
    put("ip", "192.0.2.150", [
        _r("ip", "192.0.2.150", "hosts", "domain", f"shop{i}.example.com", 0.6) for i in range(60)
    ], {"ports": [80, 443], "asn": 64511, "as_name": "SHARED-WEB (synthetic)"})
    # sample -> C2 domain
    put("hash", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", [
        _r("hash", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "communicates-with",
           "domain", "crypto-wallet-update.example.org", 0.7, detail="contacted during sandbox run (synthetic)"),
    ])
    put("domain", "crypto-wallet-update.example.org", [
        _r("domain", "crypto-wallet-update.example.org", "resolves-to", "ip", "203.0.113.200", 0.6),
    ])
    return net


_NET = _build()


class DemoPivot(PivotProvider):
    name = "demo-pivot"
    needs_key = False
    supported_kinds = {"ip", "domain", "hash", "certificate"}

    def _pivot(self, kind: str, value: str) -> PivotResult:
        res = _NET.get((kind, value))
        if res is None:
            return PivotResult()
        # copy so graph code can't mutate shared fixtures
        return PivotResult(list(res.relations), dict(res.node_attrs))
