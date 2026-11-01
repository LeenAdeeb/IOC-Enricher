import pytest

from ioc_enricher.attribution import Attributor, load_kb
from ioc_enricher.cache import Cache
from ioc_enricher.i2a import report as i2a_report
from ioc_enricher.i2a.graph import Graph
from ioc_enricher.i2a.guards import is_dynamic_dns, is_mega_domain, shared_asn_name
from ioc_enricher.i2a.investigate import Settings, investigate
from ioc_enricher.i2a.pivots import DemoPivot
from ioc_enricher.i2a.pivots.base import PivotProvider, PivotResult, Relation
from ioc_enricher.ioc import classify
from ioc_enricher.models import Enrichment, ProviderResult
from ioc_enricher.providers import build_providers


def test_guards():
    assert is_mega_domain("cdn.google.com") and not is_mega_domain("evil-update.example")
    assert is_dynamic_dns("c2.duckdns.org") and not is_dynamic_dns("duckdns.org.evil.com")
    assert shared_asn_name("AS13335") == "Cloudflare" and shared_asn_name(64496) is None


def test_graph_edge_merge_and_evidence_validation():
    g = Graph()
    a, b = g.add_node("ip", "1.2.3.4"), g.add_node("domain", "x.example")
    g.add_edge(a, b, "hosts", "observed", "src", 0.4, "2026-01-01", "2026-01-02")
    g.add_edge(a, b, "hosts", "observed", "src", 0.6, "2025-12-01", "2026-03-01")
    assert len(g.edges) == 1 and g.edges[0].weight == 0.6
    assert (g.edges[0].first_seen, g.edges[0].last_seen) == ("2025-12-01", "2026-03-01")
    with pytest.raises(AssertionError):
        g.add_edge(a, b, "x", "guess", "src")


def demo_run(seeds, **kw):
    cache = Cache(None)
    provs, _ = build_providers(cache, demo=True)
    return investigate([classify(s) for s in seeds], provs, [DemoPivot(None, cache)],
                       Settings(allow_private=True, **kw), kb=load_kb())


def test_demo_investigation_finds_cluster_and_attribution():
    inv = demo_run(["198.51.100.23"])
    ids = set(inv.graph.nodes)
    assert {"domain:update-check.example.com", "certificate:crtsh:900001", "domain:mail-relay.example.org"} <= ids
    s = inv.summaries[0]
    assert s["who"]["top"]["name"] == "APT28" and s["who"]["top"]["confidence_label"] == "High"
    dims = s["who"]["top"]["dimensions"]
    assert dims["victimology"] is None and dims["operational"] is None  # honestly "not assessed"
    assert inv.clusters and "198.51.100.23" in inv.clusters[0]["seeds"]


def test_shared_hosting_guard_keeps_graph_small():
    inv = demo_run(["192.0.2.150"])
    node = inv.graph.node("ip", "192.0.2.150")
    assert node.guarded and "60 domains" in node.guarded
    assert not [n for n in inv.graph.nodes.values() if n.value.startswith("shop")]
    assert any(r["role"] == "shared-infrastructure" for r in node.roles)


def test_depth_and_node_caps():
    assert "ip:192.0.2.99" not in demo_run(["198.51.100.23"], depth=1).graph.nodes
    assert len(demo_run(["198.51.100.23"], max_nodes=8).graph.nodes) <= 9


class Recorder(PivotProvider):
    name = "rec"
    needs_key = False
    supported_kinds = {"ip", "domain"}

    def __init__(self):
        super().__init__(None, Cache(None))
        self.calls = []

    def _pivot(self, kind, value):
        self.calls.append(value)
        return PivotResult([Relation("ip", value, "hosts", "domain", "a.example.org", "observed", "rec", 0.6)])


def test_private_seed_is_never_sent_to_external_sources():
    rec = Recorder()
    investigate([classify("10.0.0.5"), classify("8.8.4.4")], [], [rec], Settings(), kb=load_kb())
    assert "10.0.0.5" not in rec.calls and "8.8.4.4" in rec.calls


def test_low_weight_nodes_are_shown_but_not_expanded():
    rec = Recorder()
    inv = investigate([classify("8.8.4.4")], [], [rec], Settings(min_weight=0.9), kb=load_kb())
    # the seed (weight 1.0) expands; its child (weight 0.6 < 0.9) is shown on the graph but never expanded
    assert rec.calls == ["8.8.4.4"] and inv.graph.node("domain", "a.example.org")
    rec2 = Recorder()
    investigate([classify("8.8.4.4")], [], [rec2], Settings(min_weight=0.5, depth=3), kb=load_kb())
    assert "8.8.4.4" in rec2.calls and "a.example.org" in rec2.calls


# -- attribution dimensions ------------------------------------------------------------
KB = {"meta": {}, "groups": [{
    "id": "G1", "name": "APT-Alpha", "aliases": [], "country": "XX", "description": "", "url": None,
    "software": [{"name": "RareOne", "aliases": []}, {"name": "RareTwo", "aliases": []}], "techniques": ["T1566"]},
    {"id": "G2", "name": "APT-Beta", "aliases": [], "country": None, "description": "", "url": None,
     "software": [{"name": "Other", "aliases": []}], "techniques": []}]}


def enr(value, **kw):
    e = Enrichment(classify(value))
    e.results.append(ProviderResult("t", **{k: set(v) for k, v in kw.items()}))
    return e


def test_single_dimension_cannot_reach_high():
    c = Attributor(KB).attribute([enr("1.2.3.4", malware={"RareOne", "RareTwo"}, tags={"apt-alpha"})])[0]
    assert c.label == "Moderate" and "single dimension" in c.capped_reason


def test_two_dimensions_reach_high():
    c = Attributor(KB).attribute([enr("1.2.3.4", malware={"RareOne", "RareTwo"}, tags={"apt-alpha"},
                                      techniques={"T1566"})])[0]
    assert c.label == "High" and "not definitive" not in c.statement(None)
    assert "insufficient to establish definitive attribution" in c.statement(None)


def test_label_on_distant_infrastructure_is_weak():
    seed, far = enr("1.2.3.4", tags={"x"}), enr("evil.example.com", tags={"apt-alpha"})
    cands = Attributor(KB).attribute([seed, far], weights={"1.2.3.4": 1.0, "evil.example.com": 0.2}, seeds={"1.2.3.4"})
    assert cands[0].label == "Low"


# -- report ------------------------------------------------------------------------------
def test_i2a_html_escapes_hostile_data(tmp_path):
    cache = Cache(None)
    provs, _ = build_providers(cache, demo=True)
    inv = investigate([classify("198.51.100.23")], provs, [DemoPivot(None, cache)], Settings(allow_private=True), kb=load_kb())
    node = inv.graph.node("ip", "198.51.100.23")
    node.attrs["note"] = "</script><script>alert(1)</script><img src=x onerror=alert(2)>"
    inv.summaries[0]["what"]["provider_results"]["evil"] = "<b onmouseover=alert(3)>x</b>"
    rep = i2a_report.build_json(inv, {"mode": "test"})
    i2a_report.write_html(inv, rep, str(tmp_path / "r.html"))
    html = (tmp_path / "r.html").read_text()
    assert "</script><script>alert(1)" not in html and "<img src=x" not in html and "<b onmouseover" not in html
    assert "\\u003c/script\\u003e" in html
    i2a_report.write_json(rep, str(tmp_path / "r.json"))


def test_url_and_email_seeds_pivot_through_their_host():
    rec = Recorder()
    inv = investigate([classify("hxxp://login-update[.]example[.]org/a.php"), classify("hr@payroll-update.example.net")],
                      [], [rec], Settings(depth=1), kb=load_kb())
    assert "login-update.example.org" in rec.calls and "payroll-update.example.net" in rec.calls
    assert inv.graph.node("domain", "login-update.example.org").path_weight == 0.9


def test_well_known_host_of_url_seed_is_ignored():
    rec = Recorder()
    investigate([classify("https://www.google.com/search?q=x")], [], [rec], Settings(), kb=load_kb())
    assert rec.calls == []


class CdnPivot(Recorder):
    def _pivot(self, kind, value):
        res = super()._pivot(kind, value)
        if value == "a.example.org":
            res.node_attrs["asn"] = 13335
        return res


def test_cdn_asn_node_is_guarded_and_not_expanded():
    rec = CdnPivot()
    inv = investigate([classify("8.8.4.4")], [], [rec], Settings(depth=3), kb=load_kb())
    # a.example.org is a domain; give it a CDN ASN through attrs after its own pivot
    assert "a.example.org" in rec.calls
    n = inv.graph.node("domain", "a.example.org")
    assert n.guarded and "Cloudflare" in n.guarded
