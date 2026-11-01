from ioc_enricher.attribution import Attributor, load_kb
from ioc_enricher.cache import Cache
from ioc_enricher.engine import enrich
from ioc_enricher.ioc import classify
from ioc_enricher.providers.demo import DemoProvider
from ioc_enricher.report import build_report, write_html, write_json


def test_end_to_end_demo_and_xss_escaping(tmp_path):
    iocs = [classify(x) for x in ["198.51.100.23", "203.0.113.77"]]
    es = enrich(iocs, [DemoProvider(None, Cache(None))])
    # hostile provider data must be escaped in HTML
    es[0].results[0].malware.add("<script>alert(1)</script>")
    cands = Attributor(load_kb()).attribute(es)
    assert cands and cands[0].group["name"] == "APT28"
    rep = build_report(es, cands, [], {"mode": "test"})
    write_html(rep, str(tmp_path / "r.html"))
    write_json(rep, str(tmp_path / "r.json"))
    html = (tmp_path / "r.html").read_text()
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
