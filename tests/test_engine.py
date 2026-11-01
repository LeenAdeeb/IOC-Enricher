from ioc_enricher.engine import correlate, verdict_for
from ioc_enricher.ioc import classify
from ioc_enricher.models import Enrichment, ProviderResult


def mk(v, score, malware=()):
    e = Enrichment(classify(v))
    e.results.append(ProviderResult("p", malicious_score=score, malware=set(malware)))
    e.verdict, e.risk_score, e.basis = verdict_for(e)
    return e


def test_verdicts():
    assert mk("1.2.3.4", 90).verdict == "malicious"
    assert mk("1.2.3.4", 40).verdict == "suspicious"
    assert mk("1.2.3.4", 0).verdict == "clean"
    assert Enrichment(classify("1.2.3.4")).verdict == "unknown"


def test_correlation_pivots_on_shared_family():
    es = [mk("1.2.3.4", 80, {"Zebrocy"}), mk("evil.com", 80, {"Zebrocy"}), mk("5.6.7.8", 10, {"Other"})]
    cl = correlate(es)
    assert cl[0]["pivot"] == "Zebrocy" and len(cl[0]["iocs"]) == 2
