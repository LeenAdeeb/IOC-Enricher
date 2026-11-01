import pytest
import responses

from ioc_enricher.cache import Cache
from ioc_enricher.engine import verdict_for
from ioc_enricher.ioc import classify
from ioc_enricher.models import Enrichment
from ioc_enricher.providers.reputation import AbuseIPDB, VirusTotal
from ioc_enricher.providers.threatintel import OTX, MalwareBazaar

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def prov(cls):
    p = cls("key", Cache(None))
    p.min_interval = 0  # no sleeping in tests
    return p


def vt_body(**stats):
    return {"data": {"attributes": {"last_analysis_stats": stats, "tags": ["eicar"],
            "popular_threat_classification": {"popular_threat_name": [{"value": "eicar", "count": 9}]}}}}


@responses.activate
def test_vt_eicar_is_malicious_with_native_text():
    responses.get(f"https://www.virustotal.com/api/v3/files/{EICAR}",
                  json=vt_body(malicious=62, suspicious=1, harmless=0, undetected=9, **{"type-unsupported": 14}))
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert r.ok and r.found and r.malicious_score == 100
    assert r.native == "62/72 engines malicious, 1 suspicious"
    assert "eicar" in r.malware


@responses.activate
def test_vt_low_detections_not_clean():
    responses.get(f"https://www.virustotal.com/api/v3/files/{EICAR}",
                  json=vt_body(malicious=6, suspicious=0, harmless=60, undetected=4))
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert r.malicious_score >= 70  # 6 engines agree


@responses.activate
def test_vt_missing_stats_is_unknown_not_clean():
    responses.get(f"https://www.virustotal.com/api/v3/files/{EICAR}", json={"data": {"attributes": {}}})
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert r.malicious_score is None
    enr = Enrichment(classify(EICAR), [r])
    assert verdict_for(enr)[0] == "unknown"


@pytest.mark.parametrize("status,needle", [(401, "auth"), (403, "auth"), (429, "rate")])
@responses.activate
def test_vt_http_errors_return_ok_false(status, needle):
    responses.get(f"https://www.virustotal.com/api/v3/files/{EICAR}", status=status)
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert not r.ok and needle in r.error


@responses.activate
def test_vt_404_and_malformed_json():
    responses.get(f"https://www.virustotal.com/api/v3/files/{EICAR}", status=404)
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert r.ok and not r.found and r.native == "not found"
    responses.replace(responses.GET, f"https://www.virustotal.com/api/v3/files/{EICAR}", body="not json")
    r = prov(VirusTotal).lookup(classify(EICAR))
    assert not r.ok and r.error


@responses.activate
def test_abuseipdb_native_text():
    responses.get("https://api.abuseipdb.com/api/v2/check", json={"data": {
        "abuseConfidenceScore": 87, "totalReports": 214, "countryCode": "NL", "isp": "X"}})
    r = prov(AbuseIPDB).lookup(classify("8.8.4.4"))
    assert r.malicious_score == 87 and r.native == "abuse confidence 87%, 214 reports (90d)"


@responses.activate
def test_otx_pulses_actors_and_techniques():
    responses.get(url=__import__("re").compile(r"https://otx\.alienvault\.com/api/v1/indicators/IPv4/.*"), json={
        "pulse_info": {"pulses": [{"name": "Sofacy wave", "adversary": "APT28", "tags": ["sofacy"],
                       "malware_families": [{"display_name": "Zebrocy"}],
                       "attack_ids": [{"id": "T1566.001"}]}]}})
    r = prov(OTX).lookup(classify("8.8.4.4"))
    assert r.native == "1 pulse(s)" and "APT28" in r.actors and "T1566.001" in r.techniques


@responses.activate
def test_malwarebazaar_hit_and_miss():
    responses.post("https://mb-api.abuse.ch/api/v1/", json={"query_status": "ok", "data": [
        {"signature": "AgentTesla", "sha256_hash": EICAR, "tags": ["exe"]}]})
    r = prov(MalwareBazaar).lookup(classify(EICAR))
    assert r.native == 'found: signature "AgentTesla"' and r.malicious_score == 95
    responses.replace(responses.POST, "https://mb-api.abuse.ch/api/v1/", json={"query_status": "hash_not_found"})
    assert not prov(MalwareBazaar).lookup(classify(EICAR)).found


def test_standalone_score_basis():
    from ioc_enricher.models import ProviderResult
    enr = Enrichment(classify("8.8.4.4"), [
        ProviderResult("virustotal", malicious_score=100), ProviderResult("otx", malicious_score=60),
        ProviderResult("shodan", malicious_score=None)])
    verdict, risk, basis = verdict_for(enr)
    assert (verdict, risk) == ("malicious", 100)
    assert basis["contributors"] == {"virustotal": 100, "otx": 60}
    assert "virustotal" in basis["basis"] and basis["agreement_bonus"] == 5
