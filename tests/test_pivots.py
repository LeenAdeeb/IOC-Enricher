import re

import responses

from ioc_enricher.cache import Cache
from ioc_enricher.i2a.pivots.scanners import Censys, Fofa
from ioc_enricher.i2a.pivots.vt import VTRelations
from ioc_enricher.i2a.pivots.web import CrtSh, UrlScan


def mk(cls, key="k"):
    p = cls(key, Cache(None))
    p.min_interval = 0
    return p


@responses.activate
def test_crtsh_certificates_and_sans():
    big = "\n".join(f"s{i}.example.org" for i in range(60))
    responses.get("https://crt.sh/", json=[
        {"id": 5, "issuer_name": "CA", "serial_number": "01", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00",
         "name_value": "evil.example.com\n*.evil.example.com\nsibling.example.net\nwww.google.com"},
        {"id": 5, "name_value": "dup"},  # duplicate id ignored
        {"id": 6, "name_value": big, "not_before": "2026-02-01T00:00:00"},  # multi-tenant: SANs skipped
    ])
    res = mk(CrtSh, None).pivot("domain", "evil.example.com")
    rels = {(r.rel, r.dst_value) for r in res.relations}
    assert ("presents", "crtsh:5") in rels and ("presents", "crtsh:6") in rels
    assert ("covers", "sibling.example.net") in rels
    assert not any(v == "www.google.com" or v.startswith("s1.") for _, v in rels)  # mega + multi-tenant skipped
    assert res.node_attrs["multi_tenant_certs_skipped"] == 1


@responses.activate
def test_crtsh_failures_do_not_raise():
    responses.get("https://crt.sh/", status=503)
    assert "503" in mk(CrtSh, None).pivot("domain", "x.example.com").error
    responses.replace(responses.GET, "https://crt.sh/", body="<html>busy</html>")
    assert mk(CrtSh, None).pivot("domain", "x.example.com").error


@responses.activate
def test_urlscan_domain_to_ip_and_contacted_domains():
    responses.get("https://urlscan.io/api/v1/search/", json={"results": [
        {"_id": "abc", "task": {"time": "2026-05-01T10:00:00Z"}, "page": {"domain": "evil.example.com", "ip": "203.0.113.9", "asn": "AS64496"}},
        {"_id": "def", "task": {"time": "2026-06-01T10:00:00Z"}, "page": {"domain": "evil.example.com", "ip": "203.0.113.9"}}]})
    responses.get(re.compile(r"https://urlscan\.io/api/v1/result/.*"), json={
        "task": {"time": "2026-06-01T10:00:00Z"}, "page": {"domain": "landing.example.net", "redirected": "client"},
        "lists": {"domains": ["evil.example.com", "tracker.example.org", "fonts.googleapis.com"]}})
    res = mk(UrlScan, None).pivot("domain", "evil.example.com")
    got = {(r.rel, r.dst_value) for r in res.relations}
    assert ("resolves-to", "203.0.113.9") in got and ("redirects-to", "landing.example.net") in got
    assert ("loads-resource-from", "tracker.example.org") in got
    assert not any("googleapis" in v for _, v in got)
    ip_rel = next(r for r in res.relations if r.rel == "resolves-to")
    assert (ip_rel.first_seen, ip_rel.last_seen) == ("2026-05-01", "2026-06-01")


@responses.activate
def test_urlscan_ip_pivot_puts_asn_on_the_ip():
    responses.get("https://urlscan.io/api/v1/search/", json={"results": [
        {"_id": "a", "task": {"time": "2026-05-01T00:00:00Z"}, "page": {"domain": "bad.example.org", "ip": "203.0.113.9", "asn": "AS64496"}}]})
    res = mk(UrlScan, None).pivot("ip", "203.0.113.9")
    assert res.node_attrs.get("asn") == "AS64496"
    assert res.relations[0].dst_value == "bad.example.org" and not res.relations[0].dst_attrs


@responses.activate
def test_vt_relations_ip():
    responses.get("https://www.virustotal.com/api/v3/ip_addresses/203.0.113.9/resolutions", json={"data": [
        {"attributes": {"host_name": "Evil.Example.com", "date": 1780000000}}]})
    responses.get("https://www.virustotal.com/api/v3/ip_addresses/203.0.113.9/communicating_files", json={"data": [
        {"id": "A" * 64, "attributes": {"last_analysis_stats": {"malicious": 40, "undetected": 20}, "meaningful_name": "x.exe"}},
        {"id": "B" * 64, "attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 60}}}]})  # below threshold
    res = mk(VTRelations).pivot("ip", "203.0.113.9")
    got = {(r.rel, r.src_kind, r.src_value, r.dst_value) for r in res.relations}
    assert ("hosts", "ip", "203.0.113.9", "evil.example.com") in got
    assert sum(r.rel == "communicates-with" for r in res.relations) == 1
    h = next(r for r in res.relations if r.rel == "communicates-with")
    assert h.src_kind == "hash" and h.dst_attrs["vt_detections"] == "40/60"


@responses.activate
def test_vt_relations_auth_error_is_reported_not_raised():
    responses.get(re.compile(r"https://www\.virustotal\.com/api/v3/.*"), status=401)
    assert "auth" in mk(VTRelations).pivot("domain", "x.example.com").error


@responses.activate
def test_censys_host_parsing_and_cert_pivot():
    responses.get("https://api.platform.censys.io/v3/global/asset/host/203.0.113.9", json={"result": {"resource": {
        "services": [{"port": 443, "protocol": "HTTPS", "cert": {"fingerprint_sha256": "AB" * 32}}, {"port": 22, "protocol": "SSH"}],
        "autonomous_system": {"asn": 64496, "name": "DEMO-NET"}, "dns": {"reverse_dns": {"names": ["c2.example.org"]}}}}})
    res = mk(Censys).pivot("ip", "203.0.113.9")
    got = {(r.rel, r.dst_kind, r.dst_value) for r in res.relations}
    assert ("presents", "certificate", "sha256:" + "ab" * 32) in got and ("hosts", "domain", "c2.example.org") in got
    assert res.node_attrs["ports"] == [22, 443]
    responses.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": [
        {"host_v1": {"resource": {"ip": "198.51.100.7"}}}, {"x": [{"ip": "not-an-ip"}]}]}})
    res = mk(Censys).pivot("certificate", "sha256:" + "ab" * 32)
    assert [r.src_value for r in res.relations] == ["198.51.100.7"]


@responses.activate
def test_fofa_fallback_when_extended_fields_unavailable():
    calls = []

    def cb(request):
        calls.append(request.url)
        import json
        if "jarm" in request.url or "jarm%2C" in request.url:
            return 200, {}, json.dumps({"error": True, "errmsg": "field not permitted"})
        return 200, {}, json.dumps({"error": False, "results": [["x.example.org:443", "203.0.113.9", "443", "x.example.org", "T", "nginx", "https"]]})
    responses.add_callback(responses.GET, "https://fofa.info/api/v1/search/all", callback=cb)
    res = mk(Fofa).pivot("ip", "203.0.113.9")
    assert len(calls) == 2 and res.error is None
    assert ("hosts", "x.example.org") in {(r.rel, r.dst_value) for r in res.relations}
    assert res.node_attrs["ports"] == [443]
