"""Reputation providers: VirusTotal, AbuseIPDB, Shodan."""
from __future__ import annotations

import base64
from urllib.parse import quote

from ..models import IOC, ProviderResult
from .base import Provider


class VirusTotal(Provider):
    name = "virustotal"
    env_var = "VT_API_KEY"
    supported = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    min_interval = 15.5  # free tier: 4 requests / minute
    throttle_key = "virustotal"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        if ioc.type in ("ipv4", "ipv6"):
            path, ident = "ip_addresses", ioc.value
            gui = f"https://www.virustotal.com/gui/ip-address/{ioc.value}"
        elif ioc.type == "domain":
            path, ident = "domains", ioc.value
            gui = f"https://www.virustotal.com/gui/domain/{ioc.value}"
        elif ioc.type == "url":
            path = "urls"
            ident = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            gui = f"https://www.virustotal.com/gui/url/{ident}"
        else:
            path, ident = "files", ioc.value
            gui = f"https://www.virustotal.com/gui/file/{ioc.value}"

        r = self._request(
            "GET",
            f"https://www.virustotal.com/api/v3/{path}/{ident}",
            headers={"x-apikey": self.api_key},
        )
        if r.status_code == 404:
            return ProviderResult(self.name, found=False)
        r.raise_for_status()
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats") or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        # Only engines that actually returned a verdict count (type-unsupported,
        # timeouts and failures would otherwise dilute the ratio).
        total = mal + sus + stats.get("harmless", 0) + stats.get("undetected", 0)

        if total == 0:  # no usable analysis: report "unknown", never "clean"
            return ProviderResult(self.name, found=True, malicious_score=None, link=gui,
                                  native="no analysis results available",
                                  context={"note": "no analysis results available"})

        score = round(100 * (mal + 0.5 * sus) / total * 2)
        if mal >= 5:
            score = max(score, 70)  # several engines agree: malicious
        elif mal >= 1:
            score = max(score, 30)  # any detection: at least suspicious

        res = ProviderResult(self.name, found=True, link=gui)
        res.malicious_score = min(100, score)
        res.native = f"{mal}/{total} engines malicious" + (f", {sus} suspicious" if sus else "")
        res.tags |= set(a.get("tags", []))
        ptc = a.get("popular_threat_classification") or {}
        for item in ptc.get("popular_threat_name", []):
            res.malware.add(item["value"])
        label = ptc.get("suggested_threat_label")
        if label:
            res.tags.add(label)
        res.context = {
            "detections": f"{mal}/{total}",
            "suspicious": sus,
            "reputation": a.get("reputation"),
            "as_owner": a.get("as_owner"),
            "country": a.get("country"),
            "meaningful_name": a.get("meaningful_name"),
            "type_description": a.get("type_description"),
        }
        res.context = {k: v for k, v in res.context.items() if v not in (None, "")}
        return res


class AbuseIPDB(Provider):
    name = "abuseipdb"
    env_var = "ABUSEIPDB_API_KEY"
    supported = {"ipv4", "ipv6"}
    min_interval = 1.0

    def _lookup(self, ioc: IOC) -> ProviderResult:
        r = self._request(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ioc.value, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json()["data"]
        res = ProviderResult(
            self.name,
            found=d.get("totalReports", 0) > 0,
            malicious_score=int(d.get("abuseConfidenceScore", 0)),
            link=f"https://www.abuseipdb.com/check/{ioc.value}",
        )
        res.native = (f"abuse confidence {int(d.get('abuseConfidenceScore', 0))}%, "
                      f"{d.get('totalReports', 0)} reports (90d)")
        res.context = {
            k: v
            for k, v in {
                "reports_90d": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage_type": d.get("usageType"),
                "domain": d.get("domain"),
                "is_tor": d.get("isTor"),
            }.items()
            if v not in (None, "")
        }
        return res


class Shodan(Provider):
    name = "shodan"
    env_var = "SHODAN_API_KEY"
    supported = {"ipv4"}
    min_interval = 1.1

    def _lookup(self, ioc: IOC) -> ProviderResult:
        r = self._request(
            "GET",
            f"https://api.shodan.io/shodan/host/{quote(ioc.value)}",
            params={"key": self.api_key},
        )
        if r.status_code == 404:
            return ProviderResult(self.name, found=False)
        r.raise_for_status()
        d = r.json()
        res = ProviderResult(self.name, found=True, link=f"https://www.shodan.io/host/{ioc.value}")
        res.tags |= set(d.get("tags", []))
        vulns = sorted(d.get("vulns", []) or [])
        products = sorted({s.get("product") for s in d.get("data", []) if s.get("product")})
        ports = sorted(d.get("ports", []))
        res.native = (f"ports {','.join(map(str, ports[:12])) or '-'}; {len(vulns)} CVE(s); "
                      f"org {d.get('org') or '-'} (context only, no score)")
        res.context = {
            k: v
            for k, v in {
                "org": d.get("org"),
                "asn": d.get("asn"),
                "country": d.get("country_code"),
                "ports": sorted(d.get("ports", [])),
                "hostnames": d.get("hostnames"),
                "products": products,
                "cves": vulns[:15],
            }.items()
            if v not in (None, "", [])
        }
        return res
