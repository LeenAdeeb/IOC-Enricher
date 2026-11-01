"""Threat-intel providers: AlienVault OTX and abuse.ch (ThreatFox, URLhaus, MalwareBazaar)."""
from __future__ import annotations

import re
from urllib.parse import quote

from ..models import IOC, ProviderResult
from .base import Provider

_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class OTX(Provider):
    """AlienVault OTX: pulses carry adversary, malware family and ATT&CK IDs."""

    name = "otx"
    env_var = "OTX_API_KEY"
    supported = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    min_interval = 0.5

    _TYPE = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url",
             "md5": "file", "sha1": "file", "sha256": "file"}

    def _lookup(self, ioc: IOC) -> ProviderResult:
        t = self._TYPE[ioc.type]
        r = self._request(
            "GET",
            f"https://otx.alienvault.com/api/v1/indicators/{t}/{quote(ioc.value, safe='')}/general",
            headers={"X-OTX-API-KEY": self.api_key},
        )
        if r.status_code == 404:
            return ProviderResult(self.name, found=False)
        r.raise_for_status()
        d = r.json()
        pulses = d.get("pulse_info", {}).get("pulses", [])
        res = ProviderResult(self.name, found=bool(pulses), link=f"https://otx.alienvault.com/indicator/{t.lower() if t != 'file' else 'file'}/{ioc.value}")
        names = []
        for p in pulses:
            names.append(p.get("name", ""))
            if p.get("adversary"):
                res.actors.add(p["adversary"])
            res.tags |= {x for x in p.get("tags", []) if x}
            for m in p.get("malware_families", []):
                nm = m.get("display_name") if isinstance(m, dict) else m
                if nm:
                    res.malware.add(nm)
            for a in p.get("attack_ids", []):
                aid = a.get("id") if isinstance(a, dict) else a
                if aid and _ATTACK_ID.match(aid):
                    res.techniques.add(aid)
        res.native = f"{len(pulses)} pulse(s)"
        res.context = {
            "pulse_count": len(pulses),
            "pulse_names": names[:8],
            "reputation": d.get("reputation"),
            "country": d.get("country_name"),
            "asn": d.get("asn"),
        }
        res.context = {k: v for k, v in res.context.items() if v not in (None, "", [])}
        # Many pulses == more community attention; weak signal on its own.
        res.malicious_score = min(100, 15 * len(pulses)) if pulses else 0
        return res


class _AbuseCh(Provider):
    needs_key = True  # abuse.ch now requires a (free) Auth-Key for every API
    env_var = "ABUSECH_API_KEY"

    def _hdr(self) -> dict:
        return {"Auth-Key": self.api_key}


class ThreatFox(_AbuseCh):
    name = "threatfox"
    supported = {"ipv4", "domain", "url", "md5", "sha1", "sha256"}
    min_interval = 0.5

    def _lookup(self, ioc: IOC) -> ProviderResult:
        term = ioc.value
        if ioc.type == "ipv4":
            term = ioc.value  # ThreatFox stores ip:port; exact_match=false handles bare IPs
        r = self._request(
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": term, "exact_match": False},
            headers=self._hdr(),
        )
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return ProviderResult(self.name, found=False)
        res = ProviderResult(self.name, found=True, link=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(term)}")
        conf = 0
        for e in d.get("data", []):
            if e.get("malware_printable") and e["malware_printable"] != "Unknown malware":
                res.malware.add(e["malware_printable"])
            for al in (e.get("malware_alias") or "").split(","):
                if al.strip():
                    res.malware.add(al.strip())
            res.tags |= set(e.get("tags") or [])
            conf = max(conf, int(e.get("confidence_level", 0)))
        res.malicious_score = conf
        res.native = (f"{len(d.get('data', []))} entr(ies), confidence {conf}%"
                      + (f", malware: {', '.join(sorted(res.malware)[:3])}" if res.malware else ""))
        res.context = {"entries": len(d.get("data", [])), "threat_type": d["data"][0].get("threat_type_desc")}
        return res


class URLhaus(_AbuseCh):
    name = "urlhaus"
    supported = {"ipv4", "domain", "url", "md5", "sha256"}
    min_interval = 0.5

    def _lookup(self, ioc: IOC) -> ProviderResult:
        if ioc.type == "url":
            ep, data = "url", {"url": ioc.value}
        elif ioc.type in ("ipv4", "domain"):
            ep, data = "host", {"host": ioc.value}
        else:
            ep, data = "payload", {f"{ioc.type}_hash": ioc.value}
        r = self._request("POST", f"https://urlhaus-api.abuse.ch/v1/{ep}/", data=data, headers=self._hdr())
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") not in ("ok", "is_host", "is_url"):
            return ProviderResult(self.name, found=False)
        res = ProviderResult(self.name, found=True, malicious_score=90, native="listed as malware distribution")
        res.link = d.get("urlhaus_reference")
        urls = d.get("urls") or ([d] if ep == "url" else [])
        for u in urls:
            res.tags |= set(u.get("tags") or [])
            if u.get("threat"):
                res.tags.add(u["threat"])
        if ep == "payload":
            if d.get("signature"):
                res.malware.add(d["signature"])
        res.context = {"urls_seen": d.get("url_count") or len(urls), "blacklists": d.get("blacklists")}
        res.context = {k: v for k, v in res.context.items() if v not in (None, "", [])}
        return res


class MalwareBazaar(_AbuseCh):
    name = "malwarebazaar"
    supported = {"md5", "sha1", "sha256"}
    min_interval = 0.5

    def _lookup(self, ioc: IOC) -> ProviderResult:
        r = self._request(
            "POST",
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": ioc.value},
            headers=self._hdr(),
        )
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return ProviderResult(self.name, found=False)
        s = d["data"][0]
        res = ProviderResult(self.name, found=True, malicious_score=95,
                             link=f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/")
        if s.get("signature"):
            res.malware.add(s["signature"])
        res.native = f'found: signature "{s.get("signature") or "unknown"}"'
        res.tags |= set(s.get("tags") or [])
        res.context = {
            k: v
            for k, v in {
                "file_name": s.get("file_name"),
                "file_type": s.get("file_type"),
                "first_seen": s.get("first_seen"),
                "delivery_method": s.get("delivery_method"),
                "origin_country": s.get("origin_country"),
            }.items()
            if v
        }
        return res
