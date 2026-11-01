"""Internet-scan pivots: Censys (host services/certs) and FOFA (domains, fingerprints)."""
from __future__ import annotations

import base64
import re
from typing import Any, Iterator

from .base import PivotProvider, PivotResult, Relation, valid_ip

_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def _walk_ips(obj: Any) -> Iterator[str]:
    """Yield every string under an 'ip' key (response shape of search hits varies)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "ip" and isinstance(v, str) and valid_ip(v):
                yield v
            else:
                yield from _walk_ips(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_ips(v)


class Censys(PivotProvider):
    """Censys Platform API (v3, Personal Access Token). Host -> services, certificate, ASN, rDNS.

    NOTE: Censys documents the endpoints but not every response field name publicly, so the
    parser tolerates several layouts. Verify against a real response with your token.
    """

    name = "censys"
    env_var = "CENSYS_API_TOKEN"
    supported_kinds = {"ip", "certificate"}
    min_interval = 1.0
    BASE = "https://api.platform.censys.io/v3/global"
    MAX_HOSTS = 15

    def _h(self, accept: str | None = None) -> dict:
        h = {"Authorization": f"Bearer {self.api_key}"}
        if accept:
            h["Accept"] = accept
        return h

    def _pivot(self, kind: str, value: str) -> PivotResult:
        return self._host(value) if kind == "ip" else self._cert_hosts(value)

    def _host(self, ip: str) -> PivotResult:
        r = self._request("GET", f"{self.BASE}/asset/host/{ip}",
                          headers=self._h("application/vnd.censys.api.v3.host.v1+json"))
        if r.status_code == 404:
            return PivotResult()
        r.raise_for_status()
        j = r.json()
        res_ = j.get("result", j)
        host = res_.get("resource", res_)
        res = PivotResult()
        services = host.get("services") or []
        ports = sorted({s.get("port") for s in services if s.get("port") is not None})
        protos = sorted({str(s.get("protocol") or s.get("service_name") or "") for s in services} - {""})
        asys = host.get("autonomous_system") or {}
        asn, asname = asys.get("asn"), asys.get("name") or asys.get("description")
        res.node_attrs = {k: v for k, v in {"ports": ports, "services": protos, "asn": asn, "as_name": asname,
                                            "country": (host.get("location") or {}).get("country_code")}.items() if v}
        link = f"https://platform.censys.io/hosts/{ip}"
        if asn:
            res.relations.append(Relation("ip", ip, "announced-by", "asn", f"AS{asn}", "observed", self.name, 0.15,
                                          None, None, asname or "", link, {"name": asname}))
        names = ((host.get("dns") or {}).get("reverse_dns") or {}).get("names") or (host.get("dns") or {}).get("names") or []
        for n in names[:5]:
            n = str(n).lower()
            if _DOMAIN.match(n):
                res.relations.append(Relation("ip", ip, "hosts", "domain", n, "observed", self.name, 0.5,
                                              None, None, "reverse DNS", link))
        seen = set()
        for s in services:
            c = s.get("cert") or s.get("certificate") or {}
            tls = s.get("tls") or {}
            fp = (c.get("fingerprint_sha256") if isinstance(c, dict) else None) \
                or (((tls.get("certificates") or {}).get("leaf_data") or {}).get("fingerprint")) \
                or (c if isinstance(c, str) else None)
            if fp and fp.lower() not in seen:
                fp = fp.lower()
                seen.add(fp)
                res.relations.append(Relation("ip", ip, "presents", "certificate", f"sha256:{fp}", "observed",
                                              self.name, 0.7, None, None, f"on port {s.get('port')}", link,
                                              {"fingerprint_sha256": fp}))
        return res

    def _cert_hosts(self, node_value: str) -> PivotResult:
        """Other hosts presenting the same certificate (needs a sha256 fingerprint node)."""
        if not node_value.startswith("sha256:"):
            return PivotResult()
        fp = node_value.split(":", 1)[1]
        r = self._request("POST", f"{self.BASE}/search/query", headers=self._h(),
                          json={"query": f'host.services.cert.fingerprint_sha256="{fp}"', "page_size": self.MAX_HOSTS})
        if r.status_code != 200:
            return PivotResult(error=f"censys search HTTP {r.status_code}")
        res = PivotResult()
        for ip in list(dict.fromkeys(_walk_ips(r.json())))[: self.MAX_HOSTS]:
            res.relations.append(Relation("ip", ip, "presents", "certificate", node_value, "observed", self.name, 0.7,
                                          None, None, "same certificate fingerprint",
                                          f"https://platform.censys.io/hosts/{ip}"))
        return res


class Fofa(PivotProvider):
    """FOFA search: IP -> domains/services/JARM, JARM -> look-alike hosts, domain -> IPs."""

    name = "fofa"
    env_var = "FOFA_API_KEY"
    supported_kinds = {"ip", "domain"}
    min_interval = 1.5
    URL = "https://fofa.info/api/v1/search/all"
    BASIC = "host,ip,port,domain,title,server,protocol"
    EXTENDED = BASIC + ",jarm,as_organization"
    JARM_MAX_HOSTS = 20  # a fingerprint that fills the page is a default stack, not a link

    def _search(self, query: str, fields: str, size: int = 50):
        r = self._request("GET", self.URL, params={
            "key": self.api_key, "qbase64": base64.b64encode(query.encode()).decode(),
            "fields": fields, "size": size})
        j = r.json()
        if j.get("error"):
            raise ValueError(j.get("errmsg") or "FOFA error")
        return j.get("results", [])

    def _pivot(self, kind: str, value: str) -> PivotResult:
        q = f'ip="{value}"' if kind == "ip" else f'domain="{value}"'
        fields = self.EXTENDED
        try:
            rows = self._search(q, fields)
        except ValueError:  # account tier without extended fields: retry with the basic set
            fields = self.BASIC
            rows = self._search(q, fields)
        names = fields.split(",")
        recs = [dict(zip(names, row)) for row in rows]
        res = PivotResult()
        link = f"https://en.fofa.info/result?qbase64={base64.b64encode(q.encode()).decode()}"
        ports = sorted({int(r["port"]) for r in recs if str(r.get("port", "")).isdigit()})
        titles = sorted({r["title"] for r in recs if r.get("title")})[:3]
        servers = sorted({r["server"] for r in recs if r.get("server")})[:3]
        jarms = sorted({r["jarm"] for r in recs if r.get("jarm")})
        res.node_attrs = {k: v for k, v in {"ports": ports, "titles": titles, "servers": servers,
                                            "jarm": jarms[:2], "as_org": next((r.get("as_organization") for r in recs
                                                                              if r.get("as_organization")), None)}.items() if v}
        for r in recs:
            if kind == "ip" and r.get("domain") and _DOMAIN.match(r["domain"].lower()):
                res.relations.append(Relation("ip", value, "hosts", "domain", r["domain"].lower(), "observed",
                                              self.name, 0.4, None, None, "FOFA scan record", link))
            if kind == "domain" and valid_ip(r.get("ip", "")):
                res.relations.append(Relation("domain", value, "resolves-to", "ip", r["ip"], "observed",
                                              self.name, 0.5, None, None, "FOFA scan record", link))
        if kind == "ip":
            for j in jarms[:1]:
                try:
                    hits = self._search(f'jarm="{j}"', "ip", self.JARM_MAX_HOSTS)
                except ValueError:
                    break
                ips = [h[0] if isinstance(h, list) else h for h in hits]
                if len(ips) >= self.JARM_MAX_HOSTS:
                    res.node_attrs["jarm_note"] = "TLS fingerprint too common to pivot on"
                    continue
                for ip in ips:
                    if ip != value and valid_ip(ip):
                        res.relations.append(Relation("ip", value, "shares-tls-fingerprint-with", "ip", ip, "inferred",
                                                      self.name, 0.15, None, None, f"identical JARM {j[:16]}...", link))
        return res
