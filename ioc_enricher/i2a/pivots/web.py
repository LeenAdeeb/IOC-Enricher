"""Web-facing pivots: crt.sh (certificate transparency) and urlscan.io (page relationships)."""
from __future__ import annotations

import re
from urllib.parse import quote

from ...i2a.guards import is_mega_domain
from .base import PivotProvider, PivotResult, Relation, valid_ip

_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


class CrtSh(PivotProvider):
    """Domain -> certificates -> other names on the same certificates (no API key needed)."""

    name = "crtsh"
    needs_key = False
    supported_kinds = {"domain"}
    min_interval = 2.0
    MAX_CERTS = 25

    def _pivot(self, kind: str, value: str) -> PivotResult:
        r = self._request("GET", "https://crt.sh/", params={"q": value, "output": "json"}, timeout=40)
        if r.status_code != 200:
            return PivotResult(error=f"crt.sh HTTP {r.status_code}")
        try:
            rows = r.json()
        except ValueError:
            return PivotResult(error="crt.sh returned non-JSON (service busy)")
        certs: dict[int, dict] = {}
        for row in rows:
            cid = row.get("id")
            if cid is not None and cid not in certs:
                certs[cid] = row
        res = PivotResult()
        skipped = 0
        for cid, row in sorted(certs.items(), reverse=True)[: self.MAX_CERTS]:
            sans = sorted({s.strip().lower() for s in (row.get("name_value") or "").splitlines() if s.strip()})
            nb, na = (row.get("not_before") or "")[:10] or None, (row.get("not_after") or "")[:10] or None
            attrs = {"issuer": row.get("issuer_name"), "serial": row.get("serial_number"),
                     "not_before": nb, "not_after": na, "san_count": len(sans), "source": "crt.sh"}
            link = f"https://crt.sh/?id={cid}"
            res.relations.append(Relation("domain", value, "presents", "certificate", f"crtsh:{cid}", "observed",
                                          self.name, 0.7, nb, na, f"{len(sans)} name(s) on certificate", link, attrs))
            if len(sans) > 40:  # multi-tenant / CDN certificate: not evidence of common control
                skipped += 1
                continue
            w = 0.7 if len(sans) <= 10 else 0.45
            for san in sans:
                wildcard = san.startswith("*.")
                san = san[2:] if wildcard else san
                if san == value or not _DOMAIN.match(san) or is_mega_domain(san):
                    continue
                res.relations.append(Relation(
                    "certificate", f"crtsh:{cid}", "covers", "domain", san, "observed", self.name, w, nb, na,
                    "wildcard SAN" if wildcard else "SAN", link))
        if skipped:
            res.node_attrs["multi_tenant_certs_skipped"] = skipped
        return res


class UrlScan(PivotProvider):
    """Domain/IP -> scan history: resolved IPs, hosted domains, contacted domains, redirects."""

    name = "urlscan"
    env_var = "URLSCAN_API_KEY"
    needs_key = False  # works anonymously with a low quota; a key raises limits
    supported_kinds = {"domain", "ip"}
    min_interval = 1.5
    MAX_RESULTS = 25
    DETAIL_SCANS = 2

    def _headers(self) -> dict:
        return {"API-Key": self.api_key} if self.api_key else {}

    def _pivot(self, kind: str, value: str) -> PivotResult:
        q = f'page.domain:"{value}"' if kind == "domain" else f'page.ip:"{value}"'
        r = self._request("GET", "https://urlscan.io/api/v1/search/",
                          params={"q": q, "size": self.MAX_RESULTS}, headers=self._headers())
        if r.status_code != 200:
            return PivotResult(error=f"urlscan HTTP {r.status_code}")
        results = r.json().get("results", [])
        res = PivotResult()
        seen: dict[tuple, dict] = {}
        for it in results:
            page, task = it.get("page", {}), it.get("task", {})
            t = (task.get("time") or "")[:10] or None
            if kind == "domain" and page.get("ip") and valid_ip(page["ip"]):
                key = ("resolves-to", "ip", page["ip"])
            elif kind == "ip" and page.get("domain"):
                key = ("hosts", "domain", page["domain"].lower())
            else:
                continue
            e = seen.setdefault(key, {"first": t, "last": t, "n": 0, "id": it.get("_id"), "asn": page.get("asn"),
                                      "server": page.get("server")})
            e["n"] += 1
            if t:
                e["first"] = min(filter(None, [e["first"], t]), default=t)
                e["last"] = max(filter(None, [e["last"], t]), default=t)
        for (rel, dkind, dval), e in seen.items():
            if dkind == "domain" and is_mega_domain(dval):
                continue
            attrs = {k: v for k, v in {"asn": e["asn"], "server": e["server"]}.items() if v}
            if kind == "ip":  # page.asn describes the IP we asked about, not the domain found
                for k, v in attrs.items():
                    res.node_attrs.setdefault(k, v)
                attrs = {}
            src_kind = kind
            res.relations.append(Relation(
                src_kind, value, rel, dkind, dval, "observed", self.name, 0.6 if kind == "domain" else 0.55,
                e["first"], e["last"], f"seen in {e['n']} scan(s)",
                f"https://urlscan.io/result/{e['id']}/" if e["id"] else None, attrs))
        if kind == "domain":
            for it in results[: self.DETAIL_SCANS]:
                if it.get("_id"):
                    self._scan_detail(it["_id"], value, res)
        return res

    def _scan_detail(self, scan_id: str, seed: str, res: PivotResult) -> None:
        r = self._request("GET", f"https://urlscan.io/api/v1/result/{quote(scan_id)}/", headers=self._headers())
        if r.status_code != 200:
            return
        d = r.json()
        link = f"https://urlscan.io/result/{scan_id}/"
        when = (d.get("task", {}).get("time") or "")[:10] or None
        final = (d.get("page", {}).get("domain") or "").lower()
        if d.get("page", {}).get("redirected") not in (None, False, "") and final and final != seed \
                and not is_mega_domain(final):
            res.relations.append(Relation("domain", seed, "redirects-to", "domain", final, "observed",
                                          self.name, 0.6, when, when, "page redirected", link))
        added = 0
        for dom in d.get("lists", {}).get("domains", []):
            dom = dom.lower()
            if dom == seed or dom == final or is_mega_domain(dom) or not _DOMAIN.match(dom):
                continue
            res.relations.append(Relation("domain", seed, "loads-resource-from", "domain", dom, "observed",
                                          self.name, 0.25, when, when, "contacted while loading page", link))
            added += 1
            if added >= 10:
                break
