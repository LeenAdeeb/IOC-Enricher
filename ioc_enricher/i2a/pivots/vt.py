"""VirusTotal relationship pivots: passive-DNS resolutions, communicating files, sandbox contacts."""
from __future__ import annotations

from datetime import datetime, timezone

from .base import PivotProvider, PivotResult, Relation, valid_ip

API = "https://www.virustotal.com/api/v3"


def _iso(ts) -> str | None:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).date().isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class VTRelations(PivotProvider):
    name = "vt-relations"
    env_var = "VT_API_KEY"
    supported_kinds = {"ip", "domain", "hash"}
    min_interval = 15.5  # shares the free-tier quota (4/min) with the reputation provider
    throttle_key = "virustotal"
    LIMIT = 10
    MIN_DETECTIONS = 3  # communicating files below this are too noisy to treat as malicious

    def _get(self, path: str):
        r = self._request("GET", f"{API}/{path}", params={"limit": self.LIMIT}, headers={"x-apikey": self.api_key})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json().get("data", [])

    def _pivot(self, kind: str, value: str) -> PivotResult:
        res = PivotResult()
        if kind == "ip":
            for it in self._get(f"ip_addresses/{value}/resolutions"):
                a = it.get("attributes", {})
                if a.get("host_name"):
                    d = _iso(a.get("date"))
                    res.relations.append(Relation("ip", value, "hosts", "domain", a["host_name"].lower(),
                                                  "observed", self.name, 0.6, d, d, "passive DNS resolution",
                                                  f"https://www.virustotal.com/gui/ip-address/{value}/relations"))
            self._files(f"ip_addresses/{value}/communicating_files", "ip", value, res)
        elif kind == "domain":
            for it in self._get(f"domains/{value}/resolutions"):
                a = it.get("attributes", {})
                if a.get("ip_address") and valid_ip(a["ip_address"]):
                    d = _iso(a.get("date"))
                    res.relations.append(Relation("domain", value, "resolves-to", "ip", a["ip_address"],
                                                  "observed", self.name, 0.6, d, d, "passive DNS resolution",
                                                  f"https://www.virustotal.com/gui/domain/{value}/relations"))
            self._files(f"domains/{value}/communicating_files", "domain", value, res)
        else:  # hash: what does this sample talk to (sandbox-observed)?
            for rel_path, dkind in (("contacted_domains", "domain"), ("contacted_ips", "ip")):
                for it in self._get(f"files/{value}/{rel_path}"):
                    dst = (it.get("id") or "").lower()
                    if dst and (dkind == "domain" or valid_ip(dst)):
                        res.relations.append(Relation("hash", value, "communicates-with", dkind, dst, "observed",
                                                      self.name, 0.7, None, None, "contacted during sandbox run",
                                                      f"https://www.virustotal.com/gui/file/{value}/relations"))
        return res

    def _files(self, path: str, kind: str, value: str, res: PivotResult) -> None:
        for it in self._get(path):
            a = it.get("attributes", {})
            stats = a.get("last_analysis_stats") or {}
            mal = stats.get("malicious", 0)
            sha = (it.get("id") or "").lower()
            if not sha or mal < self.MIN_DETECTIONS:
                continue
            total = mal + stats.get("suspicious", 0) + stats.get("harmless", 0) + stats.get("undetected", 0)
            fam = ((a.get("popular_threat_classification") or {}).get("suggested_threat_label")) or None
            res.relations.append(Relation(
                "hash", sha, "communicates-with", kind, value, "observed", self.name, 0.6,
                _iso(a.get("first_submission_date")), None, f"{mal}/{total} engines malicious",
                f"https://www.virustotal.com/gui/file/{sha}",
                {"vt_detections": f"{mal}/{total}", "name": a.get("meaningful_name"), "family_label": fam}))
