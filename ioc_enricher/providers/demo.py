"""Offline demo provider with SYNTHETIC data so the tool runs without API keys.

Indicators use reserved documentation ranges (RFC 5737, example TLDs) and made-up
hashes. The malware/actor tags are illustrative only: they exist to show how the
correlation and attribution engine behaves and do NOT describe real infrastructure.
"""
from __future__ import annotations

from ..models import IOC, ProviderResult
from .base import Provider

DEMO_DATA: dict[str, dict] = {
    "198.51.100.23": dict(score=88, malware={"X-Agent", "Zebrocy"}, tags={"sofacy", "c2"},
                          actors={"Sofacy"}, ctx={"country": "NL", "asn": "AS64496 (demo)"}),
    "203.0.113.77": dict(score=74, malware={"CHOPSTICK"}, tags={"apt28", "phishing"},
                         techniques={"T1566.001", "T1071.001"}, ctx={"country": "DE"}),
    "update-check.example.com": dict(score=81, malware={"Zebrocy"}, tags={"c2", "spearphishing"},
                                     techniques={"T1071.001", "T1027"}, ctx={"registrar": "demo-registrar"}),
    "cdn-sync.example.net": dict(score=72, malware={"Zebrocy"}, tags={"c2", "sofacy"},
                                 techniques={"T1071.001"}, ctx={"first_seen": "2026-03-04"}),
    "mail-relay.example.org": dict(score=22, tags={"suspicious-registration"}, ctx={"first_seen": "2026-03-01"}),
    "192.0.2.99": dict(score=58, malware={"X-Agent"}, tags={"c2"}, ctx={"country": "RO", "first_seen": "2026-03-10"}),
    "crypto-wallet-update.example.org": dict(score=90, malware={"AppleJeus"}, tags={"lazarus", "c2"},
                                             techniques={"T1204.002"}, ctx={"first_seen": "2026-05-20"}),
    "192.0.2.150": dict(score=90, malware={"Cobalt Strike"}, tags={"beacon", "c2"},
                        ctx={"country": "US"}),
    "203.0.113.200": dict(score=65, malware={"Cobalt Strike"}, tags={"beacon"}, ctx={"country": "SG"}),
    "d41d8cd98f00b204e9800998ecf8427e": dict(score=95, malware={"Mimikatz"}, tags={"credential-dumping"},
                                             techniques={"T1003"}, ctx={"file_type": "exe"}),
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": dict(
        score=97, malware={"AppleJeus", "Manuscrypt"}, tags={"hidden cobra", "crypto-theft"},
        actors={"Lazarus Group"}, techniques={"T1195", "T1204.002"}, ctx={"file_type": "dmg"}),
    "hxxp://crypto-wallet-update[.]example.org/installer.dmg": dict(
        score=92, malware={"AppleJeus"}, tags={"lazarus", "trojanized-installer"},
        techniques={"T1204.002"}, ctx={"threat": "malware_download"}),
}


class DemoProvider(Provider):
    name = "demo"
    needs_key = False
    supported = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}

    def _lookup(self, ioc: IOC) -> ProviderResult:
        from ..ioc import refang

        entry = DEMO_DATA.get(ioc.value) or DEMO_DATA.get(ioc.value.replace(".", "[.]"))
        if entry is None:
            for k, v in DEMO_DATA.items():
                if refang(k) == ioc.value:
                    entry = v
                    break
        if entry is None:
            return ProviderResult(self.name, found=False, malicious_score=0)
        return ProviderResult(
            self.name,
            native=f"synthetic demo data (score {entry['score']})",
            found=True,
            malicious_score=entry["score"],
            malware=set(entry.get("malware", ())),
            tags=set(entry.get("tags", ())),
            actors=set(entry.get("actors", ())),
            techniques=set(entry.get("techniques", ())),
            context={**entry.get("ctx", {}), "synthetic": True},
        )
