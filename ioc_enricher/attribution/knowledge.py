"""Threat-actor knowledge base built from MITRE ATT&CK (STIX) and MISP Galaxy.

KB schema (JSON):
{
  "meta": {"built": ISO date, "attack_version": str, "sources": [...]},
  "groups": [{
      "id": "G0007", "name": "APT28", "aliases": [...], "country": "Russia",
      "description": "...", "url": "...", "source": "attack"|"misp",
      "software": [{"name": "X-Agent", "aliases": ["CHOPSTICK", ...]}],
      "techniques": ["T1566.001", ...]
  }]
}
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
MISP_URL = ("https://raw.githubusercontent.com/MISP/misp-galaxy/main/"
            "clusters/threat-actor.json")

BUNDLED_KB = Path(__file__).resolve().parent.parent / "data" / "groups.json"
USER_KB = Path.home() / ".ioc-enricher" / "groups.json"

# Aliases too generic to trust as a direct actor mention.
ALIAS_STOPLIST = {"snake", "carbon", "dragon", "panda", "bear", "kitten", "tiger", "spider",
                  "team", "group", "apt", "unknown", "tonto", "equation", "lead", "gold"}


def norm(s: str) -> str:
    """Normalise a name for equality matching: 'Win.Cobalt_Strike' -> 'cobaltstrike'."""
    s = s.lower().strip()
    s = re.sub(r"^(win|elf|osx|apk|ps1|js|php|py|vbs)[._]", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


def load_kb(path: str | Path | None = None) -> dict:
    for p in ([Path(path)] if path else [USER_KB, BUNDLED_KB]):
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    raise FileNotFoundError("No knowledge base found. Run: ioc-enricher update-kb")


def _ext_id(obj: dict, source="mitre-attack") -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == source and r.get("external_id"):
            return r["external_id"]
    return None


def _ext_url(obj: dict) -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("url")
    return None


def build_kb(attack: dict, misp: dict | None = None) -> dict:
    objs = [o for o in attack["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}

    groups: dict[str, dict] = {}
    for o in objs:
        if o["type"] == "intrusion-set":
            names = [o["name"]] + [a for a in o.get("aliases", []) if a != o["name"]]
            groups[o["id"]] = {
                "id": _ext_id(o) or o["id"], "name": o["name"], "aliases": names[1:],
                "country": None, "description": (o.get("description") or "").split("\n")[0][:400],
                "url": _ext_url(o), "source": "attack", "software": [], "techniques": [],
            }
    uses: dict[str, set[str]] = {}
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "uses" and o["source_ref"] in groups:
            uses.setdefault(o["source_ref"], set()).add(o["target_ref"])

    for gid, targets in uses.items():
        g = groups[gid]
        techs: set[str] = set()
        for t in targets:
            tobj = by_id.get(t)
            if not tobj:
                continue
            if tobj["type"] in ("malware", "tool"):
                aliases = [a for a in tobj.get("x_mitre_aliases", []) if a != tobj["name"]]
                g["software"].append({"name": tobj["name"], "aliases": aliases})
            elif tobj["type"] == "attack-pattern":
                tid = _ext_id(tobj)
                if tid:
                    techs.add(tid)
                    techs.add(tid.split(".")[0])  # roll sub-techniques up to parent
        g["techniques"] = sorted(techs)
        g["software"].sort(key=lambda s: s["name"].lower())

    kb_groups = list(groups.values())
    if misp:
        _merge_misp(kb_groups, misp)

    version = next((o.get("x_mitre_version") for o in attack["objects"]
                    if o["type"] == "x-mitre-collection"), None)
    return {
        "meta": {
            "built": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "attack_version": version,
            "sources": ["MITRE ATT&CK Enterprise (STIX 2.1)"] + (["MISP Galaxy threat-actor"] if misp else []),
            "group_count": len(kb_groups),
        },
        "groups": sorted(kb_groups, key=lambda g: g["name"].lower()),
    }


def _merge_misp(groups: list[dict], misp: dict) -> None:
    index: dict[str, dict] = {}
    for g in groups:
        for n in [g["name"], *g["aliases"]]:
            index.setdefault(norm(n), g)
    for v in misp.get("values", []):
        meta = v.get("meta", {})
        names = [v["value"], *meta.get("synonyms", [])]
        match = next((index[norm(n)] for n in names if norm(n) in index), None)
        country = meta.get("country")
        if match:
            known = {norm(x) for x in [match["name"], *match["aliases"]]}
            for n in names:
                if norm(n) not in known and len(n) >= 4:
                    match["aliases"].append(n)
                    known.add(norm(n))
            if country and not match["country"]:
                match["country"] = country
        else:
            groups.append({
                "id": f"MISP-{v.get('uuid', '')[:8]}", "name": v["value"],
                "aliases": [n for n in names[1:] if len(n) >= 4],
                "country": country, "description": (v.get("description") or "")[:400],
                "url": next(iter(meta.get("refs", [])), None), "source": "misp",
                "software": [], "techniques": [],
            })


def update_kb(dest: str | Path = USER_KB, with_misp: bool = True, timeout: int = 120) -> dict:
    """Download the latest ATT&CK + MISP data and write the KB."""
    attack = requests.get(ATTACK_URL, timeout=timeout)
    attack.raise_for_status()
    misp = None
    if with_misp:
        try:
            r = requests.get(MISP_URL, timeout=timeout)
            r.raise_for_status()
            misp = r.json()
        except requests.RequestException:
            misp = None
    kb = build_kb(attack.json(), misp)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(kb, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    return kb
