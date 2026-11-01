"""Explainable, weighted APT attribution.

Signals (per candidate group):

* Direct mention  - an actor name/alias appears in an adversary field, tag or pulse
                    name returned by a provider. Strongest signal.
* Software        - a malware/tool family seen on an IOC is attributed to the group in
                    ATT&CK. Weighted by *rarity*: a family used by 1 of 150 groups
                    (e.g. X-Agent) counts far more than Mimikatz (used by dozens).
* Technique       - overlap of observed ATT&CK technique IDs with the group's profile,
                    also rarity-weighted and capped (techniques are weak evidence).

Every piece of evidence belongs to a *dimension*: ``reported`` (a third-party label on the
seed IOC itself), ``infrastructure`` (an actor label on infrastructure linked to the seed
through the investigation graph), ``malware``, or ``ttp``. ``victimology`` and
``operational`` behaviour are listed as *not assessed* because no data source here provides
them. A label alone never yields High: that needs two independent dimensions.

Raw evidence is squashed into 0-100 with a saturating curve. Guard rail: without a direct
mention or at least two distinct *rare* software matches, confidence is capped (Medium for one rare family, Low for commodity-only overlap) so
commodity-tool overlap can never look like a confident attribution.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from ..models import Enrichment
from .knowledge import ALIAS_STOPLIST, norm

W_MENTION = 30.0
W_SOFTWARE = 14.0
W_TECHNIQUE = 2.0
TECHNIQUE_CAP = 16.0
SATURATION = 55.0
RARE = 0.5  # software rarity needed to count towards the "strong evidence" guard
CAP_ONE_RARE = 49  # one rare software family and nothing else: at most Moderate
CAP_COMMODITY = 20  # only widely shared tooling / technique overlap: Low
CAP_SINGLE_DIMENSION = 54  # High needs two independent dimensions
MIN_SCALE = 0.4  # evidence reached only through a weak graph path cannot lift the guard rails

INDEPENDENT = ("infrastructure", "malware", "ttp")
ALL_DIMENSIONS = ("infrastructure", "malware", "ttp", "reported", "victimology", "operational")
NOT_ASSESSED = ("victimology", "operational")
DIM_PHRASE = {"infrastructure": "infrastructure relationships", "malware": "malware characteristics",
              "ttp": "ATT&CK technique overlap", "reported": "third-party reporting"}


@dataclass
class Evidence:
    kind: str  # mention | software | technique
    detail: str
    base: float
    iocs: list[str] = field(default_factory=list)
    rarity: float = 1.0
    dimension: str = "reported"
    scale: float = 1.0  # strongest graph path weight among the IOCs that contributed

    @property
    def weight(self) -> float:
        return self.base * self.scale

    def to_dict(self):
        return {"kind": self.kind, "dimension": self.dimension, "detail": self.detail,
                "weight": round(self.weight, 1), "iocs": self.iocs}


@dataclass
class Candidate:
    group: dict
    raw: float = 0.0
    confidence: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    capped_reason: str | None = None

    @property
    def label(self) -> str:
        return "High" if self.confidence >= 55 else "Moderate" if self.confidence >= 25 else "Low"

    def dimensions(self) -> dict:
        """Evidence count per dimension; None marks dimensions this build cannot assess."""
        out: dict = {d: (None if d in NOT_ASSESSED else 0) for d in ALL_DIMENSIONS}
        for e in self.evidence:
            if out.get(e.dimension) is not None:
                out[e.dimension] += 1
        return out

    def statement(self, alternatives: list["Candidate"] | None = None) -> str:
        """Analyst-style, hedged assessment text (CERT-EU style wording)."""
        dims = [DIM_PHRASE[d] for d, n in self.dimensions().items() if n and d in DIM_PHRASE]
        ev = sorted(self.evidence, key=lambda e: -e.weight)[:3]
        parts = [f"{self.label}-confidence assessment: the observed {_join(dims) or 'indicators'} exhibit "
                 f"similarities to activity previously associated with {self.group['name']}."]
        if ev:
            parts.append("Supported by: " + "; ".join(e.detail for e in ev) + ".")
        lim = ["victimology and operational behaviour were not assessed"]
        if self.capped_reason:
            lim.insert(0, self.capped_reason)
        if any(e.kind == "software" and e.rarity < RARE for e in self.evidence):
            lim.append("part of the tooling overlap is commodity software shared by many groups")
        parts.append("Limitations: " + "; ".join(lim) + ".")
        if alternatives:
            parts.append("Alternative hypotheses: " + ", ".join(
                f"{a.group['name']} ({a.label}, {a.confidence}%)" for a in alternatives[:3]) + ".")
        parts.append("The available evidence is insufficient to establish definitive attribution.")
        return " ".join(parts)

    def to_dict(self, alternatives: list["Candidate"] | None = None):
        g = self.group
        return {
            "group_id": g["id"], "name": g["name"], "aliases": g["aliases"][:10],
            "country": g.get("country"), "url": g.get("url"),
            "confidence": self.confidence, "confidence_label": self.label,
            "capped_reason": self.capped_reason, "dimensions": self.dimensions(),
            "statement": self.statement(alternatives),
            "evidence": [e.to_dict() for e in sorted(self.evidence, key=lambda e: -e.weight)],
        }


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1] if items else ""


class Attributor:
    def __init__(self, kb: dict):
        self.groups = kb["groups"]
        # Rarity is measured against groups that actually have a software profile (ATT&CK);
        # MISP-only actors have none and would otherwise inflate the denominator.
        n = max(sum(1 for g in self.groups if g["software"]), 2)
        self._n = n
        # name -> groups; software -> groups; technique doc-frequency
        self._sw_df: dict[str, int] = {}
        self._tech_df: dict[str, int] = {}
        self._sw_index: dict[str, list[int]] = {}
        self._patterns: list[tuple[re.Pattern, int]] = []
        for i, g in enumerate(self.groups):
            seen = set()
            for s in g["software"]:
                for nm in [s["name"], *s["aliases"]]:
                    k = norm(nm)
                    if k and k not in seen:
                        seen.add(k)
                        self._sw_index.setdefault(k, []).append(i)
            for k in {norm(s["name"]) for s in g["software"]}:
                self._sw_df[k] = self._sw_df.get(k, 0) + 1
            for t in g["techniques"]:
                self._tech_df[t] = self._tech_df.get(t, 0) + 1
            for nm in [g["name"], *g["aliases"]]:
                if len(nm) >= 4 and nm.lower() not in ALIAS_STOPLIST:
                    parts = [x for x in re.split(r"[\s\-_]+", nm.lower()) if x]
                    flex = r"[\s\-_]?".join(re.escape(x) for x in parts)
                    self._patterns.append((re.compile(rf"(?<![a-z0-9]){flex}(?![a-z0-9])"), i))

    # -- rarity weight in (0, 1] ----------------------------------------
    def _rarity(self, df: int) -> float:
        df = max(df, 1)
        return math.log(1 + self._n / df) / math.log(1 + self._n)

    def _software_rarity(self, group_idx: int, key: str) -> float:
        # df = how many groups list this exact family (aliases resolve to same entry)
        return self._rarity(len(self._sw_index.get(key, [group_idx])))

    # -- main -----------------------------------------------------------
    def attribute(self, enrichments: list[Enrichment], top: int = 5,
                  weights: dict[str, float] | None = None, seeds: set[str] | None = None) -> list[Candidate]:
        """Rank candidate groups.

        ``weights`` maps IOC value -> graph path weight (default 1.0): evidence that arrives
        through a weak pivot counts for proportionally less. ``seeds`` are the IOCs the analyst
        submitted (default: all); an actor label on a seed is *reported* evidence, one found on
        linked infrastructure is *infrastructure* evidence.
        """
        weights = weights or {}
        cands: dict[int, Candidate] = {}
        mention_seen: dict[tuple[int, str], Evidence] = {}
        sw_seen: dict[tuple[int, str], Evidence] = {}
        tech_hits: dict[int, dict[str, Evidence]] = {}

        def touch(ev: Evidence, ioc: str) -> None:
            if ioc not in ev.iocs:
                ev.iocs.append(ioc)
            ev.scale = max(ev.scale, weights.get(ioc, 1.0))

        for enr in enrichments:
            ioc = enr.ioc.value
            is_seed = seeds is None or ioc in seeds
            texts: set[str] = set(enr.merged("actors")) | set(enr.merged("tags"))
            for r in enr.results:
                texts |= set(r.context.get("pulse_names", []))
            actor_texts = set(enr.merged("actors"))

            # 1) direct mentions (a label from a source: reported, or infrastructure when on a linked node)
            for text in texts:
                low = text.lower()
                for pat, gi in self._patterns:
                    if pat.search(low):
                        key = (gi, norm(text), is_seed)
                        ev = mention_seen.get(key)
                        if ev is None:
                            base = W_MENTION * (1.3 if text in actor_texts else 1.0)
                            how = "labelled by a source" if is_seed else f"on linked infrastructure ({ioc})"
                            ev = Evidence("mention", f'"{text}" names {self.groups[gi]["name"]} - {how}', base,
                                          dimension="reported" if is_seed else "infrastructure", scale=0.0)
                            mention_seen[key] = ev
                            cands.setdefault(gi, Candidate(self.groups[gi])).evidence.append(ev)
                        touch(ev, ioc)

            # 2) software
            for fam in enr.merged("malware"):
                k = norm(fam)
                for gi in self._sw_index.get(k, []):
                    key = (gi, k)
                    ev = sw_seen.get(key)
                    if ev is None:
                        rar = self._software_rarity(gi, k)
                        ev = Evidence("software", f"{fam} is attributed to {self.groups[gi]['name']} "
                                                  f"(used by {len(self._sw_index[k])} group(s))", W_SOFTWARE * rar * 2,
                                      rarity=rar, dimension="malware", scale=0.0)
                        sw_seen[key] = ev
                        cands.setdefault(gi, Candidate(self.groups[gi])).evidence.append(ev)
                    touch(ev, ioc)

            # 3) techniques
            for tid in enr.merged("techniques"):
                for gi, g in enumerate(self.groups):
                    if tid in g["techniques"]:
                        d = tech_hits.setdefault(gi, {})
                        if tid not in d:
                            d[tid] = Evidence("technique", f"{tid} observed; in {g['name']} profile",
                                              W_TECHNIQUE * self._rarity(self._tech_df.get(tid, 1)) * 2,
                                              dimension="ttp", scale=0.0)
                        touch(d[tid], ioc)

        for gi, d in tech_hits.items():
            if gi not in cands:  # technique overlap alone never creates a candidate
                continue
            total = 0.0
            for ev in sorted(d.values(), key=lambda e: -e.weight):
                if total + ev.weight > TECHNIQUE_CAP:
                    break
                total += ev.weight
                cands[gi].evidence.append(ev)

        out = []
        for gi, c in cands.items():
            c.raw = sum(e.weight for e in c.evidence)
            conf = round(100 * (1 - math.exp(-c.raw / SATURATION)))
            strong_mention = any(e.kind == "mention" and e.scale >= MIN_SCALE for e in c.evidence)
            rare = sum(e.kind == "software" and e.rarity >= RARE and e.scale >= MIN_SCALE for e in c.evidence)
            if strong_mention or rare >= 2:
                c.confidence = conf
            elif rare == 1:
                c.confidence = min(conf, CAP_ONE_RARE)
                if conf > CAP_ONE_RARE:
                    c.capped_reason = "only one distinctive tool family supports this actor"
            else:
                c.confidence = min(conf, CAP_COMMODITY)
                if conf > CAP_COMMODITY:
                    c.capped_reason = "evidence is limited to widely shared tooling or weak links"
            dims = {e.dimension for e in c.evidence if e.dimension in INDEPENDENT and e.scale >= MIN_SCALE}
            if c.confidence >= 55 and len(dims) < 2:
                c.confidence = CAP_SINGLE_DIMENSION
                c.capped_reason = "evidence comes from a single dimension (a label alone is not enough for High)"
            out.append(c)
        out.sort(key=lambda c: (-c.confidence, -c.raw, c.group["name"]))
        return out[:top]
