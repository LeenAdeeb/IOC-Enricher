import pytest

from ioc_enricher.attribution import Attributor
from ioc_enricher.ioc import classify
from ioc_enricher.models import Enrichment, ProviderResult

KB = {"meta": {}, "groups": [
    {"id": "G1", "name": "APT-Alpha", "aliases": ["Fancy Fox"], "country": "XX", "description": "", "url": None,
     "software": [{"name": "RareRAT", "aliases": ["RR"]}, {"name": "Mimikatz", "aliases": []}],
     "techniques": ["T1566"]},
    {"id": "G2", "name": "APT-Beta", "aliases": [], "country": "YY", "description": "", "url": None,
     "software": [{"name": "Mimikatz", "aliases": []}, {"name": "Other", "aliases": []}], "techniques": ["T1566"]},
    {"id": "G3", "name": "APT-Gamma", "aliases": [], "country": None, "description": "", "url": None,
     "software": [{"name": "Mimikatz", "aliases": []}], "techniques": []},
]}


def enr(value="1.2.3.4", **kw):
    e = Enrichment(classify(value))
    e.results.append(ProviderResult("t", **{k: set(v) if isinstance(v, (list, set)) else v for k, v in kw.items()}))
    return e


def test_rare_software_beats_commodity():
    c = Attributor(KB).attribute([enr(malware={"RareRAT", "Mimikatz"})])
    assert c[0].group["name"] == "APT-Alpha"
    # Beta/Gamma only share the commodity tool -> capped Low
    assert all(x.label == "Low" for x in c[1:])


def test_alias_resolution_and_mention():
    c = Attributor(KB).attribute([enr(tags={"fancy-fox campaign"})])
    assert c[0].group["name"] == "APT-Alpha"
    assert any(e.kind == "mention" for e in c[0].evidence)


def test_no_substring_false_positive():
    kb = {"meta": {}, "groups": [dict(KB["groups"][0], name="APT1", aliases=[])]}
    assert Attributor(kb).attribute([enr(tags={"apt10 activity"})]) == []


def test_technique_alone_creates_no_candidate():
    assert Attributor(KB).attribute([enr(techniques={"T1566"})]) == []


def test_family_normalisation():
    c = Attributor(KB).attribute([enr(malware={"win.rareRAT"})])
    assert c and c[0].group["name"] == "APT-Alpha"
