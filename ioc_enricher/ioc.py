"""IOC parsing: refanging, type detection and extraction from free text."""
from __future__ import annotations

import ipaddress
import re

from .models import IOC

_HEX = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}$")
_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s/]+(?:[/?#]\S*)?$", re.I)

# Candidate finder used for free-text extraction.
_CANDIDATE_RE = re.compile(
    r"(?:(?:https?|ftp)://[^\s\"'<>]+)"  # URLs
    r"|(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})"  # hashes
    r"|(?:[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})"  # emails
    r"|(?:(?:\d{1,3}\.){3}\d{1,3})"  # IPv4
    r"|(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62})"  # domains
)


def refang(text: str) -> str:
    """Convert defanged indicators (hxxp://evil[.]com) back to normal form."""
    t = text.strip()
    t = re.sub(r"\bhxxp", "http", t, flags=re.I)
    t = re.sub(r"\bfxp", "ftp", t, flags=re.I)
    t = re.sub(r"\[:\]|\(:\)", ":", t)
    t = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[@\]|\(@\)|\[at\]", "@", t, flags=re.I)
    t = t.replace("[://]", "://")
    return t


def defang(value: str) -> str:
    """Make an indicator safe to paste into chats/reports."""
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    return v.replace(".", "[.]")


def classify(raw: str) -> IOC | None:
    """Return a typed IOC or None when `raw` is not a supported indicator."""
    v = refang(raw)
    if not v:
        return None
    low = v.lower()

    if re.fullmatch(r"[a-f0-9]+", low) and len(low) in _HEX:
        return IOC(low, _HEX[len(low)])
    try:
        ip = ipaddress.ip_address(v)
        return IOC(str(ip), "ipv4" if ip.version == 4 else "ipv6")
    except ValueError:
        pass
    if _URL_RE.match(v):
        return IOC(v, "url")
    if _EMAIL_RE.match(low):
        return IOC(low, "email")
    if _DOMAIN_RE.match(low):
        return IOC(low.rstrip("."), "domain")
    return None


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract(text: str) -> list[IOC]:
    """Pull every supported indicator out of free text (reports, e-mails, logs)."""
    seen: dict[str, IOC] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0] if line.lstrip().startswith("#") else line
        for m in _CANDIDATE_RE.finditer(refang(line)):
            ioc = classify(m.group(0).rstrip(".,;)"))
            if ioc and ioc.value not in seen:
                seen[ioc.value] = ioc
    return list(seen.values())
