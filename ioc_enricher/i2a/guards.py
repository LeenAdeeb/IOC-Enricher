"""Guard rails that stop pivoting from exploding into irrelevant infrastructure.

A shared hosting IP, a CDN edge or a mega-site is a *lead at best*: thousands of unrelated
domains sit behind them. These checks keep such nodes out of (or at the edge of) the graph.
"""
from __future__ import annotations

import ipaddress

# Domains that are never useful pivots (ubiquitous third-party resources, big platforms).
MEGA_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "youtube.com", "microsoft.com", "windows.com",
    "windowsupdate.com", "office.com", "office365.com", "live.com", "msn.com", "bing.com",
    "azure.com", "azureedge.net", "cloudflare.com", "cloudflare-dns.com", "cloudfront.net",
    "amazonaws.com", "amazon.com", "akamai.net", "akamaiedge.net", "akamaihd.net", "fastly.net",
    "apple.com", "icloud.com", "facebook.com", "fbcdn.net", "twitter.com", "linkedin.com",
    "github.com", "githubusercontent.com", "cloudflareinsights.com", "jsdelivr.net", "cdnjs.com",
    "bootstrapcdn.com", "jquery.com", "w3.org", "wikipedia.org", "mozilla.org", "digicert.com",
    "letsencrypt.org", "sectigo.com", "godaddy.com", "gravatar.com", "wp.com",
}

# Dynamic-DNS providers: attacker-friendly, and many unrelated users share the zone.
DYNAMIC_DNS = {
    "duckdns.org", "no-ip.com", "no-ip.org", "noip.com", "ddns.net", "hopto.org", "zapto.org",
    "sytes.net", "servebeer.com", "serveftp.com", "myftp.org", "dynu.com", "freedns.afraid.org",
    "dyndns.org", "dyndns.info", "ddnsking.com", "3utilities.com", "bounceme.net", "redirectme.net",
}

# ASNs of large CDNs / clouds whose address space hosts huge numbers of unrelated tenants.
SHARED_ASNS = {
    13335: "Cloudflare", 20940: "Akamai", 16625: "Akamai", 54113: "Fastly", 16509: "Amazon",
    14618: "Amazon", 15169: "Google", 396982: "Google Cloud", 8075: "Microsoft", 32934: "Facebook",
    2906: "Netflix", 13414: "Twitter", 19551: "Incapsula", 30148: "Sucuri",
}

SHARED_HOSTING_DOMAIN_THRESHOLD = 40  # an IP serving more distinct domains than this is "shared"


def registered_suffix(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def is_mega_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return d in MEGA_DOMAINS or registered_suffix(d) in MEGA_DOMAINS


def is_dynamic_dns(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == z or d.endswith("." + z) for z in DYNAMIC_DNS)


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def shared_asn_name(asn) -> str | None:
    try:
        return SHARED_ASNS.get(int(str(asn).upper().replace("AS", "").split()[0]))
    except (ValueError, IndexError):
        return None
