"""Provider base class: HTTP, rate limiting, caching and error normalisation."""
from __future__ import annotations

import threading
import time
from typing import Any

import requests

from ..cache import Cache
from ..models import IOC, ProviderResult

USER_AGENT = "ioc-enricher/1.0 (+https://github.com/)"


_THROTTLE: dict[str, float] = {}
_THROTTLE_LOCK = threading.Lock()


class Provider:
    name = "base"
    throttle_key: str | None = None  # providers sharing one API quota share a key
    supported: set[str] = set()
    needs_key = True
    min_interval = 0.0  # seconds between calls (free-tier rate limits)
    env_var = ""

    def __init__(self, api_key: str | None, cache: Cache, timeout: int = 20):
        self.api_key = api_key
        self.cache = cache
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    # -- to implement -------------------------------------------------
    def _lookup(self, ioc: IOC) -> ProviderResult:
        raise NotImplementedError

    # -- public ---------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(self.api_key) or not self.needs_key

    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported

    def lookup(self, ioc: IOC) -> ProviderResult:
        key = f"{self.name}:{ioc.type}:{ioc.value}"
        hit = self.cache.get(key)
        if hit is not None and "native" in hit:  # entries from older versions lack it: refetch
            return _from_cached(hit)
        try:
            result = self._lookup(ioc)
        except requests.RequestException as exc:
            return ProviderResult(self.name, ok=False, error=f"network error: {exc}")
        except Exception as exc:  # never let one provider kill the run
            return ProviderResult(self.name, ok=False, error=f"{type(exc).__name__}: {exc}")
        if not result.native:
            result.native = "no analysis data" if result.found else "not found"
        if result.ok:
            self.cache.set(key, result.to_dict())
        return result

    # -- helpers --------------------------------------------------------
    def _throttle(self) -> None:
        key = self.throttle_key or self.name
        with _THROTTLE_LOCK:
            wait = self.min_interval - (time.time() - _THROTTLE.get(key, 0.0))
            if wait > 0:
                time.sleep(wait)
            _THROTTLE[key] = time.time()

    def _request(self, method: str, url: str, **kw: Any) -> requests.Response:
        self._throttle()
        kw.setdefault("timeout", self.timeout)
        resp = self.session.request(method, url, **kw)
        if resp.status_code == 429:
            raise requests.RequestException("rate limited (HTTP 429)")
        if resp.status_code in (401, 403):
            raise requests.RequestException(f"auth rejected (HTTP {resp.status_code}) - check API key")
        return resp


def _from_cached(d: dict) -> ProviderResult:
    return ProviderResult(
        provider=d["provider"],
        ok=d["ok"],
        found=d["found"],
        error=d.get("error"),
        malicious_score=d.get("malicious_score"),
        tags=set(d["tags"]),
        malware=set(d["malware"]),
        actors=set(d["actors"]),
        techniques=set(d["techniques"]),
        context=d.get("context", {}),
        link=d.get("link"),
        native=d.get("native", ""),
    )
