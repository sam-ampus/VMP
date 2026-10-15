"""A minimal HTTP client behind a Protocol, so fetchers can be tested without a network.

Standard library only: fewer dependencies to approve for a FedRAMP boundary, and TLS comes
from the platform's OpenSSL (FIPS mode when the host enables it).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from vmp import __version__

USER_AGENT = f"vmp/{__version__}"
RETRY_STATUSES = {429, 500, 502, 503, 504}


class HttpClient(Protocol):
    def get_json(
        self, url: str, params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any: ...

    def post_json(self, url: str, body: Any) -> Any: ...


class UrllibClient:
    def __init__(
        self, timeout: float = 30.0, retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout, self.retries, self.sleep = timeout, retries, sleep

    def get_json(
        self, url: str, params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._send(urllib.request.Request(url, headers=self._headers(headers)))

    def post_json(self, url: str, body: Any) -> Any:
        data = json.dumps(body).encode()
        headers = self._headers({"Content-Type": "application/json"})
        return self._send(urllib.request.Request(url, data=data, headers=headers, method="POST"))

    def _headers(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        return {"User-Agent": USER_AGENT, "Accept": "application/json", **(extra or {})}

    def _send(self, req: urllib.request.Request) -> Any:
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRY_STATUSES or attempt == self.retries:
                    raise
            except urllib.error.URLError:
                if attempt == self.retries:
                    raise
            self.sleep(2.0**attempt)
        raise AssertionError("unreachable")
