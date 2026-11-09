"""Public, keyless data sources: the official MCP Registry, deps.dev and the npm registry.

Every response is cached on disk (one JSON file per URL) so a study can be re-scored
offline and re-runs do not hit the APIs again.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
DEPSDEV = "https://api.deps.dev/v3"
NPM = "https://registry.npmjs.org"
UA = "mcp-posture/0.1 (+https://github.com/Mohith26/mcp-posture)"


class Fetcher:
    def __init__(self, cache_dir: Path | None, sleep: float = 0.0, offline: bool = False):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.sleep = sleep
        self.offline = offline
        self.network_calls = 0
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, url: str) -> Path | None:
        if not self.cache_dir:
            return None
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def get_json(self, url: str):
        """GET url as JSON. Returns None for 404. Cached, including 404s."""
        path = self._path(url)
        if path and path.exists():
            rec = json.loads(path.read_text())
            return rec["body"]
        if self.offline:
            raise LookupError(f"not cached (offline): {url}")
        body = None
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    body = None
                    break
                if exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                if attempt < 3:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
        self.network_calls += 1
        if path:
            path.write_text(json.dumps({"url": url, "body": body}))
        if self.sleep:
            time.sleep(self.sleep)
        return body


def _post_cached(self, url: str, body: dict):
    key = url + "\n" + json.dumps(body, sort_keys=True)
    path = self._path(key)
    if path and path.exists():
        return json.loads(path.read_text())["body"]
    if self.offline:
        raise LookupError(f"not cached (offline): POST {url}")
    data = json.dumps(body).encode()
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"User-Agent": UA, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                out = json.loads(resp.read())
            break
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))
    self.network_calls += 1
    if path:
        path.write_text(json.dumps({"url": url, "body": out}))
    return out


Fetcher.post_json = _post_cached


def registry_latest(f: Fetcher, max_pages: int = 5000) -> list[dict]:
    """All latest server.json documents from the official MCP Registry."""
    out, cursor = [], None
    for _ in range(max_pages):
        q = {"limit": "100", "version": "latest"}
        if cursor:
            q["cursor"] = cursor
        page = f.get_json(REGISTRY + "?" + urllib.parse.urlencode(q))
        if not page:
            break
        out.extend(s["server"] for s in page.get("servers", []))
        cursor = (page.get("metadata") or {}).get("nextCursor")
        if not cursor:
            break
    return out


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def depsdev_dependencies(f: Fetcher, system: str, name: str, version: str):
    return f.get_json(f"{DEPSDEV}/systems/{system}/packages/{_q(name)}/versions/{_q(version)}:dependencies")


def depsdev_version(f: Fetcher, system: str, name: str, version: str):
    return f.get_json(f"{DEPSDEV}/systems/{system}/packages/{_q(name)}/versions/{_q(version)}")


def depsdev_advisory(f: Fetcher, key: str):
    return f.get_json(f"{DEPSDEV}/advisories/{_q(key)}")


def npm_version_manifest(f: Fetcher, name: str, version: str):
    return f.get_json(f"{NPM}/{name.replace('/', '%2f')}/{_q(version)}")
