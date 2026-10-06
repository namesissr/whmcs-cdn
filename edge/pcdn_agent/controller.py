"""The controller API client (/edge/v1/*)."""

import json
import urllib.error
import urllib.request


class Controller:
    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body=None, headers=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("User-Agent", "pcdn-agent/2.0")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, dict(r.headers), (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, dict(e.headers), None
            raise
