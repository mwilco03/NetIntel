from __future__ import annotations

from typing import Any

import requests


class OpenSearchError(RuntimeError):
    """Raised when an OpenSearch request fails (HTTP error or transport error)."""


class OpenSearchClient:
    def __init__(
        self,
        base_url: str,
        *,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session if session is not None else requests.Session()
        if username:
            self.session.auth = (username, password or "")
        self.session.verify = verify_tls

    def search(
        self,
        index_pattern: str,
        body: dict,
        *,
        size: int | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/{index_pattern}/_search"
        params: dict[str, Any] = {}
        if size is not None:
            params["size"] = size
        try:
            response = self.session.post(url, json=body, params=params)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", "?")
            text = getattr(e.response, "text", "")
            raise OpenSearchError(f"OpenSearch HTTP {status}: {text}") from e
        except requests.RequestException as e:
            raise OpenSearchError(f"OpenSearch transport error: {e}") from e

    def cluster_info(self) -> dict[str, Any]:
        url = f"{self.base_url}/"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise OpenSearchError(f"OpenSearch transport error: {e}") from e
