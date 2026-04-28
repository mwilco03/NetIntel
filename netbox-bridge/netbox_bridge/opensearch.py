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

    def list_indices(self, pattern: str) -> list[dict[str, Any]]:
        """GET /_cat/indices/<pattern>?format=json — index name, doc count, store size."""
        url = f"{self.base_url}/_cat/indices/{pattern}"
        try:
            response = self.session.get(url, params={"format": "json"})
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", "?")
            text = getattr(e.response, "text", "")
            raise OpenSearchError(f"OpenSearch HTTP {status}: {text}") from e
        except requests.RequestException as e:
            raise OpenSearchError(f"OpenSearch transport error: {e}") from e

    def field_caps(self, pattern: str, fields: list[str]) -> dict[str, Any]:
        """GET /<pattern>/_field_caps?fields=...  — confirm field existence and types."""
        url = f"{self.base_url}/{pattern}/_field_caps"
        try:
            response = self.session.get(url, params={"fields": ",".join(fields)})
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", "?")
            text = getattr(e.response, "text", "")
            raise OpenSearchError(f"OpenSearch HTTP {status}: {text}") from e
        except requests.RequestException as e:
            raise OpenSearchError(f"OpenSearch transport error: {e}") from e

    def dataset_distribution(
        self,
        pattern: str,
        *,
        since: str | None = None,
    ) -> dict[str, int]:
        """Terms aggregation on event.dataset — which datasets are populated, with doc counts."""
        body: dict[str, Any] = {
            "size": 0,
            "aggs": {
                "datasets": {"terms": {"field": "event.dataset", "size": 100}}
            },
        }
        if since is not None:
            body["query"] = {
                "bool": {"filter": [{"range": {"@timestamp": {"gte": since}}}]}
            }
        response = self.search(pattern, body)
        buckets = response.get("aggregations", {}).get("datasets", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}
