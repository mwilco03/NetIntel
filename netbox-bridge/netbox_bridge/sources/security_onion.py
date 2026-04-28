"""Security Onion OpenSearch source.

Queries SO's logs-zeek-so data stream. Same ECS-aligned aggregation shape as the Malcolm source;
the difference is the index pattern and an explicit event.dataset filter (defaulting to "conn",
which gives the union of host+port+protocol observations).
"""
from __future__ import annotations

from datetime import timedelta

from ..model import Host
from ..opensearch import OpenSearchClient
from ._common import (
    aggregation_for_destination_ip,
    bucket_to_host,
    format_since,
)

DEFAULT_INDEX_PATTERN = "logs-zeek-so"
# Security Onion's default ingest pipelines (verified against
# Security-Onion-Solutions/securityonion master) include zeek.conn but not
# zeek.known_services or zeek.known_hosts — those Zeek policies aren't run
# by default. Keep "conn" as the safe default; expand via --datasets when
# a deployment is known to ingest more.
DEFAULT_DATASETS: list[str] = ["conn"]


def build_query(*, since: timedelta, datasets: list[str]) -> dict:
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": format_since(since)}}},
                    {"terms": {"event.dataset": list(datasets)}},
                ]
            }
        },
        "aggs": aggregation_for_destination_ip(),
    }


class SecurityOnionSource:
    def __init__(
        self,
        client: OpenSearchClient,
        *,
        index_pattern: str = DEFAULT_INDEX_PATTERN,
        datasets: list[str] | None = None,
    ) -> None:
        self.client = client
        self.index_pattern = index_pattern
        self.datasets = list(datasets) if datasets is not None else list(DEFAULT_DATASETS)

    def fetch_hosts(self, *, since: timedelta) -> list[Host]:
        body = build_query(since=since, datasets=self.datasets)
        response = self.client.search(self.index_pattern, body)
        buckets = (
            response.get("aggregations", {})
            .get("by_destination_ip", {})
            .get("buckets", [])
        )
        return [bucket_to_host(b, source="security_onion") for b in buckets]
