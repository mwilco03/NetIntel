"""Malcolm OpenSearch source.

Pulls Zeek/Suricata/Arkime data from Malcolm's OpenSearch backend (default index pattern
arkime_sessions3-*) and emits normalized Host records.

Malcolm runs Zeek with custom parsers (modbus, dnp3, bacnet, s7comm, etc.). We don't hardcode
network.protocol values — whatever Zeek labeled the traffic as, that's what shows up on the
Service.name. The aggregation keys on destination.ip so the host whose service was observed
becomes the Host primary_ip.
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

DEFAULT_INDEX_PATTERN = "arkime_sessions3-*"


def build_query(since: timedelta) -> dict:
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": format_since(since)}}},
                ]
            }
        },
        "aggs": aggregation_for_destination_ip(),
    }


class MalcolmSource:
    def __init__(
        self,
        client: OpenSearchClient,
        *,
        index_pattern: str = DEFAULT_INDEX_PATTERN,
    ) -> None:
        self.client = client
        self.index_pattern = index_pattern

    def fetch_hosts(self, *, since: timedelta) -> list[Host]:
        body = build_query(since)
        response = self.client.search(self.index_pattern, body)
        buckets = (
            response.get("aggregations", {})
            .get("by_destination_ip", {})
            .get("buckets", [])
        )
        return [bucket_to_host(b, source="malcolm") for b in buckets]
