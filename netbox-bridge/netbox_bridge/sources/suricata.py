"""Suricata alert-count enrichment source.

Queries an OpenSearch backend for Suricata alert documents (event.kind == "alert") and
aggregates by destination.ip with sub-aggregations on event.severity (Suricata convention:
1=high, 2=medium, 3=low) and rule.signature_id.

Field paths verified against ECS-aligned ingest pipelines (Suricata EVE -> Filebeat ECS module
or Logstash mutate). Both Malcolm (arkime_sessions3-*) and Security Onion (logs-suricata-so)
populate these paths when ingesting Suricata. If a target deployment uses raw Suricata fields
(alert.severity, alert.signature_id) instead of ECS, override via custom field map — TODO future
slice.

This is an *enrichment* source (not a Host producer): it returns a dict[ip -> HostAlertCounts]
that the pipeline merges into Host.suricata_alerts before upsert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..opensearch import OpenSearchClient
from ._common import format_since

DEFAULT_INDEX_PATTERN = "arkime_sessions3-*"  # Malcolm default; override for SO ("logs-suricata-so")
DEFAULT_HOST_AGG_SIZE = 10000
DEFAULT_TOP_SIGNATURES = 5

# Suricata severity convention (NOT ECS — Suricata's own scale):
SEVERITY_HIGH = 1
SEVERITY_MEDIUM = 2
SEVERITY_LOW = 3


@dataclass
class AlertSignature:
    signature_id: int
    name: str | None
    count: int

    def to_dict(self) -> dict:
        return {"signature_id": self.signature_id, "name": self.name, "count": self.count}


@dataclass
class HostAlertCounts:
    total: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    top_signatures: list[AlertSignature] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "top_signatures": [s.to_dict() for s in self.top_signatures],
        }


def build_query(*, since: timedelta, top_signatures: int = DEFAULT_TOP_SIGNATURES) -> dict:
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.kind": "alert"}},
                    {"range": {"@timestamp": {"gte": format_since(since)}}},
                ]
            }
        },
        "aggs": {
            "by_destination_ip": {
                "terms": {"field": "destination.ip", "size": DEFAULT_HOST_AGG_SIZE},
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "event.severity", "size": 10},
                    },
                    "top_signatures": {
                        "terms": {"field": "rule.signature_id", "size": top_signatures},
                        "aggs": {
                            "name": {"terms": {"field": "rule.name", "size": 1}}
                        },
                    },
                },
            }
        },
    }


def _severity_count(buckets: list[dict], target_key: int) -> int:
    return sum(b.get("doc_count", 0) for b in buckets if b.get("key") == target_key)


def _bucket_to_alert_counts(bucket: dict[str, Any]) -> HostAlertCounts:
    severity_buckets = bucket.get("by_severity", {}).get("buckets", []) or []
    top_sids: list[AlertSignature] = []
    for sig_bucket in bucket.get("top_signatures", {}).get("buckets", []) or []:
        name_buckets = sig_bucket.get("name", {}).get("buckets", []) or []
        name = name_buckets[0]["key"] if name_buckets else None
        top_sids.append(
            AlertSignature(
                signature_id=int(sig_bucket["key"]),
                name=name,
                count=int(sig_bucket["doc_count"]),
            )
        )
    return HostAlertCounts(
        total=int(bucket.get("doc_count", 0)),
        high=_severity_count(severity_buckets, SEVERITY_HIGH),
        medium=_severity_count(severity_buckets, SEVERITY_MEDIUM),
        low=_severity_count(severity_buckets, SEVERITY_LOW),
        top_signatures=top_sids,
    )


class SuricataSource:
    def __init__(
        self,
        client: OpenSearchClient,
        *,
        index_pattern: str = DEFAULT_INDEX_PATTERN,
    ) -> None:
        self.client = client
        self.index_pattern = index_pattern

    def fetch_alert_counts(self, *, since: timedelta) -> dict[str, HostAlertCounts]:
        """Return a mapping of destination IP to HostAlertCounts for the time window."""
        body = build_query(since=since)
        response = self.client.search(self.index_pattern, body)
        buckets = (
            response.get("aggregations", {})
            .get("by_destination_ip", {})
            .get("buckets", [])
        )
        return {b["key"]: _bucket_to_alert_counts(b) for b in buckets}
