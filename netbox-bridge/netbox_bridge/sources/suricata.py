"""Suricata alert-count enrichment source.

Queries an OpenSearch backend for Suricata alert documents (event.kind=alert) and aggregates by
destination.ip with sub-aggregations on event.severity and rule.id.

Field paths verified against upstream on 2026-04-29:

  Filebeat Suricata module ingest pipeline (Elastic / Security Onion):
    https://raw.githubusercontent.com/elastic/beats/main/x-pack/filebeat/module/suricata/eve/ingest/pipeline.yml
      alert.severity     -> event.severity   (preserves Suricata's 1=high/2=medium/3=low scale)
      alert.signature_id -> rule.id
      alert.signature    -> rule.name
      alert.category     -> rule.category

  Malcolm logstash Suricata pipeline:
    https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/suricata/11_suricata_logs.conf
      [suricata][alert][signature_id] -> [rule][id]
      [suricata][alert][signature]    -> [rule][name]
      [suricata][alert][category]     -> [rule][category]
      [event][kind] = "alert" when event_type == "alert"

  Malcolm severity transform (NOTE: NOT Suricata's native scale):
    https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/suricata/19_severity.conf
      [suricata][alert][severity] (1..4) -> [event][severity] = 91 - ((sev-1)*20)
      So Malcolm produces event.severity in {91, 71, 51, 31, 11} — NOT 1/2/3.
      Filebeat-based deployments (Security Onion) preserve 1/2/3.

Severity bucket constants below assume Filebeat's preserved scale. For Malcolm, override via
SuricataSource(severity_mapping={91: 'high', 71: 'medium', 51: 'low'}). TODO future slice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..opensearch import OpenSearchClient
from ._common import format_since

DEFAULT_INDEX_PATTERN = "arkime_sessions3-*"
DEFAULT_HOST_AGG_SIZE = 10000
DEFAULT_TOP_SIGNATURES = 5

# Filebeat preserves Suricata's native scale. Malcolm rewrites it (see module docstring).
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
                        "terms": {"field": "rule.id", "size": top_signatures},
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
