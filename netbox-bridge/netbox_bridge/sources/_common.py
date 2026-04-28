"""Shared helpers for OpenSearch-backed sources (Malcolm, Security Onion).

Both currently aggregate by destination.ip → destination.port → network.transport / .protocol.
The agg shape is identical, so the bucket-to-Host mapping lives here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from ..model import Host, Service

SourceTag = Literal["malcolm", "security_onion"]


def format_since(since: timedelta) -> str:
    total_seconds = int(since.total_seconds())
    if total_seconds % 86400 == 0:
        return f"now-{total_seconds // 86400}d"
    if total_seconds % 3600 == 0:
        return f"now-{total_seconds // 3600}h"
    if total_seconds % 60 == 0:
        return f"now-{total_seconds // 60}m"
    return f"now-{total_seconds}s"


def top_bucket_key(agg: dict[str, Any]) -> Any | None:
    buckets = agg.get("buckets") or []
    if not buckets:
        return None
    return buckets[0].get("key")


def parse_last_seen(agg: dict[str, Any]) -> datetime:
    raw = agg.get("value_as_string")
    if raw:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    millis = agg.get("value")
    if millis is not None:
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
    return datetime.now(tz=timezone.utc)


def bucket_to_host(bucket: dict[str, Any], *, source: SourceTag) -> Host:
    ip = bucket["key"]
    observed_at = parse_last_seen(bucket.get("last_seen", {}))

    services: list[Service] = []
    for port_bucket in bucket.get("by_port", {}).get("buckets", []):
        transport = top_bucket_key(port_bucket.get("by_transport", {}))
        if transport not in {"tcp", "udp"}:
            continue
        protocol_name = top_bucket_key(port_bucket.get("by_protocol", {}))
        services.append(
            Service(
                port=int(port_bucket["key"]),
                protocol=transport,
                name=protocol_name,
            )
        )

    return Host(
        primary_ip=ip,
        services=services,
        source=source,
        observed_at=observed_at,
    )


def aggregation_for_destination_ip(
    *,
    host_size: int = 10000,
    port_size: int = 100,
) -> dict[str, Any]:
    return {
        "by_destination_ip": {
            "terms": {"field": "destination.ip", "size": host_size},
            "aggs": {
                "by_port": {
                    "terms": {"field": "destination.port", "size": port_size},
                    "aggs": {
                        "by_transport": {"terms": {"field": "network.transport", "size": 5}},
                        "by_protocol": {"terms": {"field": "network.protocol", "size": 10}},
                    },
                },
                "last_seen": {"max": {"field": "@timestamp"}},
            },
        }
    }
