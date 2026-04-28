"""OpenSearch backend introspection.

Asks the backend itself what's there before issuing a real query: cluster info, indices matching
the pattern, which of our required fields are populated, and which event.dataset values have data.
This is the answer to "will my real query work in this deployment?".
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

REQUIRED_FIELDS: list[str] = [
    "@timestamp",
    "source.ip",
    "destination.ip",
    "destination.port",
    "network.transport",
    "network.protocol",
    "event.dataset",
]


class _ClientLike(Protocol):
    def cluster_info(self) -> dict[str, Any]: ...
    def list_indices(self, pattern: str) -> list[dict[str, Any]]: ...
    def field_caps(self, pattern: str, fields: list[str]) -> dict[str, Any]: ...
    def dataset_distribution(self, pattern: str, *, since: str | None = ...) -> dict[str, int]: ...


@dataclass
class ProbeReport:
    cluster_name: str
    cluster_status: str
    version: str
    indices: list[dict[str, Any]] = field(default_factory=list)
    fields_present: list[str] = field(default_factory=list)
    fields_missing: list[str] = field(default_factory=list)
    datasets: dict[str, int] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return bool(self.indices) and not self.fields_missing


def probe(
    client: _ClientLike,
    *,
    index_pattern: str,
    since: str | None = None,
) -> ProbeReport:
    info = client.cluster_info()
    cluster_name = info.get("cluster_name", "")
    version = info.get("version", {}).get("number", "")

    indices = client.list_indices(index_pattern)
    caps = client.field_caps(index_pattern, list(REQUIRED_FIELDS))
    fields_in_caps = set(caps.get("fields", {}).keys())
    fields_present = sorted(fields_in_caps & set(REQUIRED_FIELDS))
    fields_missing = sorted(set(REQUIRED_FIELDS) - fields_in_caps)

    datasets = client.dataset_distribution(index_pattern, since=since) if indices else {}

    return ProbeReport(
        cluster_name=cluster_name,
        cluster_status=info.get("status", ""),
        version=version,
        indices=indices,
        fields_present=fields_present,
        fields_missing=fields_missing,
        datasets=datasets,
    )


def _format_index(idx: dict[str, Any]) -> str:
    name = idx.get("index", "?")
    docs = idx.get("docs.count", "?")
    size = idx.get("store.size", "?")
    return f"  {name}  (docs: {docs}, size: {size})"


def render_human(report: ProbeReport) -> str:
    lines = [
        f"Cluster: {report.cluster_name} (OpenSearch {report.version})",
        "",
    ]
    if report.indices:
        lines.append(f"Indices ({len(report.indices)}):")
        for idx in report.indices:
            lines.append(_format_index(idx))
    else:
        lines.append("Indices: (none matching pattern)")
    lines.append("")

    lines.append("Required fields:")
    for f in report.fields_present:
        lines.append(f"  {f:25} present")
    for f in report.fields_missing:
        lines.append(f"  {f:25} MISSING")
    lines.append("")

    if report.datasets:
        lines.append("Populated event.dataset values:")
        for name, count in sorted(report.datasets.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name:25} {count}")
    else:
        lines.append("Populated event.dataset values: (none — backend may not populate this field)")
    lines.append("")

    if report.ready:
        lines.append("Status: READY — required fields present, indices exist.")
    else:
        reason = []
        if not report.indices:
            reason.append("no indices match the pattern")
        if report.fields_missing:
            reason.append(f"missing fields: {', '.join(report.fields_missing)}")
        lines.append(f"Status: NOT READY — {'; '.join(reason)}.")

    return "\n".join(lines)


def render_json(report: ProbeReport) -> str:
    return json.dumps({**asdict(report), "ready": report.ready}, indent=2)
