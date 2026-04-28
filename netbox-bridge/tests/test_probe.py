"""Tests for the OpenSearch probe / introspection orchestrator.

Probe is the pre-query check: given a source name and a target backend, it asks the backend itself
what indices exist, what fields are populated, and what event.dataset values it actually has data
for. That answers the "will my real query work here?" question before we run the real query.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from netbox_bridge.probe import (
    ProbeReport,
    REQUIRED_FIELDS,
    probe,
    render_human,
    render_json,
)


@dataclass
class _Index:
    name: str
    docs: int
    size: str


def _client_with_responses(
    *,
    cluster_name: str = "malcolm",
    cluster_status: str = "green",
    version: str = "2.11.0",
    indices: list[_Index] | None = None,
    fields_present: list[str] | None = None,
    field_types: dict[str, str] | None = None,
    datasets: dict[str, int] | None = None,
):
    client = MagicMock()
    client.cluster_info.return_value = {
        "cluster_name": cluster_name,
        "version": {"number": version},
        "tagline": "ok",
    }
    client.list_indices.return_value = [
        {"index": idx.name, "docs.count": str(idx.docs), "store.size": idx.size}
        for idx in (indices or [])
    ]
    field_types = field_types or {}
    fields_response = {
        "indices": [idx.name for idx in (indices or [])],
        "fields": {
            name: {field_types.get(name, "keyword"): {"type": field_types.get(name, "keyword")}}
            for name in (fields_present or [])
        },
    }
    client.field_caps.return_value = fields_response
    client.dataset_distribution.return_value = datasets or {}
    return client


class TestProbeReport:
    def test_required_fields_includes_destination_ip(self):
        # Sanity check on what a Malcolm/SO source actually needs to function.
        for required in ("destination.ip", "destination.port", "@timestamp", "event.dataset"):
            assert required in REQUIRED_FIELDS

    def test_ready_true_when_indices_exist_and_required_fields_present(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "i", "docs.count": "1", "store.size": "1b"}],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={"conn": 100},
        )
        assert report.ready is True

    def test_ready_false_when_no_indices(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={},
        )
        assert report.ready is False

    def test_ready_false_when_required_field_missing(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "i"}],
            fields_present=[],
            fields_missing=["destination.ip"],
            datasets={"conn": 100},
        )
        assert report.ready is False


class TestProbe:
    def test_collects_cluster_name_and_version(self):
        client = _client_with_responses(cluster_name="malcolm-cluster", version="2.11.0")
        report = probe(client, index_pattern="arkime_sessions3-*")
        assert report.cluster_name == "malcolm-cluster"
        assert report.version == "2.11.0"

    def test_lists_indices_matching_pattern(self):
        client = _client_with_responses(
            indices=[_Index("arkime-241124", 1234, "4.5gb"), _Index("arkime-241125", 5678, "5.1gb")]
        )
        report = probe(client, index_pattern="arkime-*")
        names = [i["index"] for i in report.indices]
        assert names == ["arkime-241124", "arkime-241125"]

    def test_classifies_required_fields_present_vs_missing(self):
        client = _client_with_responses(
            indices=[_Index("i", 1, "1b")],
            fields_present=["source.ip", "destination.ip", "@timestamp"],
            field_types={"source.ip": "ip", "destination.ip": "ip", "@timestamp": "date"},
        )
        report = probe(client, index_pattern="i")
        present = set(report.fields_present)
        missing = set(report.fields_missing)
        assert present.issuperset({"source.ip", "destination.ip", "@timestamp"})
        # destination.port, network.transport, network.protocol, event.dataset are missing
        assert missing == set(REQUIRED_FIELDS) - present

    def test_records_dataset_distribution(self):
        client = _client_with_responses(
            indices=[_Index("i", 1, "1b")],
            fields_present=list(REQUIRED_FIELDS),
            datasets={"conn": 1000, "dns": 200, "modbus": 50},
        )
        report = probe(client, index_pattern="i")
        assert report.datasets == {"conn": 1000, "dns": 200, "modbus": 50}

    def test_passes_since_to_dataset_distribution(self):
        client = _client_with_responses(indices=[_Index("i", 1, "1b")])
        probe(client, index_pattern="i", since="now-7d")
        assert client.dataset_distribution.call_args.kwargs["since"] == "now-7d"

    def test_ready_false_when_index_pattern_matches_nothing(self):
        client = _client_with_responses(indices=[])
        report = probe(client, index_pattern="i")
        assert report.ready is False

    def test_field_caps_queried_for_required_fields(self):
        client = _client_with_responses(indices=[_Index("i", 1, "1b")])
        probe(client, index_pattern="arkime-*")
        called_with = client.field_caps.call_args.args
        assert called_with[0] == "arkime-*"
        assert set(called_with[1]) == set(REQUIRED_FIELDS)


class TestRenderHuman:
    def _ready_report(self) -> ProbeReport:
        return ProbeReport(
            cluster_name="malcolm",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "arkime-241124", "docs.count": "100", "store.size": "1gb"}],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={"conn": 1000, "modbus": 50},
        )

    def test_includes_cluster_name_and_version(self):
        out = render_human(self._ready_report())
        assert "malcolm" in out
        assert "2.11.0" in out

    def test_lists_indices(self):
        out = render_human(self._ready_report())
        assert "arkime-241124" in out

    def test_lists_dataset_distribution(self):
        out = render_human(self._ready_report())
        assert "conn" in out
        assert "1000" in out
        assert "modbus" in out

    def test_says_ready_when_ready(self):
        out = render_human(self._ready_report())
        assert "READY" in out or "Ready" in out
        assert "NOT" not in out  # i.e. not "NOT READY"

    def test_says_not_ready_when_index_pattern_empty(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={},
        )
        out = render_human(report)
        assert "NOT READY" in out or "not ready" in out.lower()

    def test_says_not_ready_when_field_missing(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "i"}],
            fields_present=[],
            fields_missing=["destination.ip"],
            datasets={"conn": 1},
        )
        out = render_human(report)
        assert "destination.ip" in out
        assert "missing" in out.lower()


class TestRenderJson:
    def test_emits_valid_json(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[],
            fields_present=[],
            fields_missing=list(REQUIRED_FIELDS),
            datasets={},
        )
        json.loads(render_json(report))

    def test_includes_ready_flag(self):
        report = ProbeReport(
            cluster_name="x",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "i"}],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={"conn": 1},
        )
        parsed = json.loads(render_json(report))
        assert parsed["ready"] is True
