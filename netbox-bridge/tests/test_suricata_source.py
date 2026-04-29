"""Tests for Suricata alert-count enrichment source."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netbox_bridge.sources.suricata import (
    DEFAULT_INDEX_PATTERN,
    AlertSignature,
    HostAlertCounts,
    SuricataSource,
    build_query,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def alert_response() -> dict:
    return json.loads((FIXTURES / "suricata_alerts_response.json").read_text())


@pytest.fixture
def stub_client(alert_response):
    client = MagicMock()
    client.search.return_value = alert_response
    return client


class TestBuildQuery:
    def test_filters_on_event_kind_alert(self):
        q = build_query(since=timedelta(days=7))
        filters = q["query"]["bool"]["filter"]
        terms = [f for f in filters if "term" in f]
        assert {"term": {"event.kind": "alert"}} in terms

    def test_filters_on_time_range(self):
        q = build_query(since=timedelta(days=7))
        ranges = [f for f in q["query"]["bool"]["filter"] if "range" in f]
        assert ranges[0]["range"]["@timestamp"]["gte"] == "now-7d"

    def test_aggregates_by_destination_ip(self):
        q = build_query(since=timedelta(days=1))
        assert q["aggs"]["by_destination_ip"]["terms"]["field"] == "destination.ip"

    def test_subaggregates_event_severity(self):
        q = build_query(since=timedelta(days=1))
        sub = q["aggs"]["by_destination_ip"]["aggs"]
        assert sub["by_severity"]["terms"]["field"] == "event.severity"

    def test_subaggregates_rule_id(self):
        # alert.signature_id -> rule.id per Filebeat Suricata module ingest pipeline AND Malcolm
        # logstash/pipelines/suricata/11_suricata_logs.conf. NOT rule.signature_id.
        q = build_query(since=timedelta(days=1))
        sub = q["aggs"]["by_destination_ip"]["aggs"]
        assert sub["top_signatures"]["terms"]["field"] == "rule.id"

    def test_size_zero(self):
        q = build_query(since=timedelta(days=1))
        assert q["size"] == 0


class TestSuricataSourceFetch:
    def test_uses_default_index_pattern_for_malcolm(self, stub_client):
        source = SuricataSource(stub_client)
        source.fetch_alert_counts(since=timedelta(days=7))
        assert stub_client.search.call_args.args[0] == DEFAULT_INDEX_PATTERN

    def test_default_pattern_is_arkime_sessions(self):
        assert DEFAULT_INDEX_PATTERN == "arkime_sessions3-*"

    def test_custom_index_pattern_supported(self, stub_client):
        source = SuricataSource(stub_client, index_pattern="logs-suricata-so")
        source.fetch_alert_counts(since=timedelta(days=7))
        assert stub_client.search.call_args.args[0] == "logs-suricata-so"

    def test_emits_one_entry_per_destination_ip(self, stub_client):
        source = SuricataSource(stub_client)
        result = source.fetch_alert_counts(since=timedelta(days=7))
        assert sorted(result.keys()) == ["10.0.0.5", "10.0.0.6"]

    def test_total_count_from_doc_count(self, stub_client):
        # Captured fixture: 10.0.0.5 has 100 alerts, 10.0.0.6 has 50.
        source = SuricataSource(stub_client)
        result = source.fetch_alert_counts(since=timedelta(days=7))
        assert result["10.0.0.5"].total == 100
        assert result["10.0.0.6"].total == 50

    def test_severity_breakdown(self, stub_client):
        # Captured fixture follows Filebeat scale: 10.0.0.5 has 20 high (sev=1), 80 medium (sev=2)
        # and 0 low. 10.0.0.6 is all low (sev=3).
        source = SuricataSource(stub_client)
        result = source.fetch_alert_counts(since=timedelta(days=7))
        host5 = result["10.0.0.5"]
        assert host5.high == 20
        assert host5.medium == 80
        assert host5.low == 0

    def test_severity_only_low(self, stub_client):
        source = SuricataSource(stub_client)
        result = source.fetch_alert_counts(since=timedelta(days=7))
        host6 = result["10.0.0.6"]
        assert host6.high == 0
        assert host6.medium == 0
        assert host6.low == 50

    def test_top_signatures_extracted(self, stub_client):
        # Captured fixture: top sig on 10.0.0.5 by count is 2024900 (80 medium alerts).
        # OpenSearch returns rule.id as a string in the bucket key — int() cast required.
        source = SuricataSource(stub_client)
        result = source.fetch_alert_counts(since=timedelta(days=7))
        sigs = result["10.0.0.5"].top_signatures
        assert len(sigs) == 2
        assert sigs[0].signature_id == 2024900
        assert sigs[0].count == 80
        assert "ET INFO" in sigs[0].name

    def test_empty_response_returns_empty_dict(self):
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"by_destination_ip": {"buckets": []}},
        }
        source = SuricataSource(client)
        assert source.fetch_alert_counts(since=timedelta(days=1)) == {}


class TestHostAlertCountsSerialization:
    def test_to_dict_round_trips(self):
        counts = HostAlertCounts(
            total=10, high=2, medium=5, low=3,
            top_signatures=[AlertSignature(signature_id=2027865, name="X", count=10)],
        )
        d = counts.to_dict()
        assert d["total"] == 10
        assert d["high"] == 2
        assert d["top_signatures"][0]["signature_id"] == 2027865
        json.dumps(d)  # serializable
