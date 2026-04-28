"""Tests for the Security Onion source.

Same response shape as Malcolm — both are ECS-aligned aggregation responses against destination.ip.
The differences live in: index pattern (logs-zeek-so), an event.dataset filter, and the source tag.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netbox_bridge.sources.security_onion import (
    DEFAULT_DATASETS,
    DEFAULT_INDEX_PATTERN,
    SecurityOnionSource,
    build_query,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def conn_response() -> dict:
    return json.loads((FIXTURES / "security_onion_conn_response.json").read_text())


@pytest.fixture
def stub_client(conn_response):
    client = MagicMock()
    client.search.return_value = conn_response
    return client


class TestBuildQuery:
    def test_default_index_pattern_is_so_zeek_data_stream(self):
        assert DEFAULT_INDEX_PATTERN == "logs-zeek-so"

    def test_default_datasets_filter_includes_conn(self):
        assert "conn" in DEFAULT_DATASETS

    def test_query_filters_by_event_dataset(self):
        q = build_query(since=timedelta(days=7), datasets=["conn", "known_services"])
        filters = q["query"]["bool"]["filter"]
        terms_filters = [f for f in filters if "terms" in f]
        assert terms_filters
        assert terms_filters[0]["terms"]["event.dataset"] == ["conn", "known_services"]

    def test_query_filters_by_time_range(self):
        q = build_query(since=timedelta(hours=2), datasets=["conn"])
        filters = q["query"]["bool"]["filter"]
        ranges = [f for f in filters if "range" in f]
        assert ranges
        assert ranges[0]["range"]["@timestamp"]["gte"] == "now-2h"

    def test_query_aggregates_by_destination_ip(self):
        q = build_query(since=timedelta(days=1), datasets=["conn"])
        assert q["aggs"]["by_destination_ip"]["terms"]["field"] == "destination.ip"

    def test_size_is_zero(self):
        q = build_query(since=timedelta(days=1), datasets=["conn"])
        assert q["size"] == 0


class TestSecurityOnionSourceFetch:
    def test_uses_default_index_pattern(self, stub_client):
        source = SecurityOnionSource(stub_client)
        source.fetch_hosts(since=timedelta(days=7))
        assert stub_client.search.call_args.args[0] == "logs-zeek-so"

    def test_custom_index_pattern_supported(self, stub_client):
        source = SecurityOnionSource(stub_client, index_pattern="logs-custom-so")
        source.fetch_hosts(since=timedelta(days=1))
        assert stub_client.search.call_args.args[0] == "logs-custom-so"

    def test_custom_datasets_supported(self, stub_client):
        source = SecurityOnionSource(stub_client, datasets=["known_services"])
        source.fetch_hosts(since=timedelta(days=1))
        body = stub_client.search.call_args.args[1]
        terms = [f for f in body["query"]["bool"]["filter"] if "terms" in f]
        assert terms[0]["terms"]["event.dataset"] == ["known_services"]

    def test_emits_one_host_per_destination_ip(self, stub_client):
        source = SecurityOnionSource(stub_client)
        hosts = source.fetch_hosts(since=timedelta(days=7))
        ips = sorted(h.primary_ip for h in hosts)
        assert ips == ["192.168.1.10", "192.168.1.20"]

    def test_host_services_match_fixture(self, stub_client):
        source = SecurityOnionSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        web = hosts["192.168.1.10"]
        ports = sorted(s.port for s in web.services)
        assert ports == [80, 443]

    def test_host_source_is_security_onion(self, stub_client):
        source = SecurityOnionSource(stub_client)
        hosts = source.fetch_hosts(since=timedelta(days=1))
        assert all(h.source == "security_onion" for h in hosts)

    def test_service_protocol_name_preserved(self, stub_client):
        source = SecurityOnionSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=1))}
        rdp_host = hosts["192.168.1.20"]
        assert rdp_host.services[0].name == "rdp"

    def test_empty_aggregations_returns_no_hosts(self):
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"by_destination_ip": {"buckets": []}},
        }
        source = SecurityOnionSource(client)
        assert source.fetch_hosts(since=timedelta(days=1)) == []
