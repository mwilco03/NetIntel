"""Tests for the Malcolm OpenSearch source.

The OpenSearchClient is replaced with a stub that returns a captured response fixture, so we
test the query construction and response→Host mapping without hitting a real OpenSearch.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netbox_bridge.sources.malcolm import (
    DEFAULT_INDEX_PATTERN,
    MalcolmSource,
    build_query,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def known_services_response() -> dict:
    return json.loads((FIXTURES / "malcolm_known_services_response.json").read_text())


@pytest.fixture
def stub_client(known_services_response):
    client = MagicMock()
    client.search.return_value = known_services_response
    return client


class TestBuildQuery:
    def test_size_zero_we_only_want_aggregations(self):
        q = build_query(since=timedelta(days=7))
        assert q["size"] == 0

    def test_filters_by_time_range(self):
        q = build_query(since=timedelta(days=7))
        filters = q["query"]["bool"]["filter"]
        ranges = [f for f in filters if "range" in f]
        assert ranges
        assert ranges[0]["range"]["@timestamp"]["gte"] == "now-7d"

    def test_aggregates_by_destination_ip(self):
        q = build_query(since=timedelta(days=1))
        assert "by_destination_ip" in q["aggs"]
        assert q["aggs"]["by_destination_ip"]["terms"]["field"] == "destination.ip"

    def test_per_ip_aggregates_ports(self):
        q = build_query(since=timedelta(days=1))
        sub = q["aggs"]["by_destination_ip"]["aggs"]
        assert "by_port" in sub
        assert sub["by_port"]["terms"]["field"] == "destination.port"

    def test_per_port_subaggregates_transport_and_protocol(self):
        q = build_query(since=timedelta(days=1))
        port_aggs = q["aggs"]["by_destination_ip"]["aggs"]["by_port"]["aggs"]
        assert port_aggs["by_transport"]["terms"]["field"] == "network.transport"
        assert port_aggs["by_protocol"]["terms"]["field"] == "network.protocol"

    def test_includes_last_seen_max_aggregation(self):
        q = build_query(since=timedelta(days=1))
        sub = q["aggs"]["by_destination_ip"]["aggs"]
        assert sub["last_seen"]["max"]["field"] == "@timestamp"

    def test_since_24_hours_renders_as_now_minus_1d(self):
        q = build_query(since=timedelta(hours=24))
        filters = q["query"]["bool"]["filter"]
        ranges = [f for f in filters if "range" in f]
        assert ranges[0]["range"]["@timestamp"]["gte"] == "now-1d"

    def test_since_2_hours_renders_as_now_minus_2h(self):
        q = build_query(since=timedelta(hours=2))
        filters = q["query"]["bool"]["filter"]
        ranges = [f for f in filters if "range" in f]
        assert ranges[0]["range"]["@timestamp"]["gte"] == "now-2h"


class TestMalcolmSourceFetch:
    def test_uses_default_index_pattern(self, stub_client):
        source = MalcolmSource(stub_client)
        source.fetch_hosts(since=timedelta(days=7))
        assert stub_client.search.call_args.args[0] == DEFAULT_INDEX_PATTERN

    def test_default_pattern_is_arkime_sessions(self):
        assert DEFAULT_INDEX_PATTERN == "arkime_sessions3-*"

    def test_custom_index_pattern_supported(self, stub_client):
        source = MalcolmSource(stub_client, index_pattern="custom-*")
        source.fetch_hosts(since=timedelta(days=7))
        assert stub_client.search.call_args.args[0] == "custom-*"

    def test_emits_one_host_per_destination_ip(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = source.fetch_hosts(since=timedelta(days=7))
        ips = [h.primary_ip for h in hosts]
        assert sorted(ips) == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    def test_host_services_match_fixture(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        ports = sorted(s.port for s in host_5.services)
        assert ports == [22, 443]

    def test_service_transport_picked_from_top_bucket(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        transports = {s.protocol for s in host_5.services}
        assert transports == {"tcp"}

    def test_service_name_picked_from_protocol_bucket(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        # Modbus on 10.0.0.6:502 — proves we pick up custom-parser protocols too
        host_6 = hosts["10.0.0.6"]
        modbus = [s for s in host_6.services if s.port == 502]
        assert modbus and modbus[0].name == "modbus"

    def test_udp_transport_preserved(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        # 10.0.0.7:53/udp dns
        host_7 = hosts["10.0.0.7"]
        assert len(host_7.services) == 1
        assert host_7.services[0].port == 53
        assert host_7.services[0].protocol == "udp"
        assert host_7.services[0].name == "dns"

    def test_host_observed_at_uses_last_seen(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        # 10.0.0.5's last_seen in fixture is 2026-04-25T10:00:00.000Z
        assert hosts["10.0.0.5"].observed_at.isoformat().startswith("2026-04-25T10:00:00")

    def test_host_source_is_malcolm(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = source.fetch_hosts(since=timedelta(days=7))
        assert all(h.source == "malcolm" for h in hosts)

    def test_empty_aggregations_returns_no_hosts(self):
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {
                "by_destination_ip": {"buckets": []}
            },
        }
        source = MalcolmSource(client)
        assert source.fetch_hosts(since=timedelta(days=1)) == []

    def test_skips_unsupported_transports(self):
        # If a record has e.g. transport "icmp", we only emit tcp/udp services
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 1}, "hits": []},
            "aggregations": {
                "by_destination_ip": {
                    "buckets": [
                        {
                            "key": "10.0.0.99",
                            "doc_count": 1,
                            "last_seen": {
                                "value_as_string": "2026-04-25T10:00:00.000Z",
                                "value": 1745568000000,
                            },
                            "by_port": {
                                "buckets": [
                                    {
                                        "key": 0,
                                        "doc_count": 1,
                                        "by_transport": {
                                            "buckets": [{"key": "icmp", "doc_count": 1}]
                                        },
                                        "by_protocol": {
                                            "buckets": [{"key": "icmp", "doc_count": 1}]
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        }
        source = MalcolmSource(client)
        hosts = source.fetch_hosts(since=timedelta(days=1))
        assert len(hosts) == 1
        assert hosts[0].services == []
