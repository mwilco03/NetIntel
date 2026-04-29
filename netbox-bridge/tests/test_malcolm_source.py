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
        # Captured response from real OpenSearch: 10.0.0.5 has http(80) + modbus(502).
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        ports = sorted(s.port for s in host_5.services)
        assert ports == [80, 502]

    def test_service_transport_picked_from_top_bucket(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        transports = {s.protocol for s in host_5.services}
        assert transports == {"tcp"}

    def test_service_name_picked_from_protocol_bucket(self, stub_client):
        # Captured: 10.0.0.5 has port 502 → modbus, proving Zeek custom-parser protocols
        # land in network.protocol verbatim.
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        modbus = [s for s in host_5.services if s.port == 502]
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
        # Captured fixture: 10.0.0.5 last_seen is in the response under aggregations[buckets][0]
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        # observed_at must be a real datetime (not the now() fallback)
        assert hosts["10.0.0.5"].observed_at.year == 2026

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


class TestSourceSideMacExtraction:
    def test_query_includes_destination_mac_subagg(self, stub_client):
        source = MalcolmSource(stub_client)
        source.fetch_hosts(since=timedelta(days=7))
        body = stub_client.search.call_args.args[1]
        sub = body["aggs"]["by_destination_ip"]["aggs"]
        assert "by_mac" in sub
        assert sub["by_mac"]["terms"]["field"] == "destination.mac"

    def test_host_interfaces_populated_from_mac_bucket(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_5 = hosts["10.0.0.5"]
        assert len(host_5.interfaces) == 1
        assert host_5.interfaces[0].mac == "00:0e:8c:11:22:33"

    def test_host_interfaces_empty_when_no_mac_bucket(self, stub_client):
        source = MalcolmSource(stub_client)
        hosts = {h.primary_ip: h for h in source.fetch_hosts(since=timedelta(days=7))}
        host_7 = hosts["10.0.0.7"]
        # 10.0.0.7's by_mac bucket in fixture is empty
        assert host_7.interfaces == []

    def test_multiple_mac_buckets_all_populate_interfaces(self):
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 1}, "hits": []},
            "aggregations": {
                "by_destination_ip": {
                    "buckets": [
                        {
                            "key": "10.0.0.50",
                            "doc_count": 100,
                            "last_seen": {
                                "value_as_string": "2026-04-25T10:00:00.000Z",
                                "value": 1745568000000,
                            },
                            "by_mac": {
                                "buckets": [
                                    {"key": "aa:bb:cc:dd:ee:01", "doc_count": 60},
                                    {"key": "aa:bb:cc:dd:ee:02", "doc_count": 40},
                                ]
                            },
                            "by_port": {"buckets": []},
                        }
                    ]
                }
            },
        }
        source = MalcolmSource(client)
        hosts = source.fetch_hosts(since=timedelta(days=1))
        assert len(hosts) == 1
        macs = [iface.mac for iface in hosts[0].interfaces]
        assert macs == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]

    def test_missing_mac_bucket_field_does_not_crash(self):
        # Older Malcolm versions or deployments without L2 capture may not have destination.mac.
        # The source must produce a Host with empty interfaces, not raise.
        client = MagicMock()
        client.search.return_value = {
            "hits": {"total": {"value": 1}, "hits": []},
            "aggregations": {
                "by_destination_ip": {
                    "buckets": [
                        {
                            "key": "10.0.0.51",
                            "doc_count": 100,
                            "last_seen": {
                                "value_as_string": "2026-04-25T10:00:00.000Z",
                                "value": 1745568000000,
                            },
                            "by_port": {"buckets": []},
                            # NO by_mac bucket at all
                        }
                    ]
                }
            },
        }
        source = MalcolmSource(client)
        hosts = source.fetch_hosts(since=timedelta(days=1))
        assert hosts[0].interfaces == []
