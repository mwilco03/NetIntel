"""Tests for the OpenSearch HTTP client.

The session is injected so we can assert exact request shape without hitting a real OpenSearch.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from netbox_bridge.opensearch import OpenSearchClient, OpenSearchError


def _client_with_mock_session(**kwargs) -> tuple[OpenSearchClient, MagicMock]:
    session = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    response.raise_for_status.return_value = None
    session.post.return_value = response
    client = OpenSearchClient("https://os.example.com:9200", session=session, **kwargs)
    return client, session


class TestOpenSearchClient:
    def test_strips_trailing_slash_from_base_url(self):
        client, _ = _client_with_mock_session()
        assert client.base_url == "https://os.example.com:9200"

        session = MagicMock()
        client = OpenSearchClient("https://os.example.com:9200/", session=session)
        assert client.base_url == "https://os.example.com:9200"

    def test_basic_auth_applied_to_session(self):
        session = MagicMock()
        OpenSearchClient(
            "https://os.example.com",
            username="admin",
            password="hunter2",
            session=session,
        )
        assert session.auth == ("admin", "hunter2")

    def test_no_auth_when_no_username(self):
        session = MagicMock()
        OpenSearchClient("https://os.example.com", session=session)
        # session.auth should not be set (we never assigned it)
        assert not isinstance(session.auth, tuple)

    def test_verify_tls_propagates_to_session(self):
        session = MagicMock()
        OpenSearchClient("https://os.example.com", verify_tls=False, session=session)
        assert session.verify is False

    def test_search_posts_to_correct_url(self):
        client, session = _client_with_mock_session()
        client.search("logs-zeek-so", {"query": {"match_all": {}}})
        url = session.post.call_args.args[0]
        assert url == "https://os.example.com:9200/logs-zeek-so/_search"

    def test_search_sends_body_as_json(self):
        client, session = _client_with_mock_session()
        body = {"query": {"term": {"event.dataset": "known_services"}}}
        client.search("idx-*", body)
        assert session.post.call_args.kwargs["json"] == body

    def test_search_returns_parsed_response(self):
        client, session = _client_with_mock_session()
        session.post.return_value.json.return_value = {"hits": {"hits": [{"_id": "1"}]}}
        result = client.search("idx", {})
        assert result == {"hits": {"hits": [{"_id": "1"}]}}

    def test_search_size_param_propagates(self):
        client, session = _client_with_mock_session()
        client.search("idx", {}, size=500)
        params = session.post.call_args.kwargs.get("params", {})
        assert params.get("size") == 500

    def test_search_no_size_param_when_unspecified(self):
        client, session = _client_with_mock_session()
        client.search("idx", {})
        params = session.post.call_args.kwargs.get("params") or {}
        assert "size" not in params

    def test_search_raises_open_search_error_on_http_failure(self):
        client, session = _client_with_mock_session()

        import requests

        bad_response = MagicMock()
        bad_response.status_code = 401
        bad_response.text = "unauthorized"
        bad_response.raise_for_status.side_effect = requests.HTTPError(
            "401", response=bad_response
        )
        session.post.return_value = bad_response

        with pytest.raises(OpenSearchError) as excinfo:
            client.search("idx", {})
        assert "401" in str(excinfo.value)

    def test_search_raises_open_search_error_on_connection_failure(self):
        client, session = _client_with_mock_session()

        import requests

        session.post.side_effect = requests.ConnectionError("DNS failure")
        with pytest.raises(OpenSearchError):
            client.search("idx", {})

    def test_default_session_is_requests_session(self):
        client = OpenSearchClient("https://os.example.com")
        import requests

        assert isinstance(client.session, requests.Session)

    def test_supports_basic_health_check(self):
        client, session = _client_with_mock_session()
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {
            "cluster_name": "malcolm",
            "status": "green",
            "version": {"number": "2.11.0"},
        }
        info = client.cluster_info()
        url = session.get.call_args.args[0]
        assert url == "https://os.example.com:9200/"
        assert info["cluster_name"] == "malcolm"


class TestIntrospection:
    def test_list_indices_calls_cat_indices_with_pattern(self):
        client, session = _client_with_mock_session()
        session.get.return_value.json.return_value = [
            {"index": "arkime_sessions3-241124", "docs.count": "1234567", "store.size": "4.5gb"},
        ]
        result = client.list_indices("arkime_sessions3-*")
        url = session.get.call_args.args[0]
        assert url == "https://os.example.com:9200/_cat/indices/arkime_sessions3-*"
        params = session.get.call_args.kwargs.get("params") or {}
        assert params.get("format") == "json"
        assert result[0]["index"] == "arkime_sessions3-241124"

    def test_field_caps_calls_field_caps_endpoint(self):
        client, session = _client_with_mock_session()
        session.get.return_value.json.return_value = {
            "indices": ["arkime_sessions3-241124"],
            "fields": {
                "destination.ip": {"ip": {"type": "ip", "searchable": True, "aggregatable": True}},
                "@timestamp": {"date": {"type": "date", "searchable": True, "aggregatable": True}},
            },
        }
        result = client.field_caps("arkime_sessions3-*", ["destination.ip", "@timestamp"])
        url = session.get.call_args.args[0]
        assert url == "https://os.example.com:9200/arkime_sessions3-*/_field_caps"
        params = session.get.call_args.kwargs.get("params") or {}
        assert params.get("fields") == "destination.ip,@timestamp"
        assert "destination.ip" in result["fields"]

    def test_dataset_distribution_returns_event_dataset_buckets(self):
        client, session = _client_with_mock_session()
        session.post.return_value.json.return_value = {
            "hits": {"total": {"value": 1000}, "hits": []},
            "aggregations": {
                "datasets": {
                    "buckets": [
                        {"key": "conn", "doc_count": 800},
                        {"key": "dns", "doc_count": 150},
                        {"key": "modbus", "doc_count": 50},
                    ]
                }
            },
        }
        result = client.dataset_distribution("arkime_sessions3-*")
        body = session.post.call_args.kwargs["json"]
        assert body["size"] == 0
        assert body["aggs"]["datasets"]["terms"]["field"] == "event.dataset"
        assert result == {"conn": 800, "dns": 150, "modbus": 50}

    def test_dataset_distribution_with_time_filter(self):
        client, session = _client_with_mock_session()
        session.post.return_value.json.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"datasets": {"buckets": []}},
        }
        client.dataset_distribution("arkime_sessions3-*", since="now-7d")
        body = session.post.call_args.kwargs["json"]
        filters = body["query"]["bool"]["filter"]
        assert any("range" in f and f["range"]["@timestamp"]["gte"] == "now-7d" for f in filters)

    def test_dataset_distribution_no_filter_when_no_since(self):
        client, session = _client_with_mock_session()
        session.post.return_value.json.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"datasets": {"buckets": []}},
        }
        client.dataset_distribution("arkime_sessions3-*")
        body = session.post.call_args.kwargs["json"]
        # No range filter (or no bool filter at all)
        query = body.get("query", {})
        if "bool" in query:
            assert not any("range" in f for f in query["bool"].get("filter", []))
