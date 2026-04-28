"""Unit tests for NetBoxClient.

Pynetbox is mocked out at the api object so we verify our wrapper calls the right endpoints
without needing a live NetBox. End-to-end against a real NetBox is covered by integration tests
(see tests/integration/ — run separately).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from netbox_bridge.client import NetBoxClient, TokenAdapter


def _client_with_mock_api() -> tuple[NetBoxClient, MagicMock]:
    with patch("netbox_bridge.client.pynetbox.api") as mock_api_factory:
        mock_api = MagicMock()
        mock_api_factory.return_value = mock_api
        client = NetBoxClient("http://x", TokenAdapter("t"))
    return client, mock_api


class TestNetBoxClient:
    def test_token_adapter_applies_token_to_api(self):
        client, api = _client_with_mock_api()
        assert api.token == "t"

    def test_verify_tls_false_disables_verification(self):
        with patch("netbox_bridge.client.pynetbox.api") as mock_api_factory:
            mock_api = MagicMock()
            mock_api_factory.return_value = mock_api
            NetBoxClient("http://x", TokenAdapter("t"), verify_tls=False)
        assert mock_api.http_session.verify is False

    def test_version_returns_string(self):
        client, api = _client_with_mock_api()
        api.version = "4.1.5"
        assert client.version() == "4.1.5"

    def test_list_sites_calls_dcim_sites_all(self):
        client, api = _client_with_mock_api()
        api.dcim.sites.all.return_value = iter(["a", "b"])
        assert client.list_sites() == ["a", "b"]
        api.dcim.sites.all.assert_called_once()

    def test_list_tenants_calls_tenancy_tenants_all(self):
        client, api = _client_with_mock_api()
        api.tenancy.tenants.all.return_value = iter(["acme"])
        assert client.list_tenants() == ["acme"]

    def test_list_device_roles_calls_dcim_device_roles_all(self):
        client, api = _client_with_mock_api()
        api.dcim.device_roles.all.return_value = iter(["server"])
        assert client.list_device_roles() == ["server"]

    def test_list_platforms_calls_dcim_platforms_all(self):
        client, api = _client_with_mock_api()
        api.dcim.platforms.all.return_value = iter(["linux"])
        assert client.list_platforms() == ["linux"]

    def test_list_custom_fields_filters_by_content_type(self):
        client, api = _client_with_mock_api()
        api.extras.custom_fields.filter.return_value = iter(["cf1"])
        assert client.list_custom_fields("dcim.device") == ["cf1"]
        api.extras.custom_fields.filter.assert_called_once_with(content_types="dcim.device")

    def test_list_tags_calls_extras_tags_all(self):
        client, api = _client_with_mock_api()
        api.extras.tags.all.return_value = iter(["t1"])
        assert client.list_tags() == ["t1"]
