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

    def test_create_custom_field_posts_to_extras_custom_fields(self):
        client, api = _client_with_mock_api()
        spec = {"name": "last_seen", "type": "datetime", "object_types": ["dcim.device"]}
        client.create_custom_field(spec)
        api.extras.custom_fields.create.assert_called_once_with(spec)

    def test_create_tag_posts_to_extras_tags(self):
        client, api = _client_with_mock_api()
        spec = {"name": "source:nmap", "slug": "source-nmap", "color": "43a047"}
        client.create_tag(spec)
        api.extras.tags.create.assert_called_once_with(spec)


class TestFindDeviceByMac:
    def test_returns_none_when_no_interface_matches(self):
        client, api = _client_with_mock_api()
        api.dcim.interfaces.filter.return_value = iter([])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is None
        api.dcim.interfaces.filter.assert_called_once_with(mac_address="aa:bb:cc:dd:ee:ff")

    def test_returns_device_attached_to_matching_interface(self):
        client, api = _client_with_mock_api()
        device = MagicMock()
        device.id = 42
        iface = MagicMock()
        iface.device = device
        api.dcim.interfaces.filter.return_value = iter([iface])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is device

    def test_returns_first_when_multiple_interfaces_match(self):
        client, api = _client_with_mock_api()
        d1, d2 = MagicMock(), MagicMock()
        d1.id, d2.id = 1, 2
        i1, i2 = MagicMock(device=d1), MagicMock(device=d2)
        api.dcim.interfaces.filter.return_value = iter([i1, i2])
        assert client.find_device_by_mac("aa:bb").id == 1


class TestFindDeviceByPrimaryIp:
    def test_returns_none_when_no_ip_matches(self):
        client, api = _client_with_mock_api()
        api.ipam.ip_addresses.filter.return_value = iter([])
        assert client.find_device_by_primary_ip("10.0.0.5") is None
        api.ipam.ip_addresses.filter.assert_called_once_with(address="10.0.0.5")

    def test_returns_device_via_assigned_interface(self):
        client, api = _client_with_mock_api()
        device = MagicMock()
        device.id = 7
        iface = MagicMock()
        iface.device = device
        ip = MagicMock()
        ip.assigned_object_type = "dcim.interface"
        ip.assigned_object = iface
        api.ipam.ip_addresses.filter.return_value = iter([ip])
        assert client.find_device_by_primary_ip("10.0.0.5") is device

    def test_skips_ips_not_assigned_to_device_interface(self):
        client, api = _client_with_mock_api()
        ip = MagicMock()
        ip.assigned_object_type = "virtualization.vminterface"
        ip.assigned_object = MagicMock()
        api.ipam.ip_addresses.filter.return_value = iter([ip])
        assert client.find_device_by_primary_ip("10.0.0.5") is None

    def test_skips_unassigned_ips(self):
        client, api = _client_with_mock_api()
        ip = MagicMock()
        ip.assigned_object_type = None
        ip.assigned_object = None
        api.ipam.ip_addresses.filter.return_value = iter([ip])
        assert client.find_device_by_primary_ip("10.0.0.5") is None


class TestFindDeviceByName:
    def test_returns_none_when_no_device_matches(self):
        client, api = _client_with_mock_api()
        api.dcim.devices.filter.return_value = iter([])
        assert client.find_device_by_name("srv.corp") is None
        api.dcim.devices.filter.assert_called_once_with(name="srv.corp")

    def test_returns_first_matching_device(self):
        client, api = _client_with_mock_api()
        d1, d2 = MagicMock(), MagicMock()
        api.dcim.devices.filter.return_value = iter([d1, d2])
        assert client.find_device_by_name("srv.corp") is d1
