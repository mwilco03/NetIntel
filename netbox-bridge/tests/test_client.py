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
    """NetBox 4.2+ moved MAC to a dedicated MACAddress model. Look it up via dcim.mac_addresses,
    not via Interface.mac_address (which is now read-only).
    """

    def test_returns_none_when_no_mac_record_matches(self):
        client, api = _client_with_mock_api()
        api.dcim.mac_addresses.filter.return_value = iter([])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is None
        api.dcim.mac_addresses.filter.assert_called_once_with(mac_address="aa:bb:cc:dd:ee:ff")

    def test_returns_device_via_assigned_interface(self):
        client, api = _client_with_mock_api()
        device = MagicMock()
        device.id = 42
        iface = MagicMock()
        iface.device = device
        mac = MagicMock()
        mac.assigned_object_type = "dcim.interface"
        mac.assigned_object = iface
        api.dcim.mac_addresses.filter.return_value = iter([mac])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is device

    def test_skips_macs_assigned_to_vm_interfaces(self):
        # We only handle Device-bound MACs in v1; VM interfaces are out of scope.
        client, api = _client_with_mock_api()
        mac = MagicMock()
        mac.assigned_object_type = "virtualization.vminterface"
        mac.assigned_object = MagicMock()
        api.dcim.mac_addresses.filter.return_value = iter([mac])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is None

    def test_skips_unassigned_macs(self):
        client, api = _client_with_mock_api()
        mac = MagicMock()
        mac.assigned_object_type = None
        mac.assigned_object = None
        api.dcim.mac_addresses.filter.return_value = iter([mac])
        assert client.find_device_by_mac("aa:bb:cc:dd:ee:ff") is None


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


class TestCreatePassthroughs:
    """Each create_* method posts to the right pynetbox endpoint with the spec verbatim."""

    def test_create_device_posts_to_dcim_devices(self):
        client, api = _client_with_mock_api()
        spec = {"name": "x", "device_type": 1, "role": 2, "site": 3}
        client.create_device(spec)
        api.dcim.devices.create.assert_called_once_with(spec)

    def test_create_interface_posts_to_dcim_interfaces(self):
        client, api = _client_with_mock_api()
        spec = {"device": 1, "name": "eth0", "type": "other"}
        client.create_interface(spec)
        api.dcim.interfaces.create.assert_called_once_with(spec)

    def test_create_mac_address_posts_to_dcim_mac_addresses(self):
        # NetBox 4.2+ MAC handling — the dedicated MACAddress endpoint.
        client, api = _client_with_mock_api()
        spec = {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": 100,
        }
        client.create_mac_address(spec)
        api.dcim.mac_addresses.create.assert_called_once_with(spec)

    def test_create_ip_address_posts_to_ipam_ip_addresses(self):
        client, api = _client_with_mock_api()
        spec = {
            "address": "10.0.0.5/32",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": 100,
        }
        client.create_ip_address(spec)
        api.ipam.ip_addresses.create.assert_called_once_with(spec)

    def test_create_service_posts_to_ipam_services(self):
        client, api = _client_with_mock_api()
        spec = {
            "parent_object_type": "dcim.device",
            "parent_object_id": 1,
            "name": "ssh",
            "ports": [22],
            "protocol": "tcp",
        }
        client.create_service(spec)
        api.ipam.services.create.assert_called_once_with(spec)


class TestUpdatePassthroughs:
    def test_update_device_calls_get_then_save(self):
        client, api = _client_with_mock_api()
        device = MagicMock()
        api.dcim.devices.get.return_value = device
        client.update_device(42, {"primary_ip4": 300})
        api.dcim.devices.get.assert_called_once_with(42)
        # pynetbox pattern: mutate attributes then call .save()
        assert device.primary_ip4 == 300
        device.save.assert_called_once()

    def test_update_interface_calls_get_then_save(self):
        client, api = _client_with_mock_api()
        iface = MagicMock()
        api.dcim.interfaces.get.return_value = iface
        client.update_interface(7, {"primary_mac_address": 500})
        api.dcim.interfaces.get.assert_called_once_with(7)
        assert iface.primary_mac_address == 500
        iface.save.assert_called_once()

    def test_update_device_returns_none_when_device_not_found(self):
        client, api = _client_with_mock_api()
        api.dcim.devices.get.return_value = None
        result = client.update_device(99, {"primary_ip4": 1})
        assert result is None
