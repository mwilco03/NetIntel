"""Tests for upsert_host (CREATE path).

Scope: NEW match → create Device + Interface + (MACAddress + PATCH) + IPAddress + PATCH primary_ip
+ one Service per host.services entry. UPDATE/MERGE path lands in the next slice.

Each test that emits a payload also asserts the payload's keys are within the upstream-allowed
set from test_payload_contracts (the NetBox serializer's accepted field names). That catches
"silently passing wrong field name" failures before they hit a real backend.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from netbox_bridge.matcher import MatchKind, MatchResult
from netbox_bridge.model import Host, Interface, Service
from netbox_bridge.upsert import (
    SOURCE_TAG,
    Strategy,
    UpsertAction,
    UpsertDefaults,
    upsert_host,
)
from tests.test_payload_contracts import (
    DEVICE_CREATE_FIELDS,
    INTERFACE_CREATE_FIELDS,
    IP_ADDRESS_CREATE_FIELDS,
    MAC_ADDRESS_CREATE_FIELDS,
    SERVICE_CREATE_FIELDS,
    assert_payload_in_schema,
)


@dataclass
class _Stub:
    id: int


@dataclass
class FakeClient:
    devices_created: list[dict] = field(default_factory=list)
    interfaces_created: list[dict] = field(default_factory=list)
    mac_addresses_created: list[dict] = field(default_factory=list)
    ips_created: list[dict] = field(default_factory=list)
    services_created: list[dict] = field(default_factory=list)
    devices_updated: list[tuple[int, dict]] = field(default_factory=list)
    interfaces_updated: list[tuple[int, dict]] = field(default_factory=list)
    next_device_id: int = 100
    next_interface_id: int = 200
    next_mac_id: int = 250
    next_ip_id: int = 300
    next_service_id: int = 400

    def create_device(self, spec: dict) -> Any:
        self.devices_created.append(spec)
        out = _Stub(self.next_device_id)
        self.next_device_id += 1
        return out

    def create_interface(self, spec: dict) -> Any:
        self.interfaces_created.append(spec)
        out = _Stub(self.next_interface_id)
        self.next_interface_id += 1
        return out

    def create_mac_address(self, spec: dict) -> Any:
        self.mac_addresses_created.append(spec)
        out = _Stub(self.next_mac_id)
        self.next_mac_id += 1
        return out

    def create_ip_address(self, spec: dict) -> Any:
        self.ips_created.append(spec)
        out = _Stub(self.next_ip_id)
        self.next_ip_id += 1
        return out

    def create_service(self, spec: dict) -> Any:
        self.services_created.append(spec)
        out = _Stub(self.next_service_id)
        self.next_service_id += 1
        return out

    def update_device(self, device_id: int, fields: dict) -> Any:
        self.devices_updated.append((device_id, fields))
        return _Stub(device_id)

    def update_interface(self, interface_id: int, fields: dict) -> Any:
        self.interfaces_updated.append((interface_id, fields))
        return _Stub(interface_id)


def _defaults(site_id: int = 1, role_id: int = 2, device_type_id: int = 3) -> UpsertDefaults:
    return UpsertDefaults(site_id=site_id, role_id=role_id, device_type_id=device_type_id)


def _host(
    *,
    primary_ip: str = "10.0.0.5",
    fqdn: str | None = None,
    macs: tuple[str, ...] = (),
    services: tuple[Service, ...] = (),
    source: str = "nmap",
) -> Host:
    return Host(
        primary_ip=primary_ip,
        fqdn=fqdn,
        interfaces=[Interface(mac=m) for m in macs],
        services=list(services),
        source=source,  # type: ignore[arg-type]
        observed_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
    )


SCAN_ID = "00000000-0000-0000-0000-000000000001"


def _create(host: Host, *, dry_run: bool = False, strategy: Strategy = Strategy.MERGE) -> FakeClient:
    client = FakeClient()
    upsert_host(
        host,
        MatchResult(kind=MatchKind.NEW),
        client,
        scan_id=SCAN_ID,
        dry_run=dry_run,
        strategy=strategy,
        defaults=_defaults(site_id=1, role_id=2, device_type_id=3),
    )
    return client


class TestActionDispatch:
    def test_returns_create_when_match_is_new(self):
        result = upsert_host(
            _host(),
            MatchResult(kind=MatchKind.NEW),
            FakeClient(),
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
        )
        assert result.action == UpsertAction.CREATE

    def test_returns_conflict_when_match_is_conflict(self):
        client = FakeClient()
        result = upsert_host(
            _host(),
            MatchResult(kind=MatchKind.CONFLICT, reason="mac=#1, ip=#2"),
            client,
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
        )
        assert result.action == UpsertAction.CONFLICT
        assert client.devices_created == []

    def test_skip_strategy_skips_existing_match(self):
        client = FakeClient()
        result = upsert_host(
            _host(),
            MatchResult(kind=MatchKind.BY_IP, netbox_device_id=42),
            client,
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.SKIP,
            defaults=_defaults(),
        )
        assert result.action == UpsertAction.NOOP
        assert client.devices_created == []


class TestDeviceCreatePayload:
    def test_payload_contract_valid(self):
        spec = _create(_host()).devices_created[0]
        assert_payload_in_schema(spec, DEVICE_CREATE_FIELDS, ctx="create_device")

    def test_required_fields_present(self):
        spec = _create(_host()).devices_created[0]
        for required in ("name", "device_type", "role", "site"):
            assert required in spec, f"missing {required}"

    def test_uses_default_ids(self):
        spec = _create(_host()).devices_created[0]
        assert spec["site"] == 1
        assert spec["role"] == 2
        assert spec["device_type"] == 3

    def test_carries_source_netintel_bridge_tag(self):
        spec = _create(_host()).devices_created[0]
        assert SOURCE_TAG in spec["tags"]

    def test_carries_per_source_tag(self):
        for src, tag in [
            ("nmap", "source:nmap"),
            ("nessus", "source:nessus"),
            ("malcolm", "source:malcolm"),
            ("security_onion", "source:security_onion"),
        ]:
            spec = _create(_host(source=src)).devices_created[0]
            assert tag in spec["tags"], f"missing {tag} for source={src}"

    def test_custom_fields_populated(self):
        spec = _create(_host()).devices_created[0]
        cfs = spec["custom_fields"]
        assert "last_seen" in cfs
        assert "first_seen" in cfs
        assert cfs["last_scan_id"] == SCAN_ID
        assert cfs["source"] == "nmap"

    def test_first_seen_equals_last_seen_on_create(self):
        cfs = _create(_host()).devices_created[0]["custom_fields"]
        assert cfs["first_seen"] == cfs["last_seen"]

    def test_name_uses_fqdn_when_present(self):
        spec = _create(_host(fqdn="srv.corp")).devices_created[0]
        assert spec["name"] == "srv.corp"

    def test_name_falls_back_to_primary_ip_when_no_fqdn(self):
        spec = _create(_host(fqdn=None, primary_ip="10.0.0.5")).devices_created[0]
        assert spec["name"] == "10.0.0.5"


class TestInterfaceCreatePayload:
    def test_payload_contract_valid(self):
        spec = _create(_host()).interfaces_created[0]
        assert_payload_in_schema(spec, INTERFACE_CREATE_FIELDS, ctx="create_interface")

    def test_does_not_set_mac_address_directly(self):
        # NetBox 4.2+ made Interface.mac_address read-only — must not appear in payload.
        spec = _create(_host(macs=("aa:bb:cc:dd:ee:ff",))).interfaces_created[0]
        assert "mac_address" not in spec

    def test_attaches_to_created_device(self):
        spec = _create(_host()).interfaces_created[0]
        assert spec["device"] == 100

    def test_one_interface_created(self):
        client = _create(_host())
        assert len(client.interfaces_created) == 1


class TestMacAddressCreatePayload:
    def test_no_mac_payload_when_host_has_no_mac(self):
        client = _create(_host(macs=()))
        assert client.mac_addresses_created == []
        assert client.interfaces_updated == []

    def test_mac_payload_contract_valid(self):
        spec = _create(_host(macs=("aa:bb:cc:dd:ee:ff",))).mac_addresses_created[0]
        assert_payload_in_schema(spec, MAC_ADDRESS_CREATE_FIELDS, ctx="create_mac_address")

    def test_mac_assigned_to_interface(self):
        spec = _create(_host(macs=("aa:bb:cc:dd:ee:ff",))).mac_addresses_created[0]
        assert spec["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert spec["assigned_object_type"] == "dcim.interface"
        assert spec["assigned_object_id"] == 200  # FakeClient first interface id

    def test_interface_primary_mac_patched_after_mac_create(self):
        client = _create(_host(macs=("aa:bb:cc:dd:ee:ff",)))
        # update_interface(iface_id=200, {"primary_mac_address": 250})
        assert client.interfaces_updated
        iface_id, patch = client.interfaces_updated[0]
        assert iface_id == 200
        assert patch == {"primary_mac_address": 250}

    def test_uses_first_mac_when_multiple_observed(self):
        client = _create(_host(macs=("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")))
        # v1: emit one MACAddress, the first one. (Multi-MAC support is later.)
        assert len(client.mac_addresses_created) == 1
        assert client.mac_addresses_created[0]["mac_address"] == "aa:bb:cc:dd:ee:01"


class TestIpAddressCreatePayload:
    def test_payload_contract_valid(self):
        spec = _create(_host()).ips_created[0]
        assert_payload_in_schema(spec, IP_ADDRESS_CREATE_FIELDS, ctx="create_ip_address")

    def test_appends_slash_32_for_bare_ipv4(self):
        spec = _create(_host(primary_ip="10.0.0.5")).ips_created[0]
        assert spec["address"] == "10.0.0.5/32"

    def test_keeps_cidr_when_already_present(self):
        spec = _create(_host(primary_ip="10.0.0.5/24")).ips_created[0]
        assert spec["address"] == "10.0.0.5/24"

    def test_appends_slash_128_for_ipv6(self):
        spec = _create(_host(primary_ip="2001:db8::1")).ips_created[0]
        assert spec["address"] == "2001:db8::1/128"

    def test_assigned_to_interface(self):
        spec = _create(_host()).ips_created[0]
        assert spec["assigned_object_type"] == "dcim.interface"
        assert spec["assigned_object_id"] == 200

    def test_device_primary_ip4_patched_for_ipv4(self):
        client = _create(_host(primary_ip="10.0.0.5"))
        assert client.devices_updated
        device_id, patch = client.devices_updated[-1]
        assert device_id == 100
        assert patch == {"primary_ip4": 300}

    def test_device_primary_ip6_patched_for_ipv6(self):
        client = _create(_host(primary_ip="2001:db8::1"))
        device_id, patch = client.devices_updated[-1]
        assert patch == {"primary_ip6": 300}


class TestServiceCreatePayload:
    def test_payload_contract_valid(self):
        client = _create(_host(services=(Service(port=22, protocol="tcp", name="ssh"),)))
        spec = client.services_created[0]
        assert_payload_in_schema(spec, SERVICE_CREATE_FIELDS, ctx="create_service")

    def test_no_device_field_uses_parent_object(self):
        # Service.device was removed in favor of parent_object_type/_id.
        client = _create(_host(services=(Service(port=22, protocol="tcp", name="ssh"),)))
        spec = client.services_created[0]
        assert "device" not in spec
        assert spec["parent_object_type"] == "dcim.device"
        assert spec["parent_object_id"] == 100

    def test_one_service_per_host_service(self):
        client = _create(
            _host(
                services=(
                    Service(port=22, protocol="tcp", name="ssh"),
                    Service(port=443, protocol="tcp", name="ssl"),
                    Service(port=53, protocol="udp", name="dns"),
                )
            )
        )
        assert len(client.services_created) == 3

    def test_ports_is_list_of_int(self):
        client = _create(_host(services=(Service(port=22, protocol="tcp", name="ssh"),)))
        assert client.services_created[0]["ports"] == [22]

    def test_protocol_propagates(self):
        client = _create(
            _host(
                services=(
                    Service(port=22, protocol="tcp", name="ssh"),
                    Service(port=53, protocol="udp", name="dns"),
                )
            )
        )
        protocols = {s["protocol"] for s in client.services_created}
        assert protocols == {"tcp", "udp"}

    def test_service_name_falls_back_when_unnamed(self):
        client = _create(_host(services=(Service(port=9999, protocol="tcp", name=None),)))
        spec = client.services_created[0]
        assert spec["name"]  # non-empty fallback
        assert "9999" in spec["name"]

    def test_no_services_when_host_has_none(self):
        client = _create(_host(services=()))
        assert client.services_created == []


class TestDryRun:
    def test_dry_run_makes_no_writes(self):
        client = _create(
            _host(
                macs=("aa:bb:cc:dd:ee:ff",),
                services=(Service(port=22, protocol="tcp", name="ssh"),),
            ),
            dry_run=True,
        )
        assert client.devices_created == []
        assert client.interfaces_created == []
        assert client.mac_addresses_created == []
        assert client.ips_created == []
        assert client.services_created == []
        assert client.devices_updated == []
        assert client.interfaces_updated == []

    def test_dry_run_still_returns_create_action(self):
        result = upsert_host(
            _host(),
            MatchResult(kind=MatchKind.NEW),
            FakeClient(),
            scan_id=SCAN_ID,
            dry_run=True,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
        )
        assert result.action == UpsertAction.CREATE
        assert result.netbox_device_id is None
