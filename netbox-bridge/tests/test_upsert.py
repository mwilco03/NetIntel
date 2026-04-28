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
class _NamedTag:
    name: str


@dataclass
class _ServiceRow:
    port: int
    protocol: str


@dataclass
class _ExistingDevice:
    id: int
    tags: list[_NamedTag] = field(default_factory=list)
    custom_fields: dict = field(default_factory=dict)
    primary_ip4: Any | None = None
    primary_ip6: Any | None = None
    name: str = ""


@dataclass
class FakeClient:
    devices_created: list[dict] = field(default_factory=list)
    interfaces_created: list[dict] = field(default_factory=list)
    mac_addresses_created: list[dict] = field(default_factory=list)
    ips_created: list[dict] = field(default_factory=list)
    services_created: list[dict] = field(default_factory=list)
    devices_updated: list[tuple[int, dict]] = field(default_factory=list)
    interfaces_updated: list[tuple[int, dict]] = field(default_factory=list)
    existing_devices: dict[int, _ExistingDevice] = field(default_factory=dict)
    existing_services: dict[int, list[_ServiceRow]] = field(default_factory=dict)
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

    def get_device(self, device_id: int) -> Any | None:
        return self.existing_devices.get(device_id)

    def list_services_for_device(self, device_id: int) -> list[Any]:
        return list(self.existing_services.get(device_id, []))


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


# ---------------------------------------------------------------------------
# UPDATE path
# ---------------------------------------------------------------------------


def _existing_bridge_owned(
    *,
    device_id: int = 42,
    last_seen: str = "2026-04-20T10:00:00+00:00",
    first_seen: str = "2026-01-01T00:00:00+00:00",
    last_scan_id: str = "00000000-0000-0000-0000-old",
    sources: tuple[str, ...] = ("nmap",),
    extra_tags: tuple[str, ...] = (),
) -> _ExistingDevice:
    tags = [_NamedTag(SOURCE_TAG)] + [_NamedTag(f"source:{s}") for s in sources]
    tags += [_NamedTag(t) for t in extra_tags]
    return _ExistingDevice(
        id=device_id,
        tags=tags,
        custom_fields={
            "last_seen": last_seen,
            "first_seen": first_seen,
            "last_scan_id": last_scan_id,
            "source": ",".join(sources),
        },
    )


def _existing_human_owned(*, device_id: int = 42) -> _ExistingDevice:
    return _ExistingDevice(
        id=device_id,
        tags=[],  # no source:netintel-bridge tag
        custom_fields={},
    )


def _update(
    host: Host,
    existing: _ExistingDevice,
    *,
    match_kind: MatchKind = MatchKind.BY_MAC,
    dry_run: bool = False,
    strategy: Strategy = Strategy.MERGE,
    existing_services: list[_ServiceRow] | None = None,
) -> tuple[FakeClient, "UpsertResult"]:
    client = FakeClient()
    client.existing_devices[existing.id] = existing
    if existing_services is not None:
        client.existing_services[existing.id] = existing_services
    result = upsert_host(
        host,
        MatchResult(kind=match_kind, netbox_device_id=existing.id),
        client,
        scan_id=SCAN_ID,
        dry_run=dry_run,
        strategy=strategy,
        defaults=_defaults(),
    )
    return client, result


class TestUpdateBridgeOwned:
    """Device has source:netintel-bridge tag — bridge owns it."""

    def test_returns_update_when_last_seen_advances(self):
        existing = _existing_bridge_owned(last_seen="2026-04-20T10:00:00+00:00")
        host = _host(primary_ip="10.0.0.5")  # observed_at = 2026-04-28
        client, result = _update(host, existing)
        assert result.action == UpsertAction.UPDATE
        assert result.netbox_device_id == 42

    def test_diff_includes_last_seen_change(self):
        existing = _existing_bridge_owned(last_seen="2026-04-20T10:00:00+00:00")
        host = _host()
        _, result = _update(host, existing)
        diffs = {d.field: (d.before, d.after) for d in result.diffs}
        assert "last_seen" in diffs
        assert diffs["last_seen"][0] == "2026-04-20T10:00:00+00:00"
        assert "2026-04-28" in diffs["last_seen"][1]

    def test_update_payload_only_contains_changed_keys(self):
        existing = _existing_bridge_owned()
        host = _host()
        client, _ = _update(host, existing)
        # Only one update_device call, with only the keys that changed
        assert len(client.devices_updated) == 1
        device_id, patch = client.devices_updated[0]
        assert device_id == 42
        # last_seen, last_scan_id changed; first_seen and source did NOT
        assert "first_seen" not in patch
        assert "custom_fields" in patch
        assert "last_seen" in patch["custom_fields"]
        assert "last_scan_id" in patch["custom_fields"]
        assert "first_seen" not in patch["custom_fields"]

    def test_does_not_overwrite_first_seen_on_update(self):
        existing = _existing_bridge_owned(first_seen="2026-01-01T00:00:00+00:00")
        client, _ = _update(_host(), existing)
        _, patch = client.devices_updated[0]
        assert "first_seen" not in patch.get("custom_fields", {})

    def test_adds_per_source_tag_when_missing(self):
        existing = _existing_bridge_owned(sources=("nmap",))
        client, _ = _update(_host(source="malcolm"), existing)
        _, patch = client.devices_updated[0]
        assert "tags" in patch
        tag_names = set(patch["tags"])
        assert "source:malcolm" in tag_names
        # Existing tags preserved
        assert SOURCE_TAG in tag_names
        assert "source:nmap" in tag_names

    def test_does_not_change_tags_when_per_source_already_present(self):
        existing = _existing_bridge_owned(sources=("nmap",))
        client, _ = _update(_host(source="nmap"), existing)
        _, patch = client.devices_updated[0]
        assert "tags" not in patch

    def test_returns_noop_when_observation_is_older_than_last_seen(self):
        existing = _existing_bridge_owned(last_seen="2027-01-01T00:00:00+00:00")
        host = _host()  # observed 2026-04-28
        client, result = _update(host, existing)
        assert result.action == UpsertAction.NOOP
        assert client.devices_updated == []

    def test_returns_noop_when_nothing_changed(self):
        existing = _existing_bridge_owned(
            last_seen="2026-04-28T12:00:00+00:00",
            last_scan_id=SCAN_ID,
            sources=("nmap",),
        )
        host = _host(source="nmap")  # observed_at = 2026-04-28T12:00:00+00:00
        client, result = _update(host, existing)
        assert result.action == UpsertAction.NOOP
        assert client.devices_updated == []


class TestUpdateBridgeOwnedServices:
    def test_creates_new_service_for_new_port(self):
        existing = _existing_bridge_owned()
        existing_services = [_ServiceRow(port=22, protocol="tcp")]
        host = _host(
            services=(
                Service(port=22, protocol="tcp", name="ssh"),
                Service(port=443, protocol="tcp", name="ssl"),  # NEW
            )
        )
        client, _ = _update(host, existing, existing_services=existing_services)
        # Only one new service created
        assert len(client.services_created) == 1
        assert client.services_created[0]["ports"] == [443]

    def test_does_not_recreate_existing_service(self):
        existing = _existing_bridge_owned()
        existing_services = [
            _ServiceRow(port=22, protocol="tcp"),
            _ServiceRow(port=443, protocol="tcp"),
        ]
        host = _host(
            services=(
                Service(port=22, protocol="tcp", name="ssh"),
                Service(port=443, protocol="tcp", name="ssl"),
            )
        )
        client, _ = _update(host, existing, existing_services=existing_services)
        assert client.services_created == []

    def test_distinct_protocols_on_same_port_treated_as_distinct(self):
        # 53/tcp and 53/udp are different services
        existing = _existing_bridge_owned()
        existing_services = [_ServiceRow(port=53, protocol="tcp")]
        host = _host(services=(Service(port=53, protocol="udp", name="dns"),))
        client, _ = _update(host, existing, existing_services=existing_services)
        assert len(client.services_created) == 1
        assert client.services_created[0]["protocol"] == "udp"


class TestUpdateNotBridgeOwned:
    """Device exists but no source:netintel-bridge tag — human-managed."""

    def test_only_touches_bridge_custom_fields(self):
        existing = _existing_human_owned()
        client, result = _update(_host(), existing)
        assert client.devices_updated, "expected at least the last_seen update"
        device_id, patch = client.devices_updated[0]
        # No tag changes, only our custom field touch
        assert "tags" not in patch
        # Patch's only top-level key should be custom_fields with last_seen
        assert set(patch.keys()) == {"custom_fields"}
        assert "last_seen" in patch["custom_fields"]

    def test_does_not_create_services_on_human_owned_device(self):
        existing = _existing_human_owned()
        host = _host(services=(Service(port=22, protocol="tcp", name="ssh"),))
        client, _ = _update(host, existing)
        assert client.services_created == []

    def test_does_not_set_last_scan_id_on_human_owned_device(self):
        existing = _existing_human_owned()
        client, _ = _update(_host(), existing)
        _, patch = client.devices_updated[0]
        cfs = patch.get("custom_fields", {})
        assert "last_scan_id" not in cfs

    def test_overwrite_strategy_treats_human_owned_as_bridge_owned(self):
        existing = _existing_human_owned()
        host = _host(services=(Service(port=22, protocol="tcp", name="ssh"),))
        client, _ = _update(host, existing, strategy=Strategy.OVERWRITE)
        # With overwrite, services and tags ARE managed
        assert client.services_created
        _, patch = client.devices_updated[0]
        assert "tags" in patch


class TestUpdateDryRun:
    def test_no_writes_in_dry_run(self):
        existing = _existing_bridge_owned()
        host = _host(services=(Service(port=80, protocol="tcp", name="http"),))
        client, result = _update(host, existing, dry_run=True, existing_services=[])
        assert client.devices_updated == []
        assert client.services_created == []
        # Action and diffs still computed
        assert result.action == UpsertAction.UPDATE
        assert result.diffs


class TestUpdatePayloadContract:
    def test_update_patch_contains_only_allowed_device_fields(self):
        from tests.test_payload_contracts import (
            DEVICE_CREATE_FIELDS,
            assert_payload_in_schema,
        )

        existing = _existing_bridge_owned(sources=("nmap",))
        client, _ = _update(_host(source="malcolm"), existing)
        _, patch = client.devices_updated[0]
        assert_payload_in_schema(patch, DEVICE_CREATE_FIELDS, ctx="update_device patch")
