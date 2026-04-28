"""Tests for the host-to-device matcher.

Order: MAC -> IP -> FQDN. CONFLICT when two keys point to different devices.

The matcher takes a duck-typed client; we hand-roll a fake to drive it through every case
without touching pynetbox.
"""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

import pytest

from netbox_bridge.matcher import MatchKind, match_host
from netbox_bridge.model import Host, Interface, Service


@dataclass
class _Device:
    id: int
    name: str = ""


class FakeClient:
    def __init__(
        self,
        *,
        mac_to_device: dict[str, _Device] | None = None,
        ip_to_device: dict[str, _Device] | None = None,
        name_to_device: dict[str, _Device] | None = None,
    ) -> None:
        self.mac_to_device = mac_to_device or {}
        self.ip_to_device = ip_to_device or {}
        self.name_to_device = name_to_device or {}
        self.calls: list[tuple[str, str]] = []

    def find_device_by_mac(self, mac: str) -> Any | None:
        self.calls.append(("mac", mac))
        return self.mac_to_device.get(mac.lower())

    def find_device_by_primary_ip(self, ip: str) -> Any | None:
        self.calls.append(("ip", ip))
        return self.ip_to_device.get(ip)

    def find_device_by_name(self, name: str) -> Any | None:
        self.calls.append(("name", name))
        return self.name_to_device.get(name)


def _host(
    *,
    primary_ip: str = "10.0.0.5",
    macs: tuple[str, ...] = (),
    fqdn: str | None = None,
) -> Host:
    return Host(
        primary_ip=primary_ip,
        fqdn=fqdn,
        interfaces=[Interface(mac=m) for m in macs],
        services=[],
        source="nmap",
        observed_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
    )


class TestMatchHostNew:
    def test_no_matches_anywhere_returns_new(self):
        result = match_host(_host(macs=("aa:bb",), fqdn="srv.corp"), FakeClient())
        assert result.kind == MatchKind.NEW
        assert result.netbox_device_id is None

    def test_host_with_no_mac_no_fqdn_no_matching_ip_returns_new(self):
        result = match_host(_host(), FakeClient())
        assert result.kind == MatchKind.NEW


class TestMatchHostByMac:
    def test_mac_match_wins_over_nothing(self):
        client = FakeClient(mac_to_device={"aa:bb:cc:dd:ee:ff": _Device(1)})
        result = match_host(_host(macs=("aa:bb:cc:dd:ee:ff",)), client)
        assert result.kind == MatchKind.BY_MAC
        assert result.netbox_device_id == 1

    def test_mac_match_case_insensitive(self):
        client = FakeClient(mac_to_device={"aa:bb:cc:dd:ee:ff": _Device(2)})
        result = match_host(_host(macs=("AA:BB:CC:DD:EE:FF",)), client)
        assert result.kind == MatchKind.BY_MAC
        assert result.netbox_device_id == 2

    def test_first_matching_mac_wins(self):
        client = FakeClient(
            mac_to_device={
                "aa:bb:cc:dd:ee:01": _Device(10),
                "aa:bb:cc:dd:ee:02": _Device(20),
            }
        )
        result = match_host(_host(macs=("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")), client)
        assert result.kind == MatchKind.BY_MAC
        assert result.netbox_device_id == 10

    def test_skips_macs_until_one_matches(self):
        client = FakeClient(mac_to_device={"aa:bb:cc:dd:ee:02": _Device(20)})
        result = match_host(_host(macs=("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")), client)
        assert result.kind == MatchKind.BY_MAC
        assert result.netbox_device_id == 20


class TestMatchHostByIp:
    def test_falls_back_to_ip_when_no_macs(self):
        client = FakeClient(ip_to_device={"10.0.0.5": _Device(7)})
        result = match_host(_host(primary_ip="10.0.0.5"), client)
        assert result.kind == MatchKind.BY_IP
        assert result.netbox_device_id == 7

    def test_falls_back_to_ip_when_macs_dont_match(self):
        client = FakeClient(ip_to_device={"10.0.0.5": _Device(7)})
        result = match_host(_host(primary_ip="10.0.0.5", macs=("00:00:00:00:00:00",)), client)
        assert result.kind == MatchKind.BY_IP


class TestMatchHostByFqdn:
    def test_falls_back_to_fqdn_when_mac_and_ip_dont_match(self):
        client = FakeClient(name_to_device={"web01.corp": _Device(99)})
        result = match_host(
            _host(primary_ip="10.99.99.99", fqdn="web01.corp"),
            client,
        )
        assert result.kind == MatchKind.BY_FQDN
        assert result.netbox_device_id == 99


class TestMatchHostConflict:
    def test_mac_and_ip_pointing_to_different_devices_is_conflict(self):
        client = FakeClient(
            mac_to_device={"aa:bb:cc:dd:ee:ff": _Device(1)},
            ip_to_device={"10.0.0.5": _Device(2)},
        )
        result = match_host(
            _host(primary_ip="10.0.0.5", macs=("aa:bb:cc:dd:ee:ff",)), client
        )
        assert result.kind == MatchKind.CONFLICT
        assert result.reason
        assert "mac" in result.reason.lower() and "ip" in result.reason.lower()

    def test_mac_and_fqdn_pointing_to_different_devices_is_conflict(self):
        client = FakeClient(
            mac_to_device={"aa:bb:cc:dd:ee:ff": _Device(1)},
            name_to_device={"srv.corp": _Device(2)},
        )
        result = match_host(
            _host(macs=("aa:bb:cc:dd:ee:ff",), fqdn="srv.corp"), client
        )
        assert result.kind == MatchKind.CONFLICT

    def test_ip_and_fqdn_pointing_to_different_devices_is_conflict(self):
        client = FakeClient(
            ip_to_device={"10.0.0.5": _Device(1)},
            name_to_device={"srv.corp": _Device(2)},
        )
        result = match_host(
            _host(primary_ip="10.0.0.5", fqdn="srv.corp"), client
        )
        assert result.kind == MatchKind.CONFLICT

    def test_no_conflict_when_all_keys_point_to_same_device(self):
        same = _Device(42)
        client = FakeClient(
            mac_to_device={"aa:bb:cc:dd:ee:ff": same},
            ip_to_device={"10.0.0.5": same},
            name_to_device={"srv.corp": same},
        )
        result = match_host(
            _host(primary_ip="10.0.0.5", macs=("aa:bb:cc:dd:ee:ff",), fqdn="srv.corp"),
            client,
        )
        assert result.kind == MatchKind.BY_MAC  # priority: MAC wins
        assert result.netbox_device_id == 42


class TestMatchHostQueryBehavior:
    def test_skips_ip_lookup_when_ip_is_empty(self):
        client = FakeClient()
        match_host(_host(primary_ip=""), client)
        assert not any(c[0] == "ip" for c in client.calls)

    def test_skips_fqdn_lookup_when_fqdn_is_none(self):
        client = FakeClient()
        match_host(_host(fqdn=None), client)
        assert not any(c[0] == "name" for c in client.calls)

    def test_skips_mac_lookup_when_mac_is_none(self):
        client = FakeClient()
        match_host(_host(macs=()), client)
        assert not any(c[0] == "mac" for c in client.calls)

    def test_queries_all_three_keys_to_detect_conflicts(self):
        client = FakeClient()
        match_host(
            _host(primary_ip="10.0.0.5", macs=("aa:bb:cc:dd:ee:ff",), fqdn="srv.corp"),
            client,
        )
        kinds = {c[0] for c in client.calls}
        assert kinds == {"mac", "ip", "name"}
