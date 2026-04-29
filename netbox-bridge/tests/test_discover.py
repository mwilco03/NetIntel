"""Tests for the `discover` orchestration.

Uses a hand-rolled fake client (duck-typed against NetBoxClient) so we test the orchestration
logic without needing a live NetBox or pynetbox mock plumbing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from netbox_bridge.discover import (
    REQUIRED_DEVICE_CFS,
    REQUIRED_TAGS,
    DiscoverReport,
    discover,
    render_human,
    render_json,
)


@dataclass
class _Named:
    name: str


class FakeClient:
    def __init__(
        self,
        *,
        version: str = "4.0.0",
        sites: tuple[str, ...] = (),
        tenants: tuple[str, ...] = (),
        device_roles: tuple[str, ...] = (),
        platforms: tuple[str, ...] = (),
        device_cfs: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
    ) -> None:
        self._version = version
        self._sites = sites
        self._tenants = tenants
        self._device_roles = device_roles
        self._platforms = platforms
        self._device_cfs = device_cfs
        self._tags = tags
        self.custom_field_calls: list[str] = []

    def version(self) -> str:
        return self._version

    def list_sites(self):
        return [_Named(n) for n in self._sites]

    def list_tenants(self):
        return [_Named(n) for n in self._tenants]

    def list_device_roles(self):
        return [_Named(n) for n in self._device_roles]

    def list_platforms(self):
        return [_Named(n) for n in self._platforms]

    def list_custom_fields(self, content_type: str):
        self.custom_field_calls.append(content_type)
        return [_Named(n) for n in self._device_cfs]

    def list_tags(self):
        return [_Named(n) for n in self._tags]


class TestDiscover:
    def test_returns_netbox_version(self):
        report = discover(FakeClient(version="4.1.5"))
        assert report.netbox_version == "4.1.5"

    def test_enumerates_sites_tenants_roles_platforms(self):
        report = discover(
            FakeClient(
                sites=("hq", "dr"),
                tenants=("acme",),
                device_roles=("server", "switch"),
                platforms=("ubuntu", "windows"),
            )
        )
        assert report.sites == ["hq", "dr"]
        assert report.tenants == ["acme"]
        assert report.device_roles == ["server", "switch"]
        assert report.platforms == ["ubuntu", "windows"]

    def test_flags_all_custom_fields_missing_when_none_exist(self):
        report = discover(FakeClient())
        assert sorted(report.missing_device_cfs) == sorted(REQUIRED_DEVICE_CFS)
        assert report.existing_device_cfs == []
        assert not report.ready

    def test_flags_partial_custom_field_presence(self):
        report = discover(FakeClient(device_cfs=("last_seen", "source")))
        assert sorted(report.existing_device_cfs) == ["last_seen", "source"]
        assert sorted(report.missing_device_cfs) == [
            "first_seen",
            "last_scan_id",
            "oui_vendor",
            "related_macs",
        ]
        assert not report.ready

    def test_ignores_unrelated_custom_fields(self):
        report = discover(FakeClient(device_cfs=("some_other_org_field",)))
        assert "some_other_org_field" not in report.existing_device_cfs
        assert "some_other_org_field" not in report.missing_device_cfs

    def test_flags_all_tags_missing_when_none_exist(self):
        report = discover(FakeClient())
        assert sorted(report.missing_tags) == sorted(REQUIRED_TAGS)
        assert report.existing_tags == []

    def test_ready_when_all_required_cfs_and_tags_present(self):
        report = discover(
            FakeClient(
                device_cfs=tuple(REQUIRED_DEVICE_CFS),
                tags=tuple(REQUIRED_TAGS),
            )
        )
        assert report.missing_device_cfs == []
        assert report.missing_tags == []
        assert report.ready

    def test_queries_custom_fields_for_dcim_device_content_type(self):
        client = FakeClient()
        discover(client)
        assert "dcim.device" in client.custom_field_calls


class TestRenderHuman:
    def test_includes_netbox_version(self):
        out = render_human(DiscoverReport(netbox_version="4.2.1"))
        assert "4.2.1" in out

    def test_lists_sites_count_and_names(self):
        out = render_human(DiscoverReport(netbox_version="4.0.0", sites=["hq", "dr"]))
        assert "2" in out
        assert "hq" in out
        assert "dr" in out

    def test_says_ready_when_no_missing(self):
        report = DiscoverReport(netbox_version="4.0.0")
        out = render_human(report)
        assert "Ready" in out or "ready" in out
        assert "NOT ready" not in out

    def test_says_not_ready_and_names_missing_pieces(self):
        report = DiscoverReport(
            netbox_version="4.0.0",
            missing_device_cfs=["last_seen"],
            missing_tags=["source:nmap"],
        )
        out = render_human(report)
        assert "NOT ready" in out
        assert "last_seen" in out
        assert "source:nmap" in out

    def test_suggests_init_apply_when_not_ready(self):
        report = DiscoverReport(netbox_version="4.0.0", missing_device_cfs=["last_seen"])
        out = render_human(report)
        assert "init" in out and "--apply" in out


class TestRenderJson:
    def test_emits_valid_json(self):
        out = render_json(DiscoverReport(netbox_version="4.0.0"))
        json.loads(out)

    def test_includes_ready_field(self):
        parsed = json.loads(render_json(DiscoverReport(netbox_version="4.0.0")))
        assert parsed["ready"] is True

    def test_ready_false_when_missing(self):
        report = DiscoverReport(netbox_version="4.0.0", missing_device_cfs=["last_seen"])
        parsed = json.loads(render_json(report))
        assert parsed["ready"] is False

    def test_includes_all_report_fields(self):
        report = DiscoverReport(
            netbox_version="4.0.0",
            sites=["hq"],
            tenants=["acme"],
            device_roles=["server"],
            platforms=["linux"],
            existing_device_cfs=["last_seen"],
            missing_device_cfs=["first_seen"],
            existing_tags=["source:nmap"],
            missing_tags=["source:nessus"],
        )
        parsed = json.loads(render_json(report))
        for key in (
            "netbox_version",
            "sites",
            "tenants",
            "device_roles",
            "platforms",
            "existing_device_cfs",
            "missing_device_cfs",
            "existing_tags",
            "missing_tags",
        ):
            assert key in parsed


class TestDiscoverReport:
    def test_ready_default_true_with_no_missing(self):
        assert DiscoverReport(netbox_version="x").ready is True

    def test_ready_false_with_missing_cfs(self):
        assert DiscoverReport(netbox_version="x", missing_device_cfs=["a"]).ready is False

    def test_ready_false_with_missing_tags(self):
        assert DiscoverReport(netbox_version="x", missing_tags=["a"]).ready is False
