"""Tests for the `init` planner and CF/tag spec generator.

Init re-uses discover() under the hood: it learns what's missing, builds NetBox-shaped specs for
the missing custom fields and tags, then either applies them (when apply=True) or returns the
plan (when apply=False).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from netbox_bridge.discover import REQUIRED_DEVICE_CFS, REQUIRED_TAGS
from netbox_bridge.init import (
    CF_CONTENT_TYPES,
    InitPlan,
    cf_spec,
    plan_init,
    render_human,
    render_json,
    run_init,
    tag_spec,
)


@dataclass
class _Named:
    name: str


class FakeClient:
    """Same surface as discover's FakeClient plus create_* recording."""

    def __init__(
        self,
        *,
        version: str = "4.0.0",
        device_cfs: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
    ) -> None:
        self._version = version
        self._device_cfs = device_cfs
        self._tags = tags
        self.created_custom_fields: list[dict] = []
        self.created_tags: list[dict] = []

    def version(self) -> str:
        return self._version

    def list_sites(self): return []
    def list_tenants(self): return []
    def list_device_roles(self): return []
    def list_platforms(self): return []

    def list_custom_fields(self, content_type: str):
        return [_Named(n) for n in self._device_cfs]

    def list_tags(self):
        return [_Named(n) for n in self._tags]

    def create_custom_field(self, spec: dict) -> None:
        self.created_custom_fields.append(spec)

    def create_tag(self, spec: dict) -> None:
        self.created_tags.append(spec)


class TestCFSpec:
    def test_last_seen_is_datetime(self):
        spec = cf_spec("last_seen")
        assert spec["type"] == "datetime"

    def test_first_seen_is_datetime(self):
        spec = cf_spec("first_seen")
        assert spec["type"] == "datetime"

    def test_last_scan_id_is_text(self):
        spec = cf_spec("last_scan_id")
        assert spec["type"] == "text"

    def test_source_is_text(self):
        spec = cf_spec("source")
        assert spec["type"] == "text"

    def test_applies_to_device_ip_and_service(self):
        spec = cf_spec("last_seen")
        assert "dcim.device" in spec["object_types"]
        assert "ipam.ipaddress" in spec["object_types"]
        assert "ipam.service" in spec["object_types"]

    def test_includes_name_and_label(self):
        spec = cf_spec("last_seen")
        assert spec["name"] == "last_seen"
        assert spec["label"]

    def test_unknown_field_raises(self):
        with pytest.raises(KeyError):
            cf_spec("not_a_real_field")


class TestTagSpec:
    def test_slug_replaces_colon_with_hyphen(self):
        spec = tag_spec("source:nmap")
        assert spec["slug"] == "source-nmap"

    def test_name_preserved(self):
        spec = tag_spec("source:nmap")
        assert spec["name"] == "source:nmap"

    def test_color_is_hex_without_hash(self):
        spec = tag_spec("source:nmap")
        assert spec["color"]
        assert not spec["color"].startswith("#")
        assert len(spec["color"]) == 6

    def test_each_required_tag_has_distinct_color(self):
        colors = {tag_spec(name)["color"] for name in REQUIRED_TAGS}
        assert len(colors) == len(REQUIRED_TAGS)


class TestPlanInit:
    def test_no_pending_actions_when_everything_exists(self):
        client = FakeClient(device_cfs=tuple(REQUIRED_DEVICE_CFS), tags=tuple(REQUIRED_TAGS))
        plan = plan_init(client)
        assert plan.custom_fields_to_create == []
        assert plan.tags_to_create == []
        assert plan.is_noop

    def test_lists_missing_cfs_with_full_spec(self):
        plan = plan_init(FakeClient(tags=tuple(REQUIRED_TAGS)))
        names = [s["name"] for s in plan.custom_fields_to_create]
        assert sorted(names) == sorted(REQUIRED_DEVICE_CFS)
        for spec in plan.custom_fields_to_create:
            assert "type" in spec
            assert "object_types" in spec

    def test_lists_missing_tags_with_full_spec(self):
        plan = plan_init(FakeClient(device_cfs=tuple(REQUIRED_DEVICE_CFS)))
        names = [s["name"] for s in plan.tags_to_create]
        assert sorted(names) == sorted(REQUIRED_TAGS)
        for spec in plan.tags_to_create:
            assert "slug" in spec
            assert "color" in spec

    def test_partial_presence_only_lists_missing(self):
        client = FakeClient(
            device_cfs=("last_seen", "source"),
            tags=("source:nmap",),
        )
        plan = plan_init(client)
        cf_names = {s["name"] for s in plan.custom_fields_to_create}
        tag_names = {s["name"] for s in plan.tags_to_create}
        assert cf_names == {"first_seen", "last_scan_id", "related_macs", "oui_vendor"}
        assert tag_names == {
            "source:netintel-bridge",
            "source:nessus",
            "lifecycle:recently-added",
            "alert:mac-change",
            "class:ot",
            "class:it",
            "class:mixed",
        }


class TestRunInitDryRun:
    def test_dry_run_does_not_call_create(self):
        client = FakeClient()
        run_init(client, apply=False)
        assert client.created_custom_fields == []
        assert client.created_tags == []

    def test_dry_run_returns_plan_with_pending_actions(self):
        plan = run_init(FakeClient(), apply=False)
        assert plan.applied is False
        assert not plan.is_noop


class TestRunInitApply:
    def test_apply_creates_each_missing_cf(self):
        client = FakeClient()
        run_init(client, apply=True)
        names = sorted(s["name"] for s in client.created_custom_fields)
        assert names == sorted(REQUIRED_DEVICE_CFS)

    def test_apply_creates_each_missing_tag(self):
        client = FakeClient()
        run_init(client, apply=True)
        names = sorted(s["name"] for s in client.created_tags)
        assert names == sorted(REQUIRED_TAGS)

    def test_apply_skips_existing(self):
        client = FakeClient(device_cfs=("last_seen",), tags=("source:nmap",))
        run_init(client, apply=True)
        assert "last_seen" not in [s["name"] for s in client.created_custom_fields]
        assert "source:nmap" not in [s["name"] for s in client.created_tags]

    def test_apply_noop_when_nothing_missing(self):
        client = FakeClient(device_cfs=tuple(REQUIRED_DEVICE_CFS), tags=tuple(REQUIRED_TAGS))
        plan = run_init(client, apply=True)
        assert client.created_custom_fields == []
        assert client.created_tags == []
        assert plan.applied is True
        assert plan.is_noop


class TestRenderHuman:
    def test_dry_run_says_would_create(self):
        plan = run_init(FakeClient(), apply=False)
        out = render_human(plan)
        assert "Would create" in out or "would create" in out

    def test_apply_says_created(self):
        plan = run_init(FakeClient(), apply=True)
        out = render_human(plan)
        assert "Created" in out or "created" in out

    def test_lists_each_missing_cf(self):
        plan = run_init(FakeClient(), apply=False)
        out = render_human(plan)
        for cf_name in REQUIRED_DEVICE_CFS:
            assert cf_name in out

    def test_lists_each_missing_tag(self):
        plan = run_init(FakeClient(), apply=False)
        out = render_human(plan)
        for tag_name in REQUIRED_TAGS:
            assert tag_name in out

    def test_noop_message_when_nothing_to_do(self):
        client = FakeClient(device_cfs=tuple(REQUIRED_DEVICE_CFS), tags=tuple(REQUIRED_TAGS))
        out = render_human(run_init(client, apply=False))
        assert "Nothing to do" in out or "nothing to do" in out


class TestRenderJson:
    def test_emits_valid_json(self):
        plan = run_init(FakeClient(), apply=False)
        json.loads(render_json(plan))

    def test_includes_applied_flag(self):
        plan = run_init(FakeClient(), apply=True)
        parsed = json.loads(render_json(plan))
        assert parsed["applied"] is True

    def test_includes_pending_specs(self):
        plan = run_init(FakeClient(), apply=False)
        parsed = json.loads(render_json(plan))
        assert "custom_fields_to_create" in parsed
        assert "tags_to_create" in parsed


def test_cf_content_types_constant_includes_all_three():
    assert "dcim.device" in CF_CONTENT_TYPES
    assert "ipam.ipaddress" in CF_CONTENT_TYPES
    assert "ipam.service" in CF_CONTENT_TYPES
