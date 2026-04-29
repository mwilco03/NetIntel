from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from .discover import REQUIRED_DEVICE_CFS, REQUIRED_TAGS, discover
from .upsert import RECENTLY_ADDED_TAG  # noqa: F401  (intentional cross-import)

CF_CONTENT_TYPES: list[str] = ["dcim.device", "ipam.ipaddress", "ipam.service"]

_CF_DEFINITIONS: dict[str, dict[str, str]] = {
    "last_seen": {
        "label": "Last Seen",
        "type": "datetime",
        "description": "Most recent observation timestamp from netbox-bridge.",
    },
    "first_seen": {
        "label": "First Seen",
        "type": "datetime",
        "description": "First observation timestamp from netbox-bridge.",
    },
    "last_scan_id": {
        "label": "Last Scan ID",
        "type": "text",
        "description": "UUID of the most recent scan that touched this object.",
    },
    "source": {
        "label": "Source",
        "type": "text",
        "description": "Bridge source(s) that contributed to this object (nmap, nessus, ...).",
    },
    "related_macs": {
        "label": "Related MACs",
        "type": "json",
        "description": (
            "Windowed list of MAC addresses observed for this device's IP. "
            "More than one distinct MAC in the active window triggers alert:mac-change."
        ),
    },
    "oui_vendor": {
        "label": "OUI Vendor",
        "type": "text",
        "description": (
            "Vendor name resolved from the device's MAC OUI (first 24 bits) against "
            "the IEEE registry. High-confidence asset identification signal."
        ),
    },
}

# Distinct hex colors so each bridge-managed tag is visually distinguishable in the NetBox UI.
_TAG_COLORS: dict[str, str] = {
    "source:netintel-bridge": "1e88e5",  # blue
    "source:nmap": "43a047",             # green
    "source:nessus": "e53935",           # red
    "lifecycle:recently-added": "fb8c00",  # orange — "new in inventory"
    "alert:mac-change": "d32f2f",          # deep red — security alert
}


class _ClientLike(Protocol):
    def version(self) -> str: ...
    def list_sites(self) -> list[Any]: ...
    def list_tenants(self) -> list[Any]: ...
    def list_device_roles(self) -> list[Any]: ...
    def list_platforms(self) -> list[Any]: ...
    def list_custom_fields(self, content_type: str) -> list[Any]: ...
    def list_tags(self) -> list[Any]: ...
    def create_custom_field(self, spec: dict) -> None: ...
    def create_tag(self, spec: dict) -> None: ...


@dataclass
class InitPlan:
    custom_fields_to_create: list[dict] = field(default_factory=list)
    tags_to_create: list[dict] = field(default_factory=list)
    custom_fields_existing: list[str] = field(default_factory=list)
    tags_existing: list[str] = field(default_factory=list)
    applied: bool = False

    @property
    def is_noop(self) -> bool:
        return not self.custom_fields_to_create and not self.tags_to_create


def cf_spec(name: str) -> dict:
    """Build the NetBox payload for one bridge-owned custom field."""
    definition = _CF_DEFINITIONS[name]
    return {
        "name": name,
        "label": definition["label"],
        "type": definition["type"],
        "description": definition["description"],
        "object_types": list(CF_CONTENT_TYPES),
    }


def tag_spec(name: str) -> dict:
    """Build the NetBox payload for one bridge tag."""
    return {
        "name": name,
        "slug": name.replace(":", "-"),
        "color": _TAG_COLORS.get(name, "9e9e9e"),
        "description": f"Created by netbox-bridge ({name}).",
    }


def plan_init(client: _ClientLike) -> InitPlan:
    report = discover(client)
    return InitPlan(
        custom_fields_to_create=[cf_spec(n) for n in report.missing_device_cfs],
        tags_to_create=[tag_spec(n) for n in report.missing_tags],
        custom_fields_existing=list(report.existing_device_cfs),
        tags_existing=list(report.existing_tags),
        applied=False,
    )


def run_init(client: _ClientLike, *, apply: bool) -> InitPlan:
    plan = plan_init(client)
    if apply:
        for spec in plan.custom_fields_to_create:
            client.create_custom_field(spec)
        for spec in plan.tags_to_create:
            client.create_tag(spec)
        plan.applied = True
    return plan


def render_human(plan: InitPlan) -> str:
    if plan.is_noop:
        return "Nothing to do — all bridge custom fields and tags already exist."

    verb = "Created" if plan.applied else "Would create"
    lines = []
    if plan.custom_fields_to_create:
        lines.append(f"{verb} {len(plan.custom_fields_to_create)} custom field(s):")
        for spec in plan.custom_fields_to_create:
            lines.append(f"  - {spec['name']} ({spec['type']}) on {', '.join(spec['object_types'])}")
    if plan.tags_to_create:
        lines.append(f"{verb} {len(plan.tags_to_create)} tag(s):")
        for spec in plan.tags_to_create:
            lines.append(f"  - {spec['name']} (slug={spec['slug']}, color=#{spec['color']})")
    if not plan.applied:
        lines.append("")
        lines.append("Re-run with --apply to actually write these to NetBox.")
    return "\n".join(lines)


def render_json(plan: InitPlan) -> str:
    return json.dumps(
        {**asdict(plan), "is_noop": plan.is_noop},
        indent=2,
    )
