from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from .upsert import (
    ALERT_MAC_CHANGE_TAG,
    CF_FIRST_SEEN,
    CF_LAST_SCAN_ID,
    CF_LAST_SEEN,
    CF_OUI_VENDOR,
    CF_RELATED_MACS,
    CF_SOURCE,
    RECENTLY_ADDED_TAG,
    SOURCE_TAG,
)

REQUIRED_DEVICE_CFS: list[str] = [
    CF_LAST_SEEN,
    CF_FIRST_SEEN,
    CF_LAST_SCAN_ID,
    CF_SOURCE,
    CF_RELATED_MACS,
    CF_OUI_VENDOR,
]
REQUIRED_TAGS: list[str] = [
    SOURCE_TAG,
    "source:nmap",
    "source:nessus",
    RECENTLY_ADDED_TAG,
    ALERT_MAC_CHANGE_TAG,
]

DEVICE_CONTENT_TYPE = "dcim.device"


class _ClientLike(Protocol):
    def version(self) -> str: ...
    def list_sites(self) -> list[Any]: ...
    def list_tenants(self) -> list[Any]: ...
    def list_device_roles(self) -> list[Any]: ...
    def list_platforms(self) -> list[Any]: ...
    def list_custom_fields(self, content_type: str) -> list[Any]: ...
    def list_tags(self) -> list[Any]: ...


@dataclass
class DiscoverReport:
    netbox_version: str
    sites: list[str] = field(default_factory=list)
    tenants: list[str] = field(default_factory=list)
    device_roles: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    existing_device_cfs: list[str] = field(default_factory=list)
    missing_device_cfs: list[str] = field(default_factory=list)
    existing_tags: list[str] = field(default_factory=list)
    missing_tags: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.missing_device_cfs and not self.missing_tags


def discover(client: _ClientLike) -> DiscoverReport:
    sites = [s.name for s in client.list_sites()]
    tenants = [t.name for t in client.list_tenants()]
    device_roles = [r.name for r in client.list_device_roles()]
    platforms = [p.name for p in client.list_platforms()]
    device_cf_names = {cf.name for cf in client.list_custom_fields(DEVICE_CONTENT_TYPE)}
    tag_names = {t.name for t in client.list_tags()}

    required_cfs = set(REQUIRED_DEVICE_CFS)
    required_tags = set(REQUIRED_TAGS)

    return DiscoverReport(
        netbox_version=client.version(),
        sites=sites,
        tenants=tenants,
        device_roles=device_roles,
        platforms=platforms,
        existing_device_cfs=sorted(device_cf_names & required_cfs),
        missing_device_cfs=sorted(required_cfs - device_cf_names),
        existing_tags=sorted(tag_names & required_tags),
        missing_tags=sorted(required_tags - tag_names),
    )


def _fmt_list(items: list[str]) -> str:
    return ", ".join(items) if items else "(none)"


def render_human(report: DiscoverReport) -> str:
    lines = [
        f"NetBox version: {report.netbox_version}",
        f"Sites ({len(report.sites)}): {_fmt_list(report.sites)}",
        f"Tenants ({len(report.tenants)}): {_fmt_list(report.tenants)}",
        f"Device roles ({len(report.device_roles)}): {_fmt_list(report.device_roles)}",
        f"Platforms ({len(report.platforms)}): {_fmt_list(report.platforms)}",
        "",
        "Bridge prerequisites:",
        f"  Required device custom fields present: {_fmt_list(report.existing_device_cfs)}",
        f"  Required device custom fields missing: {_fmt_list(report.missing_device_cfs)}",
        f"  Required tags present: {_fmt_list(report.existing_tags)}",
        f"  Required tags missing: {_fmt_list(report.missing_tags)}",
        "",
    ]
    if report.ready:
        lines.append("Ready to ingest.")
    else:
        lines.append("NOT ready. Run `netbox-bridge init --apply` to create what's missing.")
    return "\n".join(lines)


def render_json(report: DiscoverReport) -> str:
    return json.dumps({**asdict(report), "ready": report.ready}, indent=2)
