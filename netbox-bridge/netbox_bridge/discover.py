from __future__ import annotations

from dataclasses import dataclass, field

from .client import NetBoxClient
from .upsert import (
    CF_FIRST_SEEN,
    CF_LAST_SCAN_ID,
    CF_LAST_SEEN,
    CF_SOURCE,
    SOURCE_TAG,
)

REQUIRED_DEVICE_CFS: list[str] = [CF_LAST_SEEN, CF_FIRST_SEEN, CF_LAST_SCAN_ID, CF_SOURCE]
REQUIRED_TAGS: list[str] = [SOURCE_TAG, "source:nmap", "source:nessus"]


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


def discover(client: NetBoxClient) -> DiscoverReport:
    raise NotImplementedError
