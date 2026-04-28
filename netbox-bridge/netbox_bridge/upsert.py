from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel

from .matcher import MatchKind, MatchResult
from .model import Host, Service

CF_LAST_SEEN = "last_seen"
CF_FIRST_SEEN = "first_seen"
CF_LAST_SCAN_ID = "last_scan_id"
CF_SOURCE = "source"

SOURCE_TAG = "source:netintel-bridge"


class Strategy(str, Enum):
    MERGE = "merge"
    OVERWRITE = "overwrite"
    SKIP = "skip"


class UpsertAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    NOOP = "noop"
    CONFLICT = "conflict"


class FieldDiff(BaseModel):
    field: str
    before: str | None
    after: str | None


class UpsertResult(BaseModel):
    action: UpsertAction
    netbox_device_id: int | None = None
    diffs: list[FieldDiff] = []
    reason: str | None = None


@dataclass
class UpsertDefaults:
    site_id: int
    role_id: int
    device_type_id: int


class _ClientLike(Protocol):
    def create_device(self, spec: dict) -> Any: ...
    def create_interface(self, spec: dict) -> Any: ...
    def create_mac_address(self, spec: dict) -> Any: ...
    def create_ip_address(self, spec: dict) -> Any: ...
    def create_service(self, spec: dict) -> Any: ...
    def update_device(self, device_id: int, fields: dict) -> Any: ...
    def update_interface(self, interface_id: int, fields: dict) -> Any: ...


def _normalize_cidr(ip: str) -> str:
    if "/" in ip:
        return ip
    addr = ipaddress.ip_address(ip)
    return f"{ip}/{32 if addr.version == 4 else 128}"


def _ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip.split("/", 1)[0]).version


def _device_name(host: Host) -> str:
    return host.fqdn or host.primary_ip


def _service_name(svc: Service) -> str:
    return svc.name or f"port-{svc.port}/{svc.protocol}"


def _build_device_spec(host: Host, scan_id: str, defaults: UpsertDefaults) -> dict:
    timestamp = host.observed_at.isoformat()
    return {
        "name": _device_name(host),
        "device_type": defaults.device_type_id,
        "role": defaults.role_id,
        "site": defaults.site_id,
        "status": "active",
        "tags": [SOURCE_TAG, f"source:{host.source}"],
        "custom_fields": {
            CF_LAST_SEEN: timestamp,
            CF_FIRST_SEEN: timestamp,
            CF_LAST_SCAN_ID: scan_id,
            CF_SOURCE: host.source,
        },
    }


def _build_interface_spec(device_id: int) -> dict:
    return {
        "device": device_id,
        "name": "observed",
        "type": "other",
    }


def _build_mac_spec(mac: str, interface_id: int) -> dict:
    return {
        "mac_address": mac,
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface_id,
    }


def _build_ip_spec(host: Host, interface_id: int) -> dict:
    return {
        "address": _normalize_cidr(host.primary_ip),
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface_id,
        "status": "active",
    }


def _build_service_spec(svc: Service, device_id: int) -> dict:
    return {
        "parent_object_type": "dcim.device",
        "parent_object_id": device_id,
        "name": _service_name(svc),
        "ports": [svc.port],
        "protocol": svc.protocol,
    }


def upsert_host(
    host: Host,
    match: MatchResult,
    client: _ClientLike,
    *,
    scan_id: str,
    dry_run: bool,
    strategy: Strategy,
    defaults: UpsertDefaults,
) -> UpsertResult:
    if match.kind == MatchKind.CONFLICT:
        return UpsertResult(action=UpsertAction.CONFLICT, reason=match.reason)

    if match.kind != MatchKind.NEW:
        if strategy == Strategy.SKIP:
            return UpsertResult(
                action=UpsertAction.NOOP,
                netbox_device_id=match.netbox_device_id,
                reason="strategy=skip",
            )
        return UpsertResult(
            action=UpsertAction.NOOP,
            netbox_device_id=match.netbox_device_id,
            reason="UPDATE path not yet implemented",
        )

    device_spec = _build_device_spec(host, scan_id, defaults)
    if dry_run:
        return UpsertResult(action=UpsertAction.CREATE)

    device = client.create_device(device_spec)

    iface = client.create_interface(_build_interface_spec(device.id))

    first_mac = next((i.mac for i in host.interfaces if i.mac), None)
    if first_mac:
        mac = client.create_mac_address(_build_mac_spec(first_mac, iface.id))
        client.update_interface(iface.id, {"primary_mac_address": mac.id})

    ip = client.create_ip_address(_build_ip_spec(host, iface.id))

    primary_field = "primary_ip6" if _ip_version(host.primary_ip) == 6 else "primary_ip4"
    client.update_device(device.id, {primary_field: ip.id})

    for svc in host.services:
        client.create_service(_build_service_spec(svc, device.id))

    return UpsertResult(action=UpsertAction.CREATE, netbox_device_id=device.id)
