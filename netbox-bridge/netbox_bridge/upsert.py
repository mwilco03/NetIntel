from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel

from .matcher import MatchKind, MatchResult
from .model import Host, Service

CF_LAST_SEEN = "last_seen"
CF_FIRST_SEEN = "first_seen"
CF_LAST_SCAN_ID = "last_scan_id"
CF_SOURCE = "source"
CF_RELATED_MACS = "related_macs"

SOURCE_TAG = "source:netintel-bridge"
RECENTLY_ADDED_TAG = "lifecycle:recently-added"
ALERT_MAC_CHANGE_TAG = "alert:mac-change"
RECENTLY_ADDED_WINDOW = timedelta(days=7)
RELATED_MAC_WINDOW = timedelta(days=7)


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
    def get_device(self, device_id: int) -> Any | None: ...
    def list_services_for_device(self, device_id: int) -> list[Any]: ...


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


def _observed_macs(host: Host) -> list[str]:
    return [i.mac.lower() for i in host.interfaces if i.mac]


def _new_mac_entry(mac: str, observed_at: datetime, scan_id: str) -> dict:
    return {
        "mac": mac.lower(),
        "observed_at": observed_at.isoformat(),
        "scan_id": scan_id,
    }


def _trim_mac_entries(entries: list[dict], now: datetime) -> list[dict]:
    threshold = now - RELATED_MAC_WINDOW
    keep: list[dict] = []
    for e in entries:
        ts = _parse_iso(e.get("observed_at"))
        if ts is not None and ts >= threshold:
            keep.append(e)
    return keep


def _build_device_spec(host: Host, scan_id: str, defaults: UpsertDefaults) -> dict:
    timestamp = host.observed_at.isoformat()
    custom_fields: dict = {
        CF_LAST_SEEN: timestamp,
        CF_FIRST_SEEN: timestamp,
        CF_LAST_SCAN_ID: scan_id,
        CF_SOURCE: host.source,
    }
    macs = _observed_macs(host)
    if macs:
        custom_fields[CF_RELATED_MACS] = [
            _new_mac_entry(m, host.observed_at, scan_id) for m in macs
        ]
    return {
        "name": _device_name(host),
        "device_type": defaults.device_type_id,
        "role": defaults.role_id,
        "site": defaults.site_id,
        "status": "active",
        "tags": [SOURCE_TAG, f"source:{host.source}", RECENTLY_ADDED_TAG],
        "custom_fields": custom_fields,
    }


def _is_recently_added(first_seen_iso: str | None, now: datetime) -> bool:
    """Bridge-tracked device counts as recently added when its first_seen is inside the window."""
    if not first_seen_iso:
        return False
    first_seen = _parse_iso(first_seen_iso)
    if first_seen is None:
        return False
    return (now - first_seen) < RECENTLY_ADDED_WINDOW


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


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _existing_tag_names(existing: Any) -> set[str]:
    return {getattr(t, "name", "") for t in (getattr(existing, "tags", []) or [])}


def _is_bridge_owned(existing: Any) -> bool:
    return SOURCE_TAG in _existing_tag_names(existing)


def _build_update_patch(
    host: Host,
    existing: Any,
    *,
    scan_id: str,
    owned_for_writes: bool,
) -> tuple[dict, list[FieldDiff]]:
    new_observed_iso = host.observed_at.isoformat()
    existing_cfs = getattr(existing, "custom_fields", {}) or {}

    custom_fields_patch: dict = {}
    diffs: list[FieldDiff] = []

    # last_seen — always advanced (caller already gated on observation freshness).
    existing_last_seen = existing_cfs.get(CF_LAST_SEEN)
    if existing_last_seen != new_observed_iso:
        custom_fields_patch[CF_LAST_SEEN] = new_observed_iso
        diffs.append(
            FieldDiff(field=CF_LAST_SEEN, before=existing_last_seen, after=new_observed_iso)
        )

    if owned_for_writes:
        existing_scan = existing_cfs.get(CF_LAST_SCAN_ID)
        if existing_scan != scan_id:
            custom_fields_patch[CF_LAST_SCAN_ID] = scan_id
            diffs.append(FieldDiff(field=CF_LAST_SCAN_ID, before=existing_scan, after=scan_id))

        existing_source_raw = existing_cfs.get(CF_SOURCE) or ""
        existing_sources = {s for s in existing_source_raw.split(",") if s}
        if host.source not in existing_sources:
            new_sources = sorted(existing_sources | {host.source})
            new_source_value = ",".join(new_sources)
            custom_fields_patch[CF_SOURCE] = new_source_value
            diffs.append(
                FieldDiff(field=CF_SOURCE, before=existing_source_raw or None, after=new_source_value)
            )

    patch: dict = {}
    if custom_fields_patch:
        patch["custom_fields"] = custom_fields_patch

    if owned_for_writes:
        existing_names = _existing_tag_names(existing)
        desired_names = existing_names | {SOURCE_TAG, f"source:{host.source}"}

        if _is_recently_added(existing_cfs.get(CF_FIRST_SEEN), host.observed_at):
            desired_names.add(RECENTLY_ADDED_TAG)
        else:
            desired_names.discard(RECENTLY_ADDED_TAG)

        # related_macs windowed list + alert:mac-change tag aging
        existing_related = list(existing_cfs.get(CF_RELATED_MACS) or [])
        appended = list(existing_related)
        for mac in _observed_macs(host):
            appended.append(_new_mac_entry(mac, host.observed_at, scan_id))
        trimmed = _trim_mac_entries(appended, host.observed_at)
        if trimmed != existing_related:
            custom_fields_patch[CF_RELATED_MACS] = trimmed
            diffs.append(
                FieldDiff(
                    field=CF_RELATED_MACS,
                    before=str(existing_related) if existing_related else None,
                    after=str(trimmed),
                )
            )
        distinct_active = {e["mac"] for e in trimmed}
        if len(distinct_active) > 1:
            desired_names.add(ALERT_MAC_CHANGE_TAG)
        else:
            desired_names.discard(ALERT_MAC_CHANGE_TAG)

        if custom_fields_patch and "custom_fields" not in patch:
            patch["custom_fields"] = custom_fields_patch

        if desired_names != existing_names:
            patch["tags"] = sorted(desired_names)
            diffs.append(
                FieldDiff(
                    field="tags",
                    before=",".join(sorted(existing_names)) or None,
                    after=",".join(sorted(desired_names)),
                )
            )

    return patch, diffs


def _missing_services(host: Host, client: _ClientLike, device_id: int) -> list[Service]:
    existing_keys = {
        (s.port, s.protocol) for s in client.list_services_for_device(device_id)
    }
    return [s for s in host.services if (s.port, s.protocol) not in existing_keys]


def _create_path(
    host: Host,
    client: _ClientLike,
    *,
    scan_id: str,
    dry_run: bool,
    defaults: UpsertDefaults,
) -> UpsertResult:
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


def _update_path(
    host: Host,
    match: MatchResult,
    client: _ClientLike,
    *,
    scan_id: str,
    dry_run: bool,
    strategy: Strategy,
) -> UpsertResult:
    existing = client.get_device(match.netbox_device_id) if match.netbox_device_id else None
    if existing is None:
        return UpsertResult(
            action=UpsertAction.NOOP,
            netbox_device_id=match.netbox_device_id,
            reason="device not found in NetBox",
        )

    existing_cfs = getattr(existing, "custom_fields", {}) or {}
    existing_last_seen_dt = _parse_iso(existing_cfs.get(CF_LAST_SEEN))
    # Only short-circuit when the recorded last_seen is strictly newer. Equal timestamps still
    # need to fall through so tag-aging (lifecycle:recently-added) can run.
    if existing_last_seen_dt is not None and existing_last_seen_dt > host.observed_at:
        return UpsertResult(
            action=UpsertAction.NOOP,
            netbox_device_id=existing.id,
            reason="observation is older than recorded last_seen",
        )

    bridge_owned = _is_bridge_owned(existing)
    owned_for_writes = bridge_owned or strategy == Strategy.OVERWRITE

    patch, diffs = _build_update_patch(
        host, existing, scan_id=scan_id, owned_for_writes=owned_for_writes
    )

    new_services: list[dict] = []
    if owned_for_writes and host.services:
        for svc in _missing_services(host, client, existing.id):
            new_services.append(_build_service_spec(svc, existing.id))

    if not patch and not new_services:
        return UpsertResult(
            action=UpsertAction.NOOP,
            netbox_device_id=existing.id,
            diffs=diffs,
        )

    if not dry_run:
        if patch:
            client.update_device(existing.id, patch)
        for svc_spec in new_services:
            client.create_service(svc_spec)

    for svc_spec in new_services:
        diffs.append(
            FieldDiff(
                field="service",
                before=None,
                after=f"{svc_spec['ports'][0]}/{svc_spec['protocol']}",
            )
        )

    return UpsertResult(
        action=UpsertAction.UPDATE,
        netbox_device_id=existing.id,
        diffs=diffs,
    )


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

    if match.kind == MatchKind.NEW:
        return _create_path(host, client, scan_id=scan_id, dry_run=dry_run, defaults=defaults)

    if strategy == Strategy.SKIP:
        return UpsertResult(
            action=UpsertAction.NOOP,
            netbox_device_id=match.netbox_device_id,
            reason="strategy=skip",
        )

    return _update_path(
        host, match, client, scan_id=scan_id, dry_run=dry_run, strategy=strategy
    )
