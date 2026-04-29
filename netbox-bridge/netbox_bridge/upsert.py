from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel

from .classify import ALL_CLASS_TAGS, classify_tags
from .matcher import MatchKind, MatchResult
from .model import Host, Service
from .oui import lookup_vendor

CF_LAST_SEEN = "last_seen"
CF_FIRST_SEEN = "first_seen"
CF_LAST_SCAN_ID = "last_scan_id"
CF_SOURCE = "source"
CF_RELATED_MACS = "related_macs"
CF_OUI_VENDOR = "oui_vendor"
CF_SURICATA_ALERTS_TOTAL = "suricata_alerts_total"
CF_SURICATA_ALERTS_HIGH = "suricata_alerts_high"
CF_SURICATA_ALERTS_MEDIUM = "suricata_alerts_medium"
CF_SURICATA_ALERTS_LOW = "suricata_alerts_low"
CF_SURICATA_TOP_SIGNATURES = "suricata_top_signatures"

SOURCE_TAG = "source:netintel-bridge"
RECENTLY_ADDED_TAG = "lifecycle:recently-added"
ALERT_MAC_CHANGE_TAG = "alert:mac-change"
ALERT_NOISY_TAG = "alert:noisy"
RECENTLY_ADDED_WINDOW = timedelta(days=7)
RELATED_MAC_WINDOW = timedelta(days=7)
NOISY_THRESHOLD = 100  # alerts in the source's window — adjust per deployment


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
        "observed_at": _iso_z(observed_at),
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


def _merge_mac_observations(
    existing: list[dict],
    new_macs: list[str],
    observed_at: datetime,
    scan_id: str,
) -> list[dict]:
    """Merge new MAC observations into existing list, deduplicated by MAC.

    For each MAC, the most recent observation wins. Without this, a re-scan of an unchanged
    network appends a duplicate per-MAC entry every run, breaking idempotency. Verified
    2026-04-29 by running the same scan twice against live NetBox 4.5 and seeing related_macs
    grow.
    """
    by_mac: dict[str, dict] = {}
    for entry in existing:
        m = (entry.get("mac") or "").lower()
        if m:
            by_mac[m] = entry
    for mac in new_macs:
        by_mac[mac.lower()] = _new_mac_entry(mac, observed_at, scan_id)
    return list(by_mac.values())


def _suricata_cf_payload(host: Host) -> dict:
    """Map host.suricata_alerts to NetBox CF dict, or {} if no alerts attached."""
    alerts = host.suricata_alerts
    if alerts is None:
        return {}
    return {
        CF_SURICATA_ALERTS_TOTAL: alerts.total,
        CF_SURICATA_ALERTS_HIGH: alerts.high,
        CF_SURICATA_ALERTS_MEDIUM: alerts.medium,
        CF_SURICATA_ALERTS_LOW: alerts.low,
        CF_SURICATA_TOP_SIGNATURES: [s.model_dump() for s in alerts.top_signatures],
    }


def _iso_z(dt: datetime) -> str:
    """Emit datetime in NetBox's stored format (UTC with trailing 'Z').

    NetBox 4.x normalizes datetime custom fields on read to '2026-04-28T12:00:00Z' regardless
    of the timezone offset sent. Sending '+00:00' would cause every re-scan to detect a string
    diff and PATCH unnecessarily — breaking idempotency. Verified 2026-04-29 against live
    NetBox 4.5 by observing a write of '+00:00' returned as 'Z'.
    """
    s = dt.isoformat()
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    return s


def _build_device_spec(host: Host, scan_id: str, defaults: UpsertDefaults) -> dict:
    timestamp = _iso_z(host.observed_at)
    custom_fields: dict = {
        CF_LAST_SEEN: timestamp,
        CF_FIRST_SEEN: timestamp,
        CF_LAST_SCAN_ID: scan_id,
        CF_SOURCE: host.source,
    }
    vendor: str | None = None
    macs = _observed_macs(host)
    if macs:
        custom_fields[CF_RELATED_MACS] = [
            _new_mac_entry(m, host.observed_at, scan_id) for m in macs
        ]
        vendor = lookup_vendor(macs[0])
        if vendor:
            custom_fields[CF_OUI_VENDOR] = vendor

    custom_fields.update(_suricata_cf_payload(host))

    tags = [SOURCE_TAG, f"source:{host.source}", RECENTLY_ADDED_TAG]
    tags.extend(sorted(classify_tags(host, vendor)))
    if host.suricata_alerts is not None and host.suricata_alerts.total > NOISY_THRESHOLD:
        tags.append(ALERT_NOISY_TAG)

    return {
        "name": _device_name(host),
        "device_type": defaults.device_type_id,
        "role": defaults.role_id,
        "site": defaults.site_id,
        "status": "active",
        # NetBox 4.x rejects tag-as-string. Verified 2026-04-29 against live NetBox 4.5:
        #   {'tags': ['Related objects must be referenced by numeric ID or by dictionary of
        #    attributes. Received an unrecognized value: source:netintel-bridge']}
        # Send each tag as {"name": "..."}; NetBox resolves to ID server-side.
        "tags": [{"name": n} for n in tags],
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


def _parse_nb_version(version_str: str) -> tuple[int, int]:
    """Parse '4.2.5' or '4.5' or '4.5.0-rc1' to (major, minor)."""
    parts = version_str.split(".", 2)
    try:
        return (int(parts[0]), int(parts[1]))
    except (IndexError, ValueError):
        return (0, 0)


def _build_service_spec(svc: Service, device_id: int, *, nb_version: str) -> dict:
    """Build the Service POST payload.

    Service serializer changed shape between NetBox 4.2 and 4.3:
      - 4.2.x: writable fields include `device` and `virtual_machine` (verified at
        https://github.com/netbox-community/netbox/blob/v4.2.5/netbox/ipam/api/serializers_/services.py)
      - 4.3+:  `device` removed; uses `parent_object_type` + `parent_object_id`
        (verified at https://github.com/netbox-community/netbox/blob/main/netbox/ipam/api/serializers_/services.py)
    Sending the wrong shape returns 400. The version-aware switch keeps the bridge
    correct for both target NetBox 4.2.5 deployments and current 4.5+ ones.
    """
    base = {
        "name": _service_name(svc),
        "ports": [svc.port],
        "protocol": svc.protocol,
    }
    if _parse_nb_version(nb_version) >= (4, 3):
        return {**base, "parent_object_type": "dcim.device", "parent_object_id": device_id}
    return {**base, "device": device_id}


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
    new_observed_iso = _iso_z(host.observed_at)
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
        # Strip class:* tags before recomputing — mutual exclusion among class:ot/it/mixed.
        desired_names = (existing_names - ALL_CLASS_TAGS) | {SOURCE_TAG, f"source:{host.source}"}

        if _is_recently_added(existing_cfs.get(CF_FIRST_SEEN), host.observed_at):
            desired_names.add(RECENTLY_ADDED_TAG)
        else:
            desired_names.discard(RECENTLY_ADDED_TAG)

        # OUI vendor identification — refresh when a known vendor differs from existing.
        observed_macs = _observed_macs(host)
        existing_vendor = existing_cfs.get(CF_OUI_VENDOR)
        effective_vendor: str | None = existing_vendor
        if observed_macs:
            new_vendor = lookup_vendor(observed_macs[0])
            if new_vendor and new_vendor != existing_vendor:
                custom_fields_patch[CF_OUI_VENDOR] = new_vendor
                diffs.append(
                    FieldDiff(
                        field=CF_OUI_VENDOR,
                        before=existing_vendor,
                        after=new_vendor,
                    )
                )
                effective_vendor = new_vendor

        # Re-classify based on current host services + effective vendor.
        desired_names |= classify_tags(host, effective_vendor)

        # Suricata enrichment: per-severity counts + alert:noisy tag aging.
        if host.suricata_alerts is not None:
            new_cfs = _suricata_cf_payload(host)
            for k, v in new_cfs.items():
                if existing_cfs.get(k) != v:
                    custom_fields_patch[k] = v
                    before = existing_cfs.get(k)
                    diffs.append(
                        FieldDiff(
                            field=k,
                            before=str(before) if before is not None else None,
                            after=str(v),
                        )
                    )
            if host.suricata_alerts.total > NOISY_THRESHOLD:
                desired_names.add(ALERT_NOISY_TAG)
            else:
                desired_names.discard(ALERT_NOISY_TAG)

        # related_macs windowed list + alert:mac-change tag aging
        existing_related = list(existing_cfs.get(CF_RELATED_MACS) or [])
        merged = _merge_mac_observations(
            existing_related, _observed_macs(host), host.observed_at, scan_id
        )
        trimmed = _trim_mac_entries(merged, host.observed_at)
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
            # NetBox tag PATCH also requires {"name": ...} form (verified against live NetBox 4.5).
            patch["tags"] = [{"name": n} for n in sorted(desired_names)]
            diffs.append(
                FieldDiff(
                    field="tags",
                    before=",".join(sorted(existing_names)) or None,
                    after=",".join(sorted(desired_names)),
                )
            )

    return patch, diffs


def _service_key(svc: Any) -> tuple[int, str] | None:
    """Extract (port, protocol) from a NetBox Service object or our internal Service.

    NetBox 4.x Service has `ports` (a list) and `protocol` (a Choice with `.value`).
    Our internal Service has `port` (single int) and `protocol` (literal string).
    Verified 2026-04-29 against pynetbox 7.x return shapes.
    """
    # internal Service (pydantic)
    if hasattr(svc, "port"):
        return (int(svc.port), str(svc.protocol))
    # NetBox Service (pynetbox)
    ports = getattr(svc, "ports", None)
    if not ports:
        return None
    proto_attr = getattr(svc, "protocol", None)
    proto = (
        getattr(proto_attr, "value", None)
        if proto_attr is not None and hasattr(proto_attr, "value")
        else proto_attr
    )
    return (int(ports[0]), str(proto)) if proto else None


def _missing_services(host: Host, client: _ClientLike, device_id: int) -> list[Service]:
    existing_keys: set[tuple[int, str]] = set()
    for s in client.list_services_for_device(device_id):
        key = _service_key(s)
        if key is not None:
            existing_keys.add(key)
    return [s for s in host.services if _service_key(s) not in existing_keys]


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

    nb_version = getattr(client, "netbox_version", "4.5")
    for svc in host.services:
        client.create_service(_build_service_spec(svc, device.id, nb_version=nb_version))

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
        nb_version = getattr(client, "netbox_version", "4.5")
        for svc in _missing_services(host, client, existing.id):
            new_services.append(_build_service_spec(svc, existing.id, nb_version=nb_version))

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
