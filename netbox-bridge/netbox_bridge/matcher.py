from __future__ import annotations

from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel

from .model import Host


class MatchKind(str, Enum):
    NEW = "new"
    BY_MAC = "by_mac"
    BY_IP = "by_ip"
    BY_FQDN = "by_fqdn"
    CONFLICT = "conflict"


class MatchResult(BaseModel):
    kind: MatchKind
    netbox_device_id: int | None = None
    reason: str | None = None


class _ClientLike(Protocol):
    def find_device_by_mac(self, mac: str) -> Any | None: ...
    def find_device_by_primary_ip(self, ip: str) -> Any | None: ...
    def find_device_by_name(self, name: str) -> Any | None: ...


def _device_id(device: Any | None) -> int | None:
    return getattr(device, "id", None) if device is not None else None


def match_host(host: Host, client: _ClientLike) -> MatchResult:
    """Resolve a Host to a NetBox Device.

    Order: MAC (most stable), then primary IP, then FQDN. CONFLICT is reserved for the case where
    different keys point at different existing devices.
    """
    mac_match: Any | None = None
    for iface in host.interfaces:
        if not iface.mac:
            continue
        candidate = client.find_device_by_mac(iface.mac.lower())
        if candidate is not None:
            mac_match = candidate
            break

    ip_match = client.find_device_by_primary_ip(host.primary_ip) if host.primary_ip else None
    fqdn_match = client.find_device_by_name(host.fqdn) if host.fqdn else None

    matches = [
        ("mac", mac_match),
        ("ip", ip_match),
        ("fqdn", fqdn_match),
    ]
    non_null = [(k, m) for k, m in matches if m is not None]

    if not non_null:
        return MatchResult(kind=MatchKind.NEW)

    unique_ids = {_device_id(m) for _, m in non_null}
    if len(unique_ids) > 1:
        details = ", ".join(f"{k}=#{_device_id(m)}" for k, m in non_null)
        return MatchResult(
            kind=MatchKind.CONFLICT,
            reason=f"keys point to different devices: {details}",
        )

    # All point to the same device; return by priority.
    chosen_id = next(iter(unique_ids))
    if mac_match is not None:
        return MatchResult(kind=MatchKind.BY_MAC, netbox_device_id=chosen_id)
    if ip_match is not None:
        return MatchResult(kind=MatchKind.BY_IP, netbox_device_id=chosen_id)
    return MatchResult(kind=MatchKind.BY_FQDN, netbox_device_id=chosen_id)
