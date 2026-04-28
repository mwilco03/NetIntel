from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from .client import NetBoxClient
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


def match_host(host: Host, client: NetBoxClient) -> MatchResult:
    """Resolve a Host to a NetBox Device.

    Order: MAC (most stable), then primary IP, then FQDN. CONFLICT is reserved for the case where
    different keys point at different existing devices — e.g., MAC matches device A but IP matches
    device B. Caller decides what to do based on `--strategy`.
    """
    raise NotImplementedError
