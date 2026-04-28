from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from .client import NetBoxClient
from .matcher import MatchResult
from .model import Host

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


def upsert_host(
    host: Host,
    match: MatchResult,
    client: NetBoxClient,
    *,
    scan_id: str,
    dry_run: bool,
    strategy: Strategy,
) -> UpsertResult:
    """Upsert a Host into NetBox.

    Ownership rule: if the matched Device carries the SOURCE_TAG, the bridge created it and may
    overwrite bridge-set fields freely. If not, the bridge only touches its own custom fields and
    leaves human-edited fields (description, comments, tenant, ...) alone.
    """
    raise NotImplementedError
