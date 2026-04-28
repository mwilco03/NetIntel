"""Pipeline orchestrator: stream Hosts through match -> upsert and accumulate results.

This is the loop that the plan and ingest CLI commands sit on top of. Errors during a single
host's upsert are caught and recorded as CONFLICT (with the exception text in `reason`) so a
single bad record can't kill an entire scan.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .matcher import MatchKind, MatchResult, match_host as default_match
from .model import Host
from .upsert import (
    Strategy,
    UpsertAction,
    UpsertDefaults,
    UpsertResult,
    upsert_host as default_upsert,
)


MatchFn = Callable[[Host, Any], MatchResult]
UpsertFn = Callable[..., UpsertResult]


@dataclass
class HostResult:
    host: Host
    match: MatchResult
    upsert: UpsertResult


@dataclass
class PipelineSummary:
    creates: int = 0
    updates: int = 0
    noops: int = 0
    conflicts: int = 0

    @property
    def total(self) -> int:
        return self.creates + self.updates + self.noops + self.conflicts

    @classmethod
    def from_results(cls, results: list[HostResult]) -> "PipelineSummary":
        s = cls()
        for r in results:
            if r.upsert.action == UpsertAction.CREATE:
                s.creates += 1
            elif r.upsert.action == UpsertAction.UPDATE:
                s.updates += 1
            elif r.upsert.action == UpsertAction.NOOP:
                s.noops += 1
            elif r.upsert.action == UpsertAction.CONFLICT:
                s.conflicts += 1
        return s


def run_pipeline(
    *,
    hosts: Iterable[Host],
    client: Any,
    scan_id: str,
    dry_run: bool,
    strategy: Strategy,
    defaults: UpsertDefaults,
    match_fn: MatchFn = default_match,
    upsert_fn: UpsertFn = default_upsert,
) -> list[HostResult]:
    results: list[HostResult] = []
    for host in hosts:
        try:
            match = match_fn(host, client)
        except Exception as e:
            results.append(
                HostResult(
                    host=host,
                    match=MatchResult(kind=MatchKind.CONFLICT, reason=f"match error: {e}"),
                    upsert=UpsertResult(action=UpsertAction.CONFLICT, reason=f"match error: {e}"),
                )
            )
            continue

        try:
            upsert = upsert_fn(
                host,
                match,
                client,
                scan_id=scan_id,
                dry_run=dry_run,
                strategy=strategy,
                defaults=defaults,
            )
        except Exception as e:
            upsert = UpsertResult(action=UpsertAction.CONFLICT, reason=f"upsert error: {e}")

        results.append(HostResult(host=host, match=match, upsert=upsert))

    return results


def _label(action: UpsertAction) -> str:
    return f"[{action.value.upper()}]"


def _host_label(host: Host) -> str:
    return host.fqdn or host.primary_ip


def _short_reason(result: HostResult) -> str:
    if result.upsert.reason:
        return result.upsert.reason
    n_diffs = len(result.upsert.diffs)
    if n_diffs:
        return f"{n_diffs} change(s)"
    return ""


def render_human(
    results: list[HostResult],
    *,
    summary: PipelineSummary,
    verbose: bool = False,
) -> str:
    lines: list[str] = []
    for r in results:
        label = _label(r.upsert.action)
        host_label = _host_label(r.host)
        reason = _short_reason(r)
        lines.append(f"{label:11} {r.host.primary_ip:18} {host_label:30} -- {reason}")
        if verbose and r.upsert.diffs:
            for d in r.upsert.diffs:
                lines.append(f"             {d.field}: {d.before!r} -> {d.after!r}")

    lines.append("")
    lines.append(
        f"Summary: {summary.creates} create, {summary.updates} update, "
        f"{summary.noops} noop, {summary.conflicts} conflict ({summary.total} total)"
    )
    return "\n".join(lines)


def render_json(results: list[HostResult], *, summary: PipelineSummary) -> str:
    return json.dumps(
        {
            "summary": {
                "creates": summary.creates,
                "updates": summary.updates,
                "noops": summary.noops,
                "conflicts": summary.conflicts,
                "total": summary.total,
            },
            "results": [
                {
                    "host": r.host.model_dump(mode="json"),
                    "match": r.match.model_dump(mode="json"),
                    "upsert": r.upsert.model_dump(mode="json"),
                }
                for r in results
            ],
        },
        indent=2,
        default=str,
    )
