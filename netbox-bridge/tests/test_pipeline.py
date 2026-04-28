"""Tests for the pipeline orchestrator.

The pipeline is the loop that takes a stream of Host records (from any source) and feeds each
through match_host -> upsert_host, accumulating per-host results. This is what the plan and
ingest CLI commands sit on top of.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from netbox_bridge.matcher import MatchKind, MatchResult
from netbox_bridge.model import Host, Service
from netbox_bridge.pipeline import (
    PipelineSummary,
    render_human,
    render_json,
    run_pipeline,
)
from netbox_bridge.upsert import (
    FieldDiff,
    Strategy,
    UpsertAction,
    UpsertDefaults,
    UpsertResult,
)


def _host(**kwargs) -> Host:
    return Host(
        primary_ip=kwargs.get("primary_ip", "10.0.0.5"),
        fqdn=kwargs.get("fqdn"),
        interfaces=kwargs.get("interfaces", []),
        services=kwargs.get("services", []),
        source=kwargs.get("source", "nmap"),  # type: ignore[arg-type]
        observed_at=kwargs.get("observed_at", datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)),
    )


def _defaults() -> UpsertDefaults:
    return UpsertDefaults(site_id=1, role_id=2, device_type_id=3)


SCAN_ID = "00000000-0000-0000-0000-000000000abc"


class TestRunPipeline:
    def test_calls_match_then_upsert_per_host(self):
        client = MagicMock()
        hosts = [_host(primary_ip="10.0.0.1"), _host(primary_ip="10.0.0.2")]

        def fake_match(host, c):
            return MatchResult(kind=MatchKind.NEW)

        def fake_upsert(host, match, c, **kwargs):
            return UpsertResult(action=UpsertAction.CREATE, netbox_device_id=42)

        results = run_pipeline(
            hosts=hosts,
            client=client,
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
            match_fn=fake_match,
            upsert_fn=fake_upsert,
        )

        assert len(results) == 2
        for r in results:
            assert r.upsert.action == UpsertAction.CREATE

    def test_passes_scan_id_through_to_upsert(self):
        client = MagicMock()
        captured = {}

        def fake_upsert(host, match, c, *, scan_id, dry_run, strategy, defaults):
            captured["scan_id"] = scan_id
            return UpsertResult(action=UpsertAction.CREATE)

        run_pipeline(
            hosts=[_host()],
            client=client,
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
            match_fn=lambda h, c: MatchResult(kind=MatchKind.NEW),
            upsert_fn=fake_upsert,
        )
        assert captured["scan_id"] == SCAN_ID

    def test_passes_dry_run_through_to_upsert(self):
        captured = {}

        def fake_upsert(host, match, c, *, scan_id, dry_run, strategy, defaults):
            captured["dry_run"] = dry_run
            return UpsertResult(action=UpsertAction.CREATE)

        run_pipeline(
            hosts=[_host()],
            client=MagicMock(),
            scan_id=SCAN_ID,
            dry_run=True,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
            match_fn=lambda h, c: MatchResult(kind=MatchKind.NEW),
            upsert_fn=fake_upsert,
        )
        assert captured["dry_run"] is True

    def test_passes_strategy_through_to_upsert(self):
        captured = {}

        def fake_upsert(host, match, c, *, scan_id, dry_run, strategy, defaults):
            captured["strategy"] = strategy
            return UpsertResult(action=UpsertAction.CREATE)

        run_pipeline(
            hosts=[_host()],
            client=MagicMock(),
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.OVERWRITE,
            defaults=_defaults(),
            match_fn=lambda h, c: MatchResult(kind=MatchKind.NEW),
            upsert_fn=fake_upsert,
        )
        assert captured["strategy"] == Strategy.OVERWRITE

    def test_continues_on_individual_upsert_errors(self):
        # If one host's upsert raises, subsequent hosts still run; the error is recorded.
        client = MagicMock()
        hosts = [_host(primary_ip="10.0.0.1"), _host(primary_ip="10.0.0.2"), _host(primary_ip="10.0.0.3")]

        def fake_upsert(host, match, c, **kwargs):
            if host.primary_ip == "10.0.0.2":
                raise RuntimeError("boom")
            return UpsertResult(action=UpsertAction.CREATE)

        results = run_pipeline(
            hosts=hosts,
            client=client,
            scan_id=SCAN_ID,
            dry_run=False,
            strategy=Strategy.MERGE,
            defaults=_defaults(),
            match_fn=lambda h, c: MatchResult(kind=MatchKind.NEW),
            upsert_fn=fake_upsert,
        )
        assert len(results) == 3
        actions = [r.upsert.action for r in results]
        assert actions[0] == UpsertAction.CREATE
        assert actions[1] == UpsertAction.CONFLICT  # error recorded as conflict
        assert "boom" in (results[1].upsert.reason or "")
        assert actions[2] == UpsertAction.CREATE


class TestPipelineSummary:
    def test_counts_actions(self):
        results = [
            _result(UpsertAction.CREATE),
            _result(UpsertAction.CREATE),
            _result(UpsertAction.UPDATE),
            _result(UpsertAction.NOOP),
            _result(UpsertAction.CONFLICT),
        ]
        summary = PipelineSummary.from_results(results)
        assert summary.creates == 2
        assert summary.updates == 1
        assert summary.noops == 1
        assert summary.conflicts == 1
        assert summary.total == 5


def _result(action: UpsertAction, *, ip="10.0.0.5", diffs=None) -> Any:
    """Pipeline result mirrors what run_pipeline produces: one per host."""
    from netbox_bridge.pipeline import HostResult

    return HostResult(
        host=_host(primary_ip=ip),
        match=MatchResult(kind=MatchKind.NEW),
        upsert=UpsertResult(action=action, diffs=diffs or []),
    )


class TestRenderHuman:
    def test_emits_one_line_per_host(self):
        results = [
            _result(UpsertAction.CREATE, ip="10.0.0.1"),
            _result(UpsertAction.UPDATE, ip="10.0.0.2"),
            _result(UpsertAction.NOOP, ip="10.0.0.3"),
        ]
        out = render_human(results, summary=PipelineSummary.from_results(results))
        assert "10.0.0.1" in out
        assert "10.0.0.2" in out
        assert "10.0.0.3" in out

    def test_action_labels_visible(self):
        results = [
            _result(UpsertAction.CREATE),
            _result(UpsertAction.UPDATE),
            _result(UpsertAction.NOOP),
            _result(UpsertAction.CONFLICT),
        ]
        out = render_human(results, summary=PipelineSummary.from_results(results))
        assert "[CREATE]" in out
        assert "[UPDATE]" in out
        assert "[NOOP]" in out
        assert "[CONFLICT]" in out

    def test_summary_footer(self):
        results = [_result(UpsertAction.CREATE), _result(UpsertAction.UPDATE)]
        out = render_human(results, summary=PipelineSummary.from_results(results))
        assert "1 create" in out.lower() or "1 creates" in out.lower()
        assert "1 update" in out.lower() or "1 updates" in out.lower()

    def test_verbose_shows_field_diffs_for_updates(self):
        results = [
            _result(
                UpsertAction.UPDATE,
                diffs=[FieldDiff(field="last_seen", before="A", after="B")],
            )
        ]
        out = render_human(results, summary=PipelineSummary.from_results(results), verbose=True)
        assert "last_seen" in out
        assert "A" in out and "B" in out


class TestRenderJson:
    def test_emits_valid_json(self):
        results = [_result(UpsertAction.CREATE)]
        out = render_json(results, summary=PipelineSummary.from_results(results))
        json.loads(out)

    def test_includes_summary_counts(self):
        results = [
            _result(UpsertAction.CREATE),
            _result(UpsertAction.UPDATE),
        ]
        out = json.loads(render_json(results, summary=PipelineSummary.from_results(results)))
        assert out["summary"]["creates"] == 1
        assert out["summary"]["updates"] == 1
        assert out["summary"]["total"] == 2

    def test_includes_per_host_results(self):
        results = [_result(UpsertAction.CREATE, ip="10.0.0.1")]
        out = json.loads(render_json(results, summary=PipelineSummary.from_results(results)))
        assert isinstance(out["results"], list)
        assert out["results"][0]["host"]["primary_ip"] == "10.0.0.1"
        assert out["results"][0]["upsert"]["action"] == "create"
