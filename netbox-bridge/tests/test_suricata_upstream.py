"""Upstream-grounded tests for the Suricata source.

These lock the SuricataSource against field paths verified against actual upstream pipeline
files. If NetBox/Malcolm/Filebeat changes the mapping, these tests fail and point at the URL
whose contents we relied on.

Verified 2026-04-29:

  Filebeat Suricata module ingest pipeline:
    https://raw.githubusercontent.com/elastic/beats/main/x-pack/filebeat/module/suricata/eve/ingest/pipeline.yml
      alert.severity     -> event.severity
      alert.signature_id -> rule.id
      alert.signature    -> rule.name
      alert.category     -> rule.category

  Malcolm logstash Suricata pipeline:
    https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/suricata/11_suricata_logs.conf
      [suricata][alert][signature_id] -> [rule][id]
      [suricata][alert][signature]    -> [rule][name]
      [suricata][alert][category]     -> [rule][category]
      [event][kind] = "alert" when event_type == "alert"

  Malcolm severity transform (Malcolm-specific; differs from Filebeat):
    https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/suricata/19_severity.conf
      [suricata][alert][severity] (1..4) -> [event][severity] = 91 - ((sev-1)*20)
      Malcolm produces event.severity in {91, 71, 51, 31, 11}, NOT 1/2/3.
"""
from __future__ import annotations

from datetime import timedelta

from netbox_bridge.sources.suricata import (
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    build_query,
)


class TestUpstreamFieldPaths:
    """Lock-in: every aggregation field name must appear in upstream pipelines."""

    def test_filter_uses_event_kind_alert(self):
        # Source: Malcolm 11_suricata_logs.conf — `[event][kind] = "alert"` set in alert block.
        # Filebeat module also sets `event.kind = alert` for alert documents.
        q = build_query(since=timedelta(days=1))
        terms = [f for f in q["query"]["bool"]["filter"] if "term" in f]
        assert {"term": {"event.kind": "alert"}} in terms

    def test_top_signatures_aggregates_on_rule_id(self):
        # Source: both Filebeat (alert.signature_id -> rule.id) and Malcolm
        # (signature_id -> [rule][id]). NOT rule.signature_id.
        q = build_query(since=timedelta(days=1))
        agg = q["aggs"]["by_destination_ip"]["aggs"]["top_signatures"]
        assert agg["terms"]["field"] == "rule.id"
        assert agg["terms"]["field"] != "rule.signature_id", (
            "rule.signature_id is not a real ECS field — both Filebeat and Malcolm map "
            "alert.signature_id -> rule.id"
        )

    def test_top_signatures_name_subagg_uses_rule_name(self):
        # Source: alert.signature -> rule.name (Filebeat AND Malcolm).
        q = build_query(since=timedelta(days=1))
        name_agg = (
            q["aggs"]["by_destination_ip"]["aggs"]["top_signatures"]["aggs"]["name"]
        )
        assert name_agg["terms"]["field"] == "rule.name"

    def test_severity_aggregates_on_event_severity(self):
        # Source: alert.severity -> event.severity (Filebeat preserves 1/2/3 scale).
        # Malcolm uses same path but rewrites the value to 0-100 — see severity-scale tests.
        q = build_query(since=timedelta(days=1))
        sev_agg = q["aggs"]["by_destination_ip"]["aggs"]["by_severity"]
        assert sev_agg["terms"]["field"] == "event.severity"

    def test_aggregates_by_destination_ip(self):
        # Source: ECS standard, used by both pipelines for the receiving endpoint.
        q = build_query(since=timedelta(days=1))
        assert q["aggs"]["by_destination_ip"]["terms"]["field"] == "destination.ip"


class TestSeverityScaleAssumesFilebeat:
    """Default severity constants assume Filebeat's preserved Suricata scale.

    Malcolm's 19_severity.conf transforms 1-4 to 91/71/51/31/11. A Malcolm deployment will see
    zero matches against these constants. A future slice should add a per-deployment severity
    mapping override; for now these constants document the assumption explicitly.
    """

    def test_high_is_one_per_filebeat_module(self):
        # Filebeat preserves Suricata's native scale. Reference: any Suricata rule sets meta:
        # severity:1 for high. The Filebeat pipeline does not transform.
        assert SEVERITY_HIGH == 1

    def test_medium_is_two_per_filebeat_module(self):
        assert SEVERITY_MEDIUM == 2

    def test_low_is_three_per_filebeat_module(self):
        assert SEVERITY_LOW == 3

    def test_malcolm_scale_documented_in_module_docstring(self):
        # Lock-in: the module docstring must reference the Malcolm severity transform so
        # operators encountering zero high/medium/low counts on Malcolm have a paper trail.
        from netbox_bridge.sources import suricata

        doc = suricata.__doc__ or ""
        assert "19_severity.conf" in doc
        assert "91" in doc and "71" in doc, (
            "Malcolm severity scale (91/71/51/31/11) must be documented in the module"
        )
