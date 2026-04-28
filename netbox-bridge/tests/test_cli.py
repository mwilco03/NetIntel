"""Tests for CLI wiring.

These verify the click command dispatches correctly. The NetBoxClient is patched out so no
network is needed.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from netbox_bridge.cli import main
from netbox_bridge.discover import DiscoverReport


class TestDiscoverCommand:
    def _fake_report(self, **overrides) -> DiscoverReport:
        defaults = dict(
            netbox_version="4.1.0",
            sites=["hq"],
            tenants=["acme"],
            device_roles=["server"],
            platforms=["linux"],
            existing_device_cfs=[],
            missing_device_cfs=["last_seen"],
            existing_tags=[],
            missing_tags=["source:netintel-bridge"],
        )
        defaults.update(overrides)
        return DiscoverReport(**defaults)

    def test_human_output_by_default(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient") as MockClient, patch(
            "netbox_bridge.cli.run_discover", return_value=self._fake_report()
        ):
            result = runner.invoke(main, ["discover", "--url", "http://x", "--token", "t"])
        assert result.exit_code == 0
        assert "NetBox version: 4.1.0" in result.output
        assert "NOT ready" in result.output
        MockClient.assert_called_once()

    def test_json_output_with_flag(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient"), patch(
            "netbox_bridge.cli.run_discover", return_value=self._fake_report()
        ):
            result = runner.invoke(
                main, ["discover", "--url", "http://x", "--token", "t", "--json"]
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["netbox_version"] == "4.1.0"
        assert parsed["ready"] is False

    def test_token_picked_up_from_env(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient") as MockClient, patch(
            "netbox_bridge.cli.run_discover", return_value=self._fake_report()
        ):
            result = runner.invoke(
                main, ["discover", "--url", "http://x"], env={"NETBOX_TOKEN": "from-env"}
            )
        assert result.exit_code == 0
        # second positional arg to NetBoxClient is the AuthAdapter
        adapter = MockClient.call_args.args[1]
        assert adapter.token == "from-env"

    def test_verify_tls_flag_propagates(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient") as MockClient, patch(
            "netbox_bridge.cli.run_discover", return_value=self._fake_report()
        ):
            runner.invoke(
                main,
                ["discover", "--url", "http://x", "--token", "t", "--no-verify-tls"],
            )
        assert MockClient.call_args.kwargs["verify_tls"] is False

    def test_exits_nonzero_when_token_missing_and_no_env(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient"), patch(
            "netbox_bridge.cli.run_discover"
        ):
            result = runner.invoke(
                main, ["discover", "--url", "http://x"], env={"NETBOX_TOKEN": ""}
            )
        assert result.exit_code != 0
        assert "token" in result.output.lower()


class TestInitCommand:
    def _fake_plan(self, **overrides):
        from netbox_bridge.init import InitPlan

        defaults = dict(
            custom_fields_to_create=[
                {"name": "last_seen", "type": "datetime", "object_types": ["dcim.device"]}
            ],
            tags_to_create=[{"name": "source:nmap", "slug": "source-nmap", "color": "43a047"}],
            applied=False,
        )
        defaults.update(overrides)
        return InitPlan(**defaults)

    def test_dry_run_by_default(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient"), patch(
            "netbox_bridge.cli.run_init"
        ) as mock_run:
            mock_run.return_value = self._fake_plan(applied=False)
            result = runner.invoke(main, ["init", "--url", "http://x", "--token", "t"])
        assert result.exit_code == 0
        assert mock_run.call_args.kwargs["apply"] is False
        assert "Would create" in result.output

    def test_apply_flag_passes_apply_true(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.NetBoxClient"), patch(
            "netbox_bridge.cli.run_init"
        ) as mock_run:
            mock_run.return_value = self._fake_plan(applied=True)
            result = runner.invoke(
                main, ["init", "--url", "http://x", "--token", "t", "--apply"]
            )
        assert result.exit_code == 0
        assert mock_run.call_args.kwargs["apply"] is True
        assert "Created" in result.output

    def test_exits_nonzero_when_token_missing(self):
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--url", "http://x"], env={"NETBOX_TOKEN": ""})
        assert result.exit_code != 0


class TestFetchCommand:
    def _fake_hosts(self):
        from datetime import datetime, timezone
        from netbox_bridge.model import Host, Service

        return [
            Host(
                primary_ip="10.0.0.5",
                services=[Service(port=22, protocol="tcp", name="ssh")],
                source="malcolm",
                observed_at=datetime(2026, 4, 25, 10, 0, tzinfo=timezone.utc),
            )
        ]

    def test_malcolm_source_emits_host_json(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.MalcolmSource"
        ) as MockSource:
            MockSource.return_value.fetch_hosts.return_value = self._fake_hosts()
            result = runner.invoke(
                main,
                [
                    "fetch",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://malcolm:9200",
                    "--username",
                    "admin",
                    "--password",
                    "p",
                    "--since",
                    "7d",
                ],
            )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert parsed[0]["primary_ip"] == "10.0.0.5"
        assert parsed[0]["source"] == "malcolm"

    def test_since_passed_through_as_timedelta(self):
        from datetime import timedelta

        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.MalcolmSource"
        ) as MockSource:
            MockSource.return_value.fetch_hosts.return_value = []
            runner.invoke(
                main,
                [
                    "fetch",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--since",
                    "2h",
                ],
            )
        kwargs = MockSource.return_value.fetch_hosts.call_args.kwargs
        assert kwargs["since"] == timedelta(hours=2)

    def test_password_picked_up_from_env(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient") as MockClient, patch(
            "netbox_bridge.cli.MalcolmSource"
        ) as MockSource:
            MockSource.return_value.fetch_hosts.return_value = []
            runner.invoke(
                main,
                [
                    "fetch",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--since",
                    "1d",
                ],
                env={"OPENSEARCH_PASSWORD": "from-env"},
            )
        kwargs = MockClient.call_args.kwargs
        assert kwargs["password"] == "from-env"

    def test_index_pattern_override(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.MalcolmSource"
        ) as MockSource:
            MockSource.return_value.fetch_hosts.return_value = []
            runner.invoke(
                main,
                [
                    "fetch",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--since",
                    "1d",
                    "--index-pattern",
                    "custom-*",
                ],
            )
        assert MockSource.call_args.kwargs["index_pattern"] == "custom-*"

    def test_invalid_since_fails(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "fetch",
                "--source",
                "malcolm",
                "--url",
                "https://m:9200",
                "--username",
                "u",
                "--password",
                "p",
                "--since",
                "garbage",
            ],
        )
        assert result.exit_code != 0

    def test_security_onion_source_routed_correctly(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.SecurityOnionSource"
        ) as MockSource:
            MockSource.return_value.fetch_hosts.return_value = []
            result = runner.invoke(
                main,
                [
                    "fetch",
                    "--source",
                    "security-onion",
                    "--url",
                    "https://so:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--since",
                    "1d",
                ],
            )
        assert result.exit_code == 0
        MockSource.assert_called_once()

    def test_invalid_source_fails(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "fetch",
                "--source",
                "snake-oil",
                "--url",
                "https://m:9200",
                "--username",
                "u",
                "--password",
                "p",
                "--since",
                "1d",
            ],
        )
        assert result.exit_code != 0


class TestProbeCommand:
    def _fake_report(self, **overrides):
        from netbox_bridge.probe import REQUIRED_FIELDS, ProbeReport

        defaults = dict(
            cluster_name="malcolm",
            cluster_status="green",
            version="2.11.0",
            indices=[{"index": "arkime-241124", "docs.count": "100", "store.size": "1gb"}],
            fields_present=list(REQUIRED_FIELDS),
            fields_missing=[],
            datasets={"conn": 100},
        )
        defaults.update(overrides)
        return ProbeReport(**defaults)

    def test_uses_malcolm_default_index_pattern(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ) as mock_probe:
            runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                ],
            )
        assert mock_probe.call_args.kwargs["index_pattern"] == "arkime_sessions3-*"

    def test_uses_security_onion_default_index_pattern(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ) as mock_probe:
            runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "security-onion",
                    "--url",
                    "https://so:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                ],
            )
        assert mock_probe.call_args.kwargs["index_pattern"] == "logs-zeek-so"

    def test_index_pattern_override(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ) as mock_probe:
            runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--index-pattern",
                    "custom-*",
                ],
            )
        assert mock_probe.call_args.kwargs["index_pattern"] == "custom-*"

    def test_since_passed_through(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ) as mock_probe:
            runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--since",
                    "7d",
                ],
            )
        assert mock_probe.call_args.kwargs["since"] == "now-7d"

    def test_human_output_includes_status(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ):
            result = runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                ],
            )
        assert result.exit_code == 0
        assert "READY" in result.output

    def test_json_output(self):
        runner = CliRunner()
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=self._fake_report()
        ):
            result = runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                    "--json",
                ],
            )
        parsed = json.loads(result.output)
        assert parsed["ready"] is True

    def test_exits_nonzero_when_not_ready(self):
        runner = CliRunner()
        not_ready = self._fake_report(indices=[], fields_missing=["destination.ip"])
        with patch("netbox_bridge.cli.OpenSearchClient"), patch(
            "netbox_bridge.cli.run_probe", return_value=not_ready
        ):
            result = runner.invoke(
                main,
                [
                    "probe",
                    "--source",
                    "malcolm",
                    "--url",
                    "https://m:9200",
                    "--username",
                    "u",
                    "--password",
                    "p",
                ],
            )
        # NOT READY → exit non-zero so scripts can short-circuit
        assert result.exit_code != 0


class TestStubCommands:
    """Commands that are still stubs should fail loudly, not silently succeed."""

    def test_plan_not_implemented(self, tmp_path):
        scan = tmp_path / "scan.xml"
        scan.write_text("<nmaprun/>")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["plan", "--url", "http://x", "--token", "t", "--input", str(scan)],
        )
        assert result.exit_code != 0

    def test_ingest_not_implemented(self, tmp_path):
        scan = tmp_path / "scan.xml"
        scan.write_text("<nmaprun/>")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ingest", "--url", "http://x", "--token", "t", "--input", str(scan)],
        )
        assert result.exit_code != 0
