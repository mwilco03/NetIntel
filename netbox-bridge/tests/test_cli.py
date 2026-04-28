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
