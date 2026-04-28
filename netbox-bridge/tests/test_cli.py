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


class TestStubCommands:
    """Commands that are still stubs should fail loudly, not silently succeed."""

    def test_init_not_implemented(self):
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--url", "http://x", "--token", "t"])
        assert result.exit_code != 0

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
