"""Lock cf_spec types against NetBox 4.x CustomFieldTypeChoices.

Source verified 2026-04-29:
  https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/choices.py
  class CustomFieldTypeChoices: TYPE_TEXT = 'text', TYPE_INTEGER = 'integer',
  TYPE_DATETIME = 'datetime', TYPE_JSON = 'json', etc.

If a future cf_spec uses a non-existent type, NetBox returns 400. These tests catch that at
test time with the URL to re-verify.
"""
from __future__ import annotations

import pytest

from netbox_bridge.discover import REQUIRED_DEVICE_CFS
from netbox_bridge.init import cf_spec

# Verbatim from netbox-community/netbox/main/netbox/extras/choices.py CustomFieldTypeChoices
# (only listing the values; class also defines (display_name, _color) tuples).
NETBOX_CUSTOM_FIELD_TYPES: set[str] = {
    "text",
    "longtext",
    "integer",
    "decimal",
    "boolean",
    "date",
    "datetime",
    "url",
    "json",
    "select",
    "multiselect",
    "object",
    "multiobject",
}


class TestCustomFieldTypeIsValid:
    """Every CF spec the bridge sends must use a NetBox-recognized type."""

    @pytest.mark.parametrize("name", REQUIRED_DEVICE_CFS)
    def test_required_cf_spec_type_is_valid(self, name):
        spec = cf_spec(name)
        assert spec["type"] in NETBOX_CUSTOM_FIELD_TYPES, (
            f"cf_spec({name!r}) emits type={spec['type']!r} which is NOT in NetBox's "
            f"CustomFieldTypeChoices. Re-verify against "
            f"https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/choices.py"
        )


class TestSpecificTypeAssignments:
    """Lock each CF to its expected type so accidental edits are caught."""

    def test_last_seen_is_datetime(self):
        assert cf_spec("last_seen")["type"] == "datetime"

    def test_first_seen_is_datetime(self):
        assert cf_spec("first_seen")["type"] == "datetime"

    def test_last_scan_id_is_text(self):
        # UUID stored as plain string; "text" max length is sufficient.
        assert cf_spec("last_scan_id")["type"] == "text"

    def test_source_is_text(self):
        # Comma-separated provenance list. Could be a multiselect long-term but text is fine.
        assert cf_spec("source")["type"] == "text"

    def test_oui_vendor_is_text(self):
        assert cf_spec("oui_vendor")["type"] == "text"

    def test_related_macs_is_json(self):
        # List of {mac, observed_at, scan_id} — must be json type.
        assert cf_spec("related_macs")["type"] == "json"

    def test_suricata_top_signatures_is_json(self):
        assert cf_spec("suricata_top_signatures")["type"] == "json"

    def test_suricata_alert_counts_are_integer(self):
        for name in ("suricata_alerts_total", "suricata_alerts_high",
                     "suricata_alerts_medium", "suricata_alerts_low"):
            assert cf_spec(name)["type"] == "integer"
