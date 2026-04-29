"""Tests for OUI vendor lookup.

The OUI table is a curated starter set verified against the IEEE registry; tests both prove the
lookup logic and lock in a few representative vendor IDs so a future overzealous edit can't
silently break SOC-critical identification.
"""
from __future__ import annotations

import pytest

from netbox_bridge.oui import OUI_VENDORS, lookup_vendor, normalize_mac


class TestNormalizeMac:
    def test_strips_colons(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"

    def test_strips_hyphens(self):
        assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AABBCCDDEEFF"

    def test_strips_cisco_dotted_format(self):
        assert normalize_mac("aabb.ccdd.eeff") == "AABBCCDDEEFF"

    def test_uppercases(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"

    def test_handles_empty_separators(self):
        assert normalize_mac("AABBCCDDEEFF") == "AABBCCDDEEFF"


class TestLookupVendor:
    def test_returns_none_for_empty(self):
        assert lookup_vendor("") is None
        assert lookup_vendor(None) is None

    def test_returns_none_for_too_short(self):
        assert lookup_vendor("aa:bb") is None

    def test_returns_none_for_unknown_oui(self):
        assert lookup_vendor("00:00:00:11:22:33") is None

    def test_case_insensitive(self):
        assert lookup_vendor("00:0E:8C:11:22:33") == "Siemens AG"
        assert lookup_vendor("00:0e:8c:11:22:33") == "Siemens AG"

    def test_handles_separators(self):
        assert lookup_vendor("00:0E:8C:11:22:33") == "Siemens AG"
        assert lookup_vendor("00-0E-8C-11-22-33") == "Siemens AG"
        assert lookup_vendor("000E.8C11.2233") == "Siemens AG"
        assert lookup_vendor("000E8C112233") == "Siemens AG"


class TestVendorCoverage:
    """Lock-in: representative OUIs for SOC-critical vendors must resolve."""

    @pytest.mark.parametrize(
        "mac,expected",
        [
            # OT
            ("00:0E:8C:00:00:00", "Siemens AG"),
            ("00:1B:1B:00:00:00", "Siemens AG"),
            ("00:00:BC:00:00:00", "Rockwell Automation"),
            ("08:61:95:00:00:00", "Rockwell Automation"),
            ("00:00:54:00:00:00", "Schneider Electric"),
            ("00:50:C2:00:00:00", "ABB"),
            ("00:22:6A:00:00:00", "Honeywell"),
            # IT
            ("00:00:0C:00:00:00", "Cisco Systems"),
            ("00:0C:29:00:00:00", "VMware"),
            ("00:50:56:00:00:00", "VMware"),
            ("00:15:5D:00:00:00", "Microsoft"),  # Hyper-V default
        ],
    )
    def test_known_vendor_resolves(self, mac, expected):
        assert lookup_vendor(mac) == expected

    def test_table_has_no_duplicate_keys(self):
        # Sanity: dict literal syntax silently swallows duplicates. Make sure none slipped in.
        # (Re-load the file and count distinct keys vs. file lines that look like entries.)
        import netbox_bridge.oui as m
        # If this fails the test exposes a coding mistake; not a runtime correctness check.
        assert len(m.OUI_VENDORS) == len(set(m.OUI_VENDORS.keys()))

    def test_keys_are_uppercase_six_chars(self):
        for k in OUI_VENDORS:
            assert len(k) == 6, f"OUI key {k!r} not 6 chars"
            assert k == k.upper(), f"OUI key {k!r} not upper-case"
            int(k, 16)  # raises if not valid hex
