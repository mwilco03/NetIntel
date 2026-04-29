"""Tests for IT/OT classification."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netbox_bridge.classify import (
    ALL_CLASS_TAGS,
    CLASS_IT,
    CLASS_MIXED,
    CLASS_OT,
    IT_PROTOCOLS,
    OT_PROTOCOLS,
    OT_VENDORS,
    classify_tags,
)
from netbox_bridge.model import Host, Service


def _host(*, services=(), source="nmap"):
    return Host(
        primary_ip="10.0.0.5",
        services=list(services),
        source=source,  # type: ignore[arg-type]
        observed_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
    )


def _svc(port: int, name: str | None, protocol: str = "tcp") -> Service:
    return Service(port=port, protocol=protocol, name=name)  # type: ignore[arg-type]


class TestClassByProtocol:
    def test_modbus_only_classifies_ot(self):
        h = _host(services=(_svc(502, "modbus"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_dnp3_only_classifies_ot(self):
        h = _host(services=(_svc(20000, "dnp3"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_enip_only_classifies_ot(self):
        h = _host(services=(_svc(44818, "enip"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_profinet_only_classifies_ot(self):
        h = _host(services=(_svc(34962, "profinet"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_s7comm_only_classifies_ot(self):
        h = _host(services=(_svc(102, "s7comm"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_bacnet_only_classifies_ot(self):
        h = _host(services=(_svc(47808, "bacnet", protocol="udp"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_opcua_classifies_ot(self):
        h = _host(services=(_svc(4840, "opcua-binary"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_http_only_classifies_it(self):
        h = _host(services=(_svc(80, "http"),))
        assert classify_tags(h, vendor=None) == {CLASS_IT}

    def test_ssh_only_classifies_it(self):
        h = _host(services=(_svc(22, "ssh"),))
        assert classify_tags(h, vendor=None) == {CLASS_IT}

    def test_smtp_only_classifies_it(self):
        h = _host(services=(_svc(25, "smtp"),))
        assert classify_tags(h, vendor=None) == {CLASS_IT}

    def test_https_only_classifies_it(self):
        h = _host(services=(_svc(443, "https"),))
        assert classify_tags(h, vendor=None) == {CLASS_IT}


class TestClassByVendor:
    def test_siemens_vendor_alone_classifies_ot(self):
        h = _host()
        assert classify_tags(h, vendor="Siemens AG") == {CLASS_OT}

    def test_rockwell_vendor_alone_classifies_ot(self):
        h = _host()
        assert classify_tags(h, vendor="Rockwell Automation") == {CLASS_OT}

    def test_schneider_vendor_alone_classifies_ot(self):
        h = _host()
        assert classify_tags(h, vendor="Schneider Electric") == {CLASS_OT}

    def test_unknown_vendor_yields_no_class(self):
        h = _host()
        assert classify_tags(h, vendor="ACME Widgets") == set()

    def test_vmware_vendor_yields_no_class(self):
        # Conservative: virtualization vendors are not classified by vendor alone.
        h = _host()
        assert classify_tags(h, vendor="VMware") == set()


class TestClassMixed:
    def test_ot_protocol_plus_it_protocol_is_mixed(self):
        h = _host(services=(_svc(502, "modbus"), _svc(80, "http")))
        assert classify_tags(h, vendor=None) == {CLASS_MIXED}

    def test_ot_vendor_plus_it_protocol_is_mixed(self):
        h = _host(services=(_svc(80, "http"),))
        assert classify_tags(h, vendor="Siemens AG") == {CLASS_MIXED}

    def test_ot_vendor_plus_ot_protocol_is_ot(self):
        h = _host(services=(_svc(502, "modbus"),))
        assert classify_tags(h, vendor="Siemens AG") == {CLASS_OT}


class TestClassNoSignal:
    def test_no_services_no_vendor_returns_empty(self):
        h = _host()
        assert classify_tags(h, vendor=None) == set()

    def test_unknown_protocol_returns_empty(self):
        h = _host(services=(_svc(9999, "unknown-proto"),))
        assert classify_tags(h, vendor=None) == set()

    def test_unnamed_service_returns_empty(self):
        h = _host(services=(_svc(9999, None),))
        assert classify_tags(h, vendor=None) == set()


class TestClassCaseInsensitive:
    def test_protocol_match_is_case_insensitive(self):
        h = _host(services=(_svc(502, "MODBUS"),))
        assert classify_tags(h, vendor=None) == {CLASS_OT}

    def test_protocol_match_handles_mixed_case(self):
        h = _host(services=(_svc(80, "Http"),))
        assert classify_tags(h, vendor=None) == {CLASS_IT}


class TestClassAtMostOne:
    """Mutual exclusion: classify_tags returns at most one class:* tag."""

    def test_returns_at_most_one_class_tag(self):
        # Try every reasonable combination
        cases = [
            _host(services=(_svc(502, "modbus"),)),
            _host(services=(_svc(80, "http"),)),
            _host(services=(_svc(502, "modbus"), _svc(80, "http"))),
            _host(),
        ]
        vendors = [None, "Siemens AG", "VMware", "ACME"]
        for h in cases:
            for v in vendors:
                tags = classify_tags(h, vendor=v)
                assert tags <= ALL_CLASS_TAGS
                assert len(tags) <= 1


class TestProtocolTableCoverage:
    """Lock-in: the user's MVP OT protocols must be present."""

    @pytest.mark.parametrize(
        "proto",
        ["modbus", "dnp3", "enip", "cip", "profinet", "s7comm"],
    )
    def test_mvp_ot_protocol_in_table(self, proto):
        assert proto in OT_PROTOCOLS

    @pytest.mark.parametrize(
        "proto",
        ["http", "https", "ssh", "smtp", "ldap", "kerberos", "smb"],
    )
    def test_common_it_protocol_in_table(self, proto):
        assert proto in IT_PROTOCOLS

    def test_protocol_tables_dont_overlap(self):
        # A protocol can't be both OT and IT — would force class:mixed for everyone.
        assert OT_PROTOCOLS.isdisjoint(IT_PROTOCOLS)


class TestVendorTable:
    @pytest.mark.parametrize(
        "vendor",
        ["Siemens AG", "Rockwell Automation", "Schneider Electric", "ABB", "Honeywell"],
    )
    def test_mvp_ot_vendor_in_table(self, vendor):
        assert vendor in OT_VENDORS
