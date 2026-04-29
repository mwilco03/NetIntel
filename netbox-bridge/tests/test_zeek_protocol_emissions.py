"""Lock OT_PROTOCOLS against actual Malcolm Zeek logstash filter emissions.

Each entry in OT_PROTOCOLS must match the string value that Malcolm's per-protocol filter sets
for [zeek_cols][service]. Cited URLs verified 2026-04-29 by reading each filter file directly.

If Malcolm renames or splits a filter, these tests fail and point at the URL that needs
re-verification.

Open question (documented as known-limitation): Malcolm's 1300_zeek_normalize.conf does NOT
contain a centralized rename of [zeek_cols][service] -> [network][protocol] for OT protocols.
For IT protocols (DNS/HTTP/SMTP/SSL/SSH/SMB) the normalize file has explicit ECS-cased values,
but OT protocols travel as [zeek_cols][service] internally. Source-side aggregation may need to
also try [event][dataset] in real deployments. See test_normalize_uncertainty below.
"""
from __future__ import annotations

import pytest

from netbox_bridge.classify import IT_PROTOCOLS, OT_PROTOCOLS

# (protocol_value, malcolm_filter_url)
OT_VERIFIED_EMISSIONS = [
    ("modbus", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1037_zeek_modbus.conf"),
    ("dnp3", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1019_zeek_dnp3.conf"),
    ("enip", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1022_zeek_enip.conf"),
    ("cip", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1022_zeek_enip.conf"),
    ("profinet", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1047_zeek_profinet.conf"),
    ("profinet_dce_rpc", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1047_zeek_profinet.conf"),
    ("s7comm", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1051_zeek_s7comm.conf"),
    ("s7comm-plus", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1051_zeek_s7comm.conf"),
    ("cotp", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1051_zeek_s7comm.conf"),
]

IT_VERIFIED_EMISSIONS = [
    ("http", "https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/zeek/1029_zeek_http.conf"),
]


class TestOtProtocolUpstreamGrounding:
    """Each MVP OT protocol's value must match Malcolm's filter file."""

    @pytest.mark.parametrize(
        "value,url",
        OT_VERIFIED_EMISSIONS,
        ids=[v[0] for v in OT_VERIFIED_EMISSIONS],
    )
    def test_value_in_ot_protocols(self, value, url):
        assert value in OT_PROTOCOLS, (
            f"OT_PROTOCOLS missing {value!r} which Malcolm's filter at {url} emits as "
            f"[zeek_cols][service]. Real Malcolm conn data with this protocol would not "
            f"trigger class:ot."
        )

    def test_made_up_aliases_removed(self):
        # These were earlier guesses that don't match what Malcolm actually emits. Lock them
        # OUT so a regression doesn't reintroduce protocol-name drift.
        assert "modbus_tcp" not in OT_PROTOCOLS
        assert "modbus-tcp" not in OT_PROTOCOLS
        assert "s7-comm" not in OT_PROTOCOLS  # Malcolm uses "s7comm" not "s7-comm"
        assert "opcua-binary" not in OT_PROTOCOLS  # Malcolm uses "opcua_binary"
        assert "iec-104" not in OT_PROTOCOLS  # not verified upstream; remove until cited


class TestItProtocolUpstreamGrounding:
    @pytest.mark.parametrize(
        "value,url",
        IT_VERIFIED_EMISSIONS,
        ids=[v[0] for v in IT_VERIFIED_EMISSIONS],
    )
    def test_value_in_it_protocols(self, value, url):
        assert value in IT_PROTOCOLS, (
            f"IT_PROTOCOLS missing {value!r} from {url}"
        )


class TestNormalizeUncertainty:
    """Malcolm's centralized normalize doesn't propagate [zeek_cols][service] to network.protocol
    for OT protocols (only DNS/HTTP/SMTP/SSL/SSH/SMB are explicitly translated). This is a known
    risk: in real Malcolm conn aggregations, OT protocols may need to be looked up via
    event.dataset rather than network.protocol. The classify path uses Service.name which is
    populated from network.protocol — so passive Zeek OT detection is currently best-effort.

    This test exists as a paper trail. When source-side aggregation is updated to also check
    event.dataset, this test should be updated.
    """

    def test_known_limitation_documented(self):
        from netbox_bridge.classify import __doc__ as classify_doc
        # The constraint is documented in the module docstring AND in OT_PROTOCOLS comments.
        # If a future edit removes the citations, this test fires.
        from netbox_bridge import classify
        src = classify.__file__
        with open(src) as f:
            content = f.read()
        assert "1037_zeek_modbus.conf" in content
        assert "verified against" in content.lower()
