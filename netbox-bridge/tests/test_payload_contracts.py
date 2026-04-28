"""Contract tests: every payload the bridge sends to NetBox must use only fields the upstream
serializer accepts. Lock-in for the API shape we depend on, derived from netbox-community/netbox
source. Update these sets when NetBox releases change something.

References (cite when changing):
  - dcim devices       https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/dcim/api/serializers_/devices.py
  - extras customfields https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/api/serializers_/customfields.py
  - extras tags        https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/api/serializers_/tags.py
  - ipam ip            https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/ipam/api/serializers_/ip.py
  - ipam services      https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/ipam/api/serializers_/services.py
  - dcim 4.2 MAC notes https://netboxlabs.com/docs/netbox/release-notes/version-4.2/
"""
from __future__ import annotations

import pytest

# Field sets accepted by NetBox 4.x serializers (allowlists).
# Required = the subset of these that POST cannot omit. We only validate the *closure* — i.e. our
# payloads contain no surprise keys. Required-field checks live in higher-level tests.

DEVICE_CREATE_FIELDS: set[str] = {
    "name", "device_type", "role", "site", "status",
    "platform", "tenant", "rack", "location", "position", "face",
    "primary_ip4", "primary_ip6",
    "tags", "custom_fields", "description", "comments",
    "serial", "asset_tag",
}

INTERFACE_CREATE_FIELDS: set[str] = {
    "device", "name", "type",
    "enabled", "description",
    "tags", "custom_fields",
    # In NetBox 4.2+ the mac_address field on Interface is READ-ONLY.
    # Use the separate MACAddress endpoint, then PATCH Interface.primary_mac_address.
    "primary_mac_address",
}

MAC_ADDRESS_CREATE_FIELDS: set[str] = {
    "mac_address",
    "assigned_object_type",  # "dcim.interface" / "virtualization.vminterface"
    "assigned_object_id",
    "description",
    "tags", "custom_fields",
}

IP_ADDRESS_CREATE_FIELDS: set[str] = {
    "address",
    "assigned_object_type",  # "dcim.interface"
    "assigned_object_id",
    "status", "role",
    "vrf", "tenant", "nat_inside",
    "dns_name", "description", "comments",
    "tags", "custom_fields",
}

SERVICE_CREATE_FIELDS: set[str] = {
    # Service was generalized — NO 'device' field anymore.
    "parent_object_type",  # "dcim.device" / "virtualization.virtualmachine"
    "parent_object_id",
    "name", "ports", "protocol",
    "ipaddresses",
    "description", "comments",
    "tags", "custom_fields",
}

CUSTOM_FIELD_CREATE_FIELDS: set[str] = {
    "name", "label", "type",
    "object_types",
    "description",
    "required", "default", "weight",
    "filter_logic",
    "ui_visible", "ui_editable",
    "search_weight", "is_cloneable",
    "validation_minimum", "validation_maximum", "validation_regex",
    "choice_set", "related_object_type", "group_name",
    "unique",
}

TAG_CREATE_FIELDS: set[str] = {
    "name", "slug", "color", "description",
    "object_types",
}


def assert_payload_in_schema(payload: dict, allowed: set[str], *, ctx: str) -> None:
    surprise = set(payload) - allowed
    assert not surprise, (
        f"{ctx}: payload contains keys NetBox does not accept: {sorted(surprise)}. "
        f"If NetBox changed, update the allowlist in test_payload_contracts.py with a citation."
    )


class TestInitCustomFieldSpecsContractValid:
    """Contract: init.cf_spec(...) must produce payloads NetBox's CustomField serializer accepts."""

    def test_each_required_cf_spec_uses_only_allowed_fields(self):
        from netbox_bridge.discover import REQUIRED_DEVICE_CFS
        from netbox_bridge.init import cf_spec

        for name in REQUIRED_DEVICE_CFS:
            spec = cf_spec(name)
            assert_payload_in_schema(spec, CUSTOM_FIELD_CREATE_FIELDS, ctx=f"cf_spec({name!r})")


class TestInitTagSpecsContractValid:
    """Contract: init.tag_spec(...) must produce payloads NetBox's Tag serializer accepts."""

    def test_each_required_tag_spec_uses_only_allowed_fields(self):
        from netbox_bridge.discover import REQUIRED_TAGS
        from netbox_bridge.init import tag_spec

        for name in REQUIRED_TAGS:
            spec = tag_spec(name)
            assert_payload_in_schema(spec, TAG_CREATE_FIELDS, ctx=f"tag_spec({name!r})")
