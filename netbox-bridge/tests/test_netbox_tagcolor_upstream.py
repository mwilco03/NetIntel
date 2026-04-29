"""Lock TAG_COLORS against NetBox's ColorValidator regex.

Source verified 2026-04-29:
  https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/utilities/validators.py
  ColorValidator regex: r'^[0-9a-f]{6}$'

  https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/utilities/fields.py
  class ColorField(models.CharField):
      default_validators = [ColorValidator]

  https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/models/tags.py
  class Tag: color = ColorField(...)

So a Tag color sent via the API must match ^[0-9a-f]{6}$ — exactly six lowercase hex chars,
no leading '#', no shorthand. Anything else returns 400 from NetBox.
"""
from __future__ import annotations

import re

import pytest

from netbox_bridge.discover import REQUIRED_TAGS
from netbox_bridge.init import tag_spec

NETBOX_COLOR_REGEX = re.compile(r"^[0-9a-f]{6}$")


class TestTagColorMatchesUpstreamRegex:
    @pytest.mark.parametrize("name", REQUIRED_TAGS)
    def test_color_passes_netbox_validator(self, name):
        spec = tag_spec(name)
        color = spec["color"]
        assert NETBOX_COLOR_REGEX.match(color), (
            f"tag_spec({name!r})['color'] = {color!r} does not match NetBox's "
            f"ColorValidator regex r'^[0-9a-f]{{6}}$'. NetBox would reject this on POST. "
            f"Re-verify against utilities/validators.py upstream."
        )


class TestUpperCaseHexRejected:
    """ColorValidator uses [0-9a-f] (lowercase only). Catch any future drift to upper-case."""

    @pytest.mark.parametrize("name", REQUIRED_TAGS)
    def test_color_is_lowercase(self, name):
        color = tag_spec(name)["color"]
        assert color == color.lower(), (
            f"{name!r} color {color!r} contains upper-case; NetBox regex is [0-9a-f]"
        )


class TestNoLeadingHash:
    """ColorValidator pattern starts with ^[0-9a-f] — NOT ^#. Strip if any sneak in."""

    @pytest.mark.parametrize("name", REQUIRED_TAGS)
    def test_color_has_no_leading_hash(self, name):
        color = tag_spec(name)["color"]
        assert not color.startswith("#"), (
            f"{name!r} color {color!r} has a leading '#'. NetBox's ColorValidator "
            f"r'^[0-9a-f]{{6}}$' rejects it."
        )


class TestNoShorthand:
    @pytest.mark.parametrize("name", REQUIRED_TAGS)
    def test_color_is_exactly_six_chars(self, name):
        color = tag_spec(name)["color"]
        assert len(color) == 6, (
            f"{name!r} color {color!r} is {len(color)} chars; NetBox requires exactly 6."
        )
