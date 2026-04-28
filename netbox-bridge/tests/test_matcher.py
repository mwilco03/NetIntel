import pytest

from netbox_bridge.matcher import match_host


def test_match_host_not_implemented():
    with pytest.raises(NotImplementedError):
        match_host(None, None)  # type: ignore[arg-type]
