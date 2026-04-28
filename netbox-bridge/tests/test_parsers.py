from pathlib import Path

import pytest

from netbox_bridge.parsers.nessus import parse_nessus
from netbox_bridge.parsers.nmap import parse_nmap


def test_parse_nmap_not_implemented():
    with pytest.raises(NotImplementedError):
        parse_nmap(Path("/tmp/nope.xml"))


def test_parse_nessus_not_implemented():
    with pytest.raises(NotImplementedError):
        parse_nessus(Path("/tmp/nope.nessus"))
