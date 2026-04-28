from __future__ import annotations

from pathlib import Path

from ..model import Host


def parse_nmap(path: Path) -> list[Host]:
    """Parse an Nmap XML file into normalized Host records."""
    raise NotImplementedError
