from __future__ import annotations

from pathlib import Path

from ..model import Host


def parse_nessus(path: Path) -> list[Host]:
    """Parse a Nessus .nessus file into normalized Host records."""
    raise NotImplementedError
