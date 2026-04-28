"""Seed the local netbox-docker instance with a small amount of data so `discover` has something to find."""
from __future__ import annotations

import os
import sys


def main() -> int:
    url = os.environ.get("NETBOX_URL", "http://localhost:8000")
    token = os.environ.get("NETBOX_TOKEN")
    if not token:
        print("NETBOX_TOKEN not set. Mint a token via `make dev-token` and the NetBox UI.", file=sys.stderr)
        return 2
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
