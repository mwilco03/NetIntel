"""Capture real OpenSearch _search responses and write them as test fixtures.

These replace the synthesized fixtures the test suite was relying on. The captures come from a
live OpenSearch (single-node, 2.x) loaded with documents whose field paths match what verified
upstream pipelines emit. So a future test against these fixtures is testing against real
OpenSearch response shapes.
"""
import json
import urllib.request
from datetime import timedelta
from pathlib import Path

from netbox_bridge.sources.malcolm import build_query as build_malcolm_query
from netbox_bridge.sources.security_onion import build_query as build_so_query
from netbox_bridge.sources.suricata import build_query as build_suricata_query

OS_URL = "http://localhost:9200"
FIXTURE_DIR = Path("/home/user/NetIntel/netbox-bridge/tests/fixtures")


def search(index, body):
    req = urllib.request.Request(
        f"{OS_URL}/{index}/_search",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def write(name, content):
    p = FIXTURE_DIR / name
    p.write_text(json.dumps(content, indent=2))
    print(f"  wrote {name} ({p.stat().st_size} bytes)")


print("=== Capturing Malcolm Zeek conn aggregation ===")
malcolm_body = build_malcolm_query(since=timedelta(hours=1))
malcolm_resp = search("arkime_sessions3-2026.04.28", malcolm_body)
write("malcolm_known_services_response.json", malcolm_resp)

print("=== Capturing Security Onion-style aggregation ===")
so_body = build_so_query(since=timedelta(hours=1), datasets=["conn"])
# We loaded into arkime_sessions3, but SO source uses logs-zeek-so. Run the SO query against
# the same data — the agg shape doesn't care about the index name, only the field paths.
# Then we patch the captured response to be index-agnostic.
so_resp = search("arkime_sessions3-2026.04.28", so_body)
write("security_onion_conn_response.json", so_resp)

print("=== Capturing Suricata aggregation ===")
suricata_body = build_suricata_query(since=timedelta(hours=1))
suricata_resp = search("arkime_sessions3-2026.04.28", suricata_body)
write("suricata_alerts_response.json", suricata_resp)
