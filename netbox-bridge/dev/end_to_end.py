"""End-to-end smoke test against real NetBox 4.5.

Runs the bridge's NetBoxClient + match_host + upsert_host against a live netbox-docker.
Captures the real Device/Interface/MACAddress/IPAddress/Service responses and verifies the
bridge's payload + matching logic actually work. This is the test that's been missing.
"""
from datetime import datetime, timezone
import json
import os
import sys

from netbox_bridge.client import NetBoxClient, TokenAdapter
from netbox_bridge.matcher import match_host
from netbox_bridge.model import Host, Interface, Service
from netbox_bridge.upsert import (
    SOURCE_TAG, UpsertAction, Strategy, UpsertDefaults, upsert_host,
)

NB_URL = os.environ["NB_URL"]
NB_TOKEN = os.environ["NB_TOKEN"]

client = NetBoxClient(NB_URL, TokenAdapter(NB_TOKEN))
defaults = UpsertDefaults(site_id=1, role_id=1, device_type_id=1)
SCAN_ID = "test-scan-001"

print("=== STEP 1: CREATE a Siemens-MAC Host with modbus + http (mixed OT/IT) ===")
host = Host(
    primary_ip="10.0.0.5",
    fqdn="plc-01.lab",
    interfaces=[Interface(mac="00:0e:8c:11:22:33")],   # Siemens AG OUI
    services=[
        Service(port=502, protocol="tcp", name="modbus"),
        Service(port=80, protocol="tcp", name="http"),
    ],
    source="malcolm",
    observed_at=datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc),
)
m = match_host(host, client)
print(f"  match_host: kind={m.kind.value} device_id={m.netbox_device_id}")
r = upsert_host(host, m, client, scan_id=SCAN_ID, dry_run=False, strategy=Strategy.MERGE, defaults=defaults)
print(f"  upsert_host: action={r.action.value} device_id={r.netbox_device_id}")
assert r.action == UpsertAction.CREATE, f"Expected CREATE, got {r.action.value}"

print()
print("=== STEP 2: Verify NetBox state ===")
device = client.api.dcim.devices.get(r.netbox_device_id)
print(f"  Device: id={device.id} name={device.name}")
print(f"    tags: {[t.name for t in device.tags]}")
print(f"    custom_fields: {json.dumps(device.custom_fields, default=str, indent=4)}")

iface = list(client.api.dcim.interfaces.filter(device_id=device.id))[0]
print(f"  Interface: id={iface.id} name={iface.name}")
mac_obj = list(client.api.dcim.mac_addresses.filter(interface_id=iface.id))[0]
print(f"  MACAddress: {mac_obj.mac_address} (id={mac_obj.id})")

svcs = list(client.api.ipam.services.filter(device_id=device.id))
print(f"  Services ({len(svcs)}):")
for s in svcs:
    print(f"    {s.ports[0]}/{s.protocol.value} name={s.name}")

print()
print("=== STEP 3: Re-run same scan — must be NOOP (idempotency) ===")
m2 = match_host(host, client)
print(f"  match_host: kind={m2.kind.value} device_id={m2.netbox_device_id}")
r2 = upsert_host(host, m2, client, scan_id=SCAN_ID, dry_run=False, strategy=Strategy.MERGE, defaults=defaults)
print(f"  upsert_host: action={r2.action.value} (expect NOOP)")
assert r2.action == UpsertAction.NOOP, f"NOT IDEMPOTENT: got {r2.action.value}"
assert m2.kind.value == "by_mac", f"Expected match by_mac on rescan, got {m2.kind.value}"

print()
print("=== STEP 4: Same host with NEW MAC (Rockwell) — must trigger alert:mac-change ===")
host2 = host.model_copy(update={
    "interfaces": [Interface(mac="08:61:95:00:11:22")],   # Rockwell Automation OUI
    "observed_at": datetime(2026, 4, 28, 13, 0, tzinfo=timezone.utc),
})
m3 = match_host(host2, client)
print(f"  match_host: kind={m3.kind.value} device_id={m3.netbox_device_id}")
r3 = upsert_host(host2, m3, client, scan_id="test-scan-002", dry_run=False, strategy=Strategy.MERGE, defaults=defaults)
print(f"  upsert_host: action={r3.action.value}")
print(f"  diffs ({len(r3.diffs)}):")
for d in r3.diffs:
    print(f"    {d.field}: {d.before} -> {d.after}")

print()
print("=== STEP 5: Verify alert:mac-change tag now on device ===")
device3 = client.api.dcim.devices.get(r3.netbox_device_id)
tags = [t.name for t in device3.tags]
print(f"  tags: {tags}")
assert "alert:mac-change" in tags, "MAC change should have triggered alert:mac-change"
print(f"  oui_vendor: {device3.custom_fields.get('oui_vendor')}")
print(f"  related_macs ({len(device3.custom_fields.get('related_macs') or [])}):")
for entry in device3.custom_fields.get("related_macs") or []:
    print(f"    {entry}")

print()
print("=== ALL STEPS PASSED ===")
