# Deployment runbook

Verified end-to-end on 2026-04-29 against:
- **NetBox 4.5** (image `docker.io/netboxcommunity/netbox:v4.5-4.0.2`, image digest pinned by tag)
- **OpenSearch 2.19.5** (image `docker.io/opensearchproject/opensearch:2`, single-node)

This runbook is the procedure that produced 5 `[CREATE]`s into a fresh NetBox from real-shaped Zeek + Suricata documents in OpenSearch, then ran twice more proving idempotency. Every step has the upstream citation an operator needs to verify it.

---

## 0. Prerequisites

- Docker daemon
- Python 3.11+ with `pip install -e .[dev]` from this repo
- Approximately 4 GB RAM for NetBox + 2 GB for OpenSearch

## 1. Bring up NetBox

The `dev/` directory contains a Makefile that clones [`netbox-community/netbox-docker`](https://github.com/netbox-community/netbox-docker) on first use and brings it up.

```
cd netbox-bridge/dev
make dev-up        # clones netbox-docker, runs docker compose up -d
```

**First boot runs migrations and takes 1–3 minutes.** Watch with `docker compose -f .netbox-docker/docker-compose.yml logs -f netbox`.

NetBox 4.5 in netbox-docker hardcodes `--host "::"` for granian, which fails on hosts without IPv6. The `dev/.netbox-docker/docker-compose.override.yml` we generate patches `launch-netbox.sh` to bind `0.0.0.0` instead. Real deployments don't need this.

## 2. Mint an API token

NetBox 4.5 changed token storage — the `users.Token` model now has `version` (1=plaintext, 2=HMAC), and v2 tokens cannot be retrieved after creation. Use a v1 token for scripted access:

```python
docker compose -f dev/.netbox-docker/docker-compose.yml exec -T netbox \
  /opt/netbox/netbox/manage.py shell -c "
from users.models import Token
from django.contrib.auth import get_user_model
u = get_user_model().objects.get(username='admin')
Token.objects.filter(user=u).delete()
t = Token(user=u, version=1)  # plaintext, NetBox <= 4.5 compatible
t.save()
print(t.plaintext)
"
```

Reference: NetBox 4.5 `users.models.Token` source — `version`, `plaintext`, and `hmac_digest` fields.

## 3. Seed required NetBox state

Bridge needs four objects to exist before ingest: a **Manufacturer**, **DeviceType**, **DeviceRole**, **Site**. Create the minimum:

```
NB_TOKEN=<from step 2>
H="-H Authorization:Token\ $NB_TOKEN -H Content-Type:application/json"

curl -sS -X POST http://localhost:8000/api/dcim/manufacturers/ $H \
  -d '{"name":"Generic","slug":"generic"}'
curl -sS -X POST http://localhost:8000/api/dcim/device-types/ $H \
  -d '{"manufacturer":1,"model":"Generic","slug":"generic"}'
curl -sS -X POST http://localhost:8000/api/dcim/device-roles/ $H \
  -d '{"name":"Discovered","slug":"discovered","color":"9e9e9e"}'
curl -sS -X POST http://localhost:8000/api/dcim/sites/ $H \
  -d '{"name":"Bridge Discovered","slug":"bridge-discovered","status":"active"}'
```

API endpoints verified against [`netbox-community/netbox`](https://github.com/netbox-community/netbox) `dcim.api.serializers_`. The hex color `9e9e9e` matches NetBox's `ColorValidator` regex `^[0-9a-f]{6}$` (verified at `netbox-community/netbox/main/netbox/utilities/validators.py`).

## 4. Init the bridge schema

```
netbox-bridge discover --url http://localhost:8000 --token $NB_TOKEN
# Reports NOT READY: missing 11 custom fields and 11 tags.

netbox-bridge init --url http://localhost:8000 --token $NB_TOKEN          # dry-run
netbox-bridge init --url http://localhost:8000 --token $NB_TOKEN --apply  # creates them

netbox-bridge discover --url http://localhost:8000 --token $NB_TOKEN
# Reports READY.
```

What gets created:

| Custom Field | Type | Purpose |
|---|---|---|
| `last_seen` | datetime | Most recent observation |
| `first_seen` | datetime | First observation, immutable after create |
| `last_scan_id` | text | UUID of most recent scan that touched this object |
| `source` | text | Which bridge sources contributed |
| `oui_vendor` | text | Vendor name resolved from MAC OUI |
| `related_macs` | json | Windowed list of MACs observed at this device's IP |
| `suricata_alerts_total` / `_high` / `_medium` / `_low` | integer | Per-severity Suricata alert counts |
| `suricata_top_signatures` | json | Top SIDs+counts hitting this host |

Type values verified against [`netbox-community/netbox/main/netbox/extras/choices.py`](https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/extras/choices.py) `CustomFieldTypeChoices`.

| Tag | Color | Purpose |
|---|---|---|
| `source:netintel-bridge` | blue `#1e88e5` | Bridge ownership marker |
| `source:nmap` / `nessus` / `malcolm` / `security_onion` | per-source | Provenance |
| `lifecycle:recently-added` | orange `#fb8c00` | First-seen within 7 days |
| `class:ot` / `it` / `mixed` | purple/teal/brown | Environment classification |
| `alert:mac-change` | deep red `#d32f2f` | Multi-MAC observation (ARP-spoof signal) |
| `alert:noisy` | bright red-orange `#f4511e` | Suricata alert volume past threshold |

All colors match NetBox's `^[0-9a-f]{6}$` validator (no `#`, lowercase, exactly 6 hex chars).

Tag references in payloads must use `[{"name": "..."}]` form, not raw strings. NetBox 4.5 returns 400 otherwise:

> `'Related objects must be referenced by numeric ID or by dictionary of attributes.'`

This is enforced by the bridge's `_build_device_spec` and `_build_update_patch`.

## 5. Bring up OpenSearch (optional — for source-side ingest)

Single-node, security plugin disabled (development only):

```
docker run -d --name os-test \
  -p 9200:9200 -p 9600:9600 \
  -e "discovery.type=single-node" \
  -e "DISABLE_SECURITY_PLUGIN=true" \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  docker.io/opensearchproject/opensearch:2
```

For real Malcolm/Security Onion deployments, point at the existing OpenSearch on port 9200.

## 6. Probe the OpenSearch backend

**Always run probe before ingest.** It calls `_cat/indices`, `_field_caps`, and a `terms` agg on `event.dataset` to confirm the bridge's required fields are populated. Exits non-zero on NOT READY.

```
netbox-bridge probe --source malcolm \
  --url http://localhost:9200 --username "" --password "" \
  --since 7d --index-pattern "arkime_sessions3-*"
```

Field paths verified against:
- `cisagov/Malcolm/logstash/pipelines/zeek/1300_zeek_normalize.conf` — Zeek conn → ECS
- `cisagov/Malcolm/logstash/pipelines/zeek/1015_zeek_conn.conf` — base parse
- `Security-Onion-Solutions/securityonion/.../zeek.common` — same ECS shape for SO
- `Security-Onion-Solutions/securityonion/.../zeek.conn` — service + transport + duration

## 7. Load test data (skip in production — real env has live data)

```
python3 dev/load_opensearch_fixtures.py
```

Writes 168 documents across 3 hosts: a Siemens MAC running modbus + http (mixed), a Rockwell MAC running profinet + s7comm (pure OT), an unmac'd host running dns (pure IT, graceful degradation). 150 Suricata alerts with the field paths Filebeat's Suricata module emits (`event.kind=alert`, `rule.id`, `rule.name`, `event.severity` 1/2/3).

## 8. Ingest

```
netbox-bridge ingest \
  --source malcolm \
  --opensearch-url http://localhost:9200 \
  --opensearch-username "" --opensearch-password "" \
  --since 1h --index-pattern "arkime_sessions3-*" \
  --netbox-url http://localhost:8000 \
  --netbox-token $NB_TOKEN \
  --site-id 1 --role-id 1 --device-type-id 1
```

Expected output (3 hosts in the test fixture):

```
[CREATE]    10.0.0.5           10.0.0.5    -- 
[CREATE]    10.0.0.6           10.0.0.6    -- 
[CREATE]    10.0.0.7           10.0.0.7    -- 

Summary: 3 create, 0 update, 0 noop, 0 conflict (3 total)
```

Re-run the same command — every host becomes NOOP unless the source data actually changed. Verified idempotency against real NetBox 4.5: zero PATCH calls on second run when `--scan-id` is held constant.

## 9. Suricata enrichment

The bridge ships Suricata enrichment as a separate pass. To populate the `suricata_alerts_*` custom fields and `alert:noisy` tag:

```
netbox-bridge enrich-suricata \
  --url http://localhost:9200 --username "" --password "" \
  --since 7d --index-pattern "arkime_sessions3-*"
```

This emits a JSON map of IP → alert counts. To wire it into ingest as a single pipeline, a follow-on slice (`--enrich-suricata` flag on `ingest`) will combine them. The two-pass approach keeps the OpenSearch source decision (Malcolm vs. SO vs. dedicated Suricata index) explicit.

Severity scale notes:
- **Filebeat / Security Onion**: preserves Suricata's native 1=high / 2=medium / 3=low. Bridge defaults assume this.
- **Malcolm**: `19_severity.conf` transforms 1–4 into 91/71/51/31/11. Bridge currently reports 0/0/0 on Malcolm. **Open issue.** Verified at [Malcolm 19_severity.conf](https://raw.githubusercontent.com/cisagov/Malcolm/main/logstash/pipelines/suricata/19_severity.conf).

## 10. Reproducible end-to-end test

To replay this entire procedure on a fresh laptop:

```
# 1. Bring up NetBox + create token (steps 1, 2 above)
# 2. Bring up OpenSearch (step 5)
# 3. Run the all-in-one validation:

cd netbox-bridge
NB_URL=http://localhost:8000 NB_TOKEN=<token> python3 dev/end_to_end.py
```

`end_to_end.py` runs five sequential operations against the real NetBox:
1. CREATE a host with Siemens MAC + modbus + http (asserts `class:mixed`, OUI=Siemens AG).
2. Verify NetBox state matches expectations.
3. Re-run same scan — must be NOOP (idempotency check).
4. Same host with Rockwell MAC — must trigger `alert:mac-change`.
5. Verify final state shows the alert tag, OUI changed to Rockwell, related_macs has both entries.

If any assertion fails, the script aborts with a clear pointer.

## Known limitations

- **Malcolm severity scale** unsupported (item from upstream-grounding audit). On Malcolm, `event.severity` is 91/71/51/31/11, not 1/2/3. Bridge will report zero high/medium/low. Workaround: use Security Onion sources, or wait for `--severity-scale=malcolm` flag.
- **OUI table** is a curated starter set (~70 OUIs across 11 vendors). Real networks may have many devices with no `oui_vendor` resolved. Workaround: the bridge degrades gracefully — `oui_vendor` simply remains unset, OUI-based classification doesn't fire.
- **Auth on OpenSearch** is HTTP basic only. Malcolm/SO with SSO/Keycloak in front of OpenSearch needs additional auth wiring.
- **Concurrent ingest** is unprotected. Two simultaneous runs against the same NetBox can race on `related_macs`. Run single-threaded in production until observation DB ships.
- **No bulk writes.** Per-device PATCH is fine for 100s of devices; painful at 10k+.
- **OpenSearch `network.protocol` for OT protocols** — Malcolm's `1300_zeek_normalize.conf` does NOT centrally rename `[zeek_cols][service]` to `[network][protocol]` for OT protocols (only DNS/HTTP/SMTP/SSL/SSH/SMB are explicitly translated). Real Malcolm ingest may produce conn records where Zeek labeled it `modbus` but our query looking at `network.protocol` returns nothing. Probe will catch this — its dataset distribution will show `conn` populated but our protocol filtering won't classify them.
