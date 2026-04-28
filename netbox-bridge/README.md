# netbox-bridge

CLI that ingests Nmap and Nessus scan output into NetBox.

> **Status:** Phase 1 / Phase 2 in progress.
> - `discover`, `init`, `fetch` — implemented + tested
> - `plan`, `ingest` — stubs (raise `NotImplementedError`)

## Commands

| Command | What it does | Default safety | Status |
|---|---|---|---|
| `netbox-bridge discover --url <netbox>` | Enumerate NetBox state; report what exists and what the bridge needs but doesn't find. | Read-only. | implemented |
| `netbox-bridge init --url <netbox>` | Create the custom fields and tags the bridge needs. | Dry-run; pass `--apply` to actually write. | implemented |
| `netbox-bridge fetch --source <malcolm\|security-onion> --url <opensearch> --since 7d` | Pull observed hosts from an OpenSearch backend, emit normalized Host JSON. | Read-only against OpenSearch; no NetBox writes. | implemented |
| `netbox-bridge plan --url <netbox> --input scan.xml` | Show what `ingest` would do, without writing. | Read-only. | stub |
| `netbox-bridge ingest --url <netbox> --input scan.xml` | Parse a scan file and upsert into NetBox. | Writes; pass `--dry-run` to preview. | stub |

### Sources

The `fetch` command supports two OpenSearch backends:

- **Malcolm** — index pattern `arkime_sessions3-*`, no dataset filter. Aggregates by `destination.ip` so hosts running observed services become Hosts. Carries protocol names from Zeek's custom parsers (modbus, dnp3, bacnet, s7comm) verbatim.
- **Security Onion** — data stream `logs-zeek-so`, default `event.dataset` filter `[conn, known_services]`. Same ECS-aligned aggregation.

Both use HTTP basic auth on port 9200. Pass `--password` or set `OPENSEARCH_PASSWORD`.

## Auth

In order of precedence: `--token` flag, `NETBOX_TOKEN` env var, `~/.config/netbox-bridge/config.toml`.

The auth layer is an adapter (`netbox_bridge.client.AuthAdapter`) so non-token mechanisms (OIDC, mTLS, reverse-proxy basic auth) can plug in later without touching the rest of the code.

## Dev

Stand up a local NetBox via Docker:

```
cd dev
make dev-up        # clones netbox-docker, runs docker compose up -d
make dev-token     # creates a superuser; mint an API token in the UI
```

Tear down: `make dev-down` keeps volumes, `make dev-reset` drops them.

## Design

- **Identity:** dedup by MAC → IP → FQDN, in that order.
- **Strategy on conflict:** `merge` by default. `--strategy=overwrite|skip` to override.
- **Bridge-owned custom fields** (on Device, IPAddress, Service): `last_seen`, `first_seen`, `last_scan_id`, `source`.
- **Bridge ownership signal:** the tag `source:netintel-bridge`. On devices the bridge created, future scans freely update bridge-set fields. On devices the bridge did not create, only the bridge's own custom fields are touched — `description`, `comments`, `tenant`, etc. are left alone.
- **History:** the local SQLite observation DB at `~/.local/share/netbox-bridge/observations.db` holds the full scan-by-scan history. NetBox holds the current best view. This keeps NetBox's per-host footprint constant regardless of how many scans run.
- **Idempotent writes:** a re-scan of an unchanged network produces zero NetBox `ObjectChange` rows.

## NetBox compatibility

Targets NetBox 4.x. Pinned `pynetbox>=7.4`. If the target environment runs an older NetBox, adjust here.

## Testing

TDD throughout. New behavior gets a failing test first, then implementation.

```
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Test layout:

- `tests/test_discover.py` — orchestration of `discover()` and rendering
- `tests/test_init.py` — CF/tag spec generation, plan/apply behavior, rendering
- `tests/test_cli.py` — click command wiring (NetBoxClient / OpenSearchClient mocked)
- `tests/test_client.py` — `NetBoxClient` pynetbox passthroughs (pynetbox.api mocked)
- `tests/test_opensearch.py` — `OpenSearchClient` request/auth/error handling (requests.Session mocked)
- `tests/test_malcolm_source.py` — query construction + Host mapping (fixture-driven)
- `tests/test_security_onion_source.py` — same, for SO

Integration tests against a live NetBox (the `dev/` netbox-docker harness) are not written yet — they're the next layer once `init` and `ingest` exist. For now, verify `discover` end-to-end manually:

```
cd dev && make dev-up && make dev-token   # mint a token in the UI
NETBOX_TOKEN=<token> netbox-bridge discover --url http://localhost:8000
```
