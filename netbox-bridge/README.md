# netbox-bridge

CLI that ingests Nmap and Nessus scan output into NetBox.

> **Status:** Phase 1 scaffold. Stubs only — no real logic yet. The shape is for review.

## Commands

| Command | What it does | Default safety |
|---|---|---|
| `netbox-bridge discover --url <netbox>` | Enumerate NetBox state; report what exists and what the bridge needs but doesn't find. | Read-only. |
| `netbox-bridge init --url <netbox>` | Create the custom fields and tags the bridge needs. | Dry-run; pass `--apply` to actually write. |
| `netbox-bridge plan --url <netbox> --input scan.xml` | Show what `ingest` would do, without writing. | Read-only. |
| `netbox-bridge ingest --url <netbox> --input scan.xml` | Parse a scan file and upsert into NetBox. | Writes; pass `--dry-run` to preview. |

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
