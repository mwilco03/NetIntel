# dev

Local NetBox for developing the bridge against. Uses upstream `netbox-community/netbox-docker`, cloned on first `make dev-up` into `.netbox-docker/` (gitignored).

```
make dev-up      # start
make dev-token   # create superuser, mint API token in the UI at http://localhost:8000
make dev-seed    # NETBOX_TOKEN=... make dev-seed
make dev-down    # stop, keep data
make dev-reset   # stop and wipe volumes
```

Minimum host: 4 GB RAM, 20 GB disk, 1 core. Tested on Linux/macOS.
