NETBOX_DOCKER_DIR := .netbox-docker

.PHONY: dev-up dev-down dev-reset dev-token dev-seed help

help:
	@echo "Targets:"
	@echo "  dev-up      Clone netbox-docker (if needed) and start it (http://localhost:8000)"
	@echo "  dev-down    Stop containers, keep volumes"
	@echo "  dev-reset   Stop containers and drop volumes (full reset)"
	@echo "  dev-token   Create a superuser; mint an API token in the NetBox UI"
	@echo "  dev-seed    Populate dev NetBox with a few sites/tenants/roles"

$(NETBOX_DOCKER_DIR):
	git clone -b release https://github.com/netbox-community/netbox-docker.git $@
	cp $@/docker-compose.override.yml.example $@/docker-compose.override.yml

dev-up: $(NETBOX_DOCKER_DIR)
	cd $(NETBOX_DOCKER_DIR) && docker compose up -d
	@echo "NetBox is starting at http://localhost:8000 (first boot can take a few minutes)."

dev-down:
	cd $(NETBOX_DOCKER_DIR) && docker compose down

dev-reset:
	cd $(NETBOX_DOCKER_DIR) && docker compose down -v

dev-token:
	cd $(NETBOX_DOCKER_DIR) && docker compose exec netbox /opt/netbox/netbox/manage.py createsuperuser

dev-seed:
	NETBOX_URL=http://localhost:8000 python seed.py
