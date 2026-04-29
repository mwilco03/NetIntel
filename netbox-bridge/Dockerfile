# syntax=docker/dockerfile:1
#
# netbox-bridge — air-gap-friendly distroless-leaning image.
# Two stages: build (resolve deps) + runtime (slim, non-root).

FROM python:3.11-slim-bookworm AS build

WORKDIR /build

# lxml needs libxml2/libxslt headers at install time. Runtime needs the .so only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxslt1-dev \
        libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY netbox_bridge ./netbox_bridge
COPY README.md ./

RUN pip install --no-cache-dir --upgrade pip build \
 && pip wheel --no-cache-dir --wheel-dir /wheels .

# ---------------------------------------------------------------------------

FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="netbox-bridge" \
      org.opencontainers.image.description="Pulls Nmap/Nessus/Malcolm/Security Onion observations into NetBox" \
      org.opencontainers.image.source="https://github.com/mwilco03/NetIntel" \
      org.opencontainers.image.licenses="MIT"

# Runtime libs only — drop the -dev variants.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1000 -m -d /home/bridge bridge

# Install pre-built wheels from the build stage. No compilation, no toolchain.
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels netbox-bridge \
 && rm -rf /wheels

# Bring the runbook so an operator inside the container can `cat /opt/DEPLOYMENT.md`.
COPY DEPLOYMENT.md /opt/DEPLOYMENT.md

USER bridge
WORKDIR /home/bridge

ENTRYPOINT ["netbox-bridge"]
CMD ["--help"]
