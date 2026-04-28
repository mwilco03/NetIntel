from __future__ import annotations

import json
import re
from datetime import timedelta

import click

from . import __version__
from .client import NetBoxClient, TokenAdapter
from .discover import discover as run_discover
from .discover import render_human, render_json
from .init import render_human as render_init_human
from .init import render_json as render_init_json
from .init import run_init
from .opensearch import OpenSearchClient
from .probe import probe as run_probe
from .probe import render_human as render_probe_human
from .probe import render_json as render_probe_json
from .sources.malcolm import DEFAULT_INDEX_PATTERN as MALCOLM_INDEX_PATTERN
from .sources.malcolm import MalcolmSource
from .sources.security_onion import DEFAULT_INDEX_PATTERN as SO_INDEX_PATTERN
from .sources.security_onion import SecurityOnionSource

_SOURCE_DEFAULT_INDEX_PATTERN: dict[str, str] = {
    "malcolm": MALCOLM_INDEX_PATTERN,
    "security-onion": SO_INDEX_PATTERN,
}

_SINCE_PATTERN = re.compile(r"^(\d+)([smhd])$")
_SINCE_UNITS: dict[str, str] = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}

_SOURCE_NAMES: list[str] = ["malcolm", "security-onion"]


def _parse_since(value: str) -> timedelta:
    match = _SINCE_PATTERN.match(value)
    if not match:
        raise click.BadParameter(
            f"Invalid --since value '{value}'. Expected forms like 30s, 5m, 2h, 7d."
        )
    n = int(match.group(1))
    unit = _SINCE_UNITS[match.group(2)]
    return timedelta(**{unit: n})


def _since_to_opensearch(value: str) -> str:
    """Convert a --since user value (e.g. '7d') to OpenSearch range format ('now-7d')."""
    _parse_since(value)  # raises BadParameter if invalid
    return f"now-{value}"


@click.group()
@click.version_option(__version__)
def main() -> None:
    pass


def _require_token(token: str | None) -> str:
    if not token:
        raise click.UsageError(
            "NetBox API token required (pass --token or set NETBOX_TOKEN env var)."
        )
    return token


@main.command()
@click.option("--url", required=True, help="NetBox base URL, e.g. https://netbox.example.com")
@click.option("--token", envvar="NETBOX_TOKEN", help="NetBox API token (or NETBOX_TOKEN env var).")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def discover(url: str, token: str | None, verify_tls: bool, as_json: bool) -> None:
    """Enumerate NetBox state. Read-only.

    Reports sites, tenants, device roles, platforms, custom fields, tags, and the NetBox version.
    Flags what the bridge needs but does not find (missing custom fields, missing source tags).
    """
    token = _require_token(token)
    client = NetBoxClient(url, TokenAdapter(token), verify_tls=verify_tls)
    report = run_discover(client)
    click.echo(render_json(report) if as_json else render_human(report))


@main.command()
@click.option("--url", required=True)
@click.option("--token", envvar="NETBOX_TOKEN")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option(
    "--apply",
    is_flag=True,
    help="Actually create custom fields and tags. Without this flag, prints a plan only.",
)
@click.option("--json", "as_json", is_flag=True)
def init(url: str, token: str | None, verify_tls: bool, apply: bool, as_json: bool) -> None:
    """Create the custom fields and tags the bridge needs. Dry-run by default."""
    token = _require_token(token)
    client = NetBoxClient(url, TokenAdapter(token), verify_tls=verify_tls)
    plan = run_init(client, apply=apply)
    click.echo(render_init_json(plan) if as_json else render_init_human(plan))


@main.command()
@click.option("--url", required=True)
@click.option("--token", envvar="NETBOX_TOKEN")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Nmap XML or Nessus .nessus file.",
)
@click.option(
    "--strategy",
    type=click.Choice(["merge", "overwrite", "skip"]),
    default="merge",
)
@click.option("--verbose", is_flag=True, help="Expand UPDATE rows to field-level diffs.")
@click.option("--json", "as_json", is_flag=True)
def plan(
    url: str,
    token: str | None,
    verify_tls: bool,
    input_path: str,
    strategy: str,
    verbose: bool,
    as_json: bool,
) -> None:
    """Show what `ingest` would do, without writing."""
    raise NotImplementedError


@main.command()
@click.option("--url", required=True)
@click.option("--token", envvar="NETBOX_TOKEN")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--strategy",
    type=click.Choice(["merge", "overwrite", "skip"]),
    default="merge",
)
@click.option("--dry-run", is_flag=True, help="Parse and match, but do not write to NetBox.")
def ingest(
    url: str,
    token: str | None,
    verify_tls: bool,
    input_path: str,
    strategy: str,
    dry_run: bool,
) -> None:
    """Parse a scan file and upsert into NetBox."""
    raise NotImplementedError


@main.command()
@click.option(
    "--source",
    "source_name",
    type=click.Choice(_SOURCE_NAMES),
    required=True,
)
@click.option("--url", required=True, help="OpenSearch base URL, e.g. https://malcolm:9200")
@click.option("--username", required=True)
@click.option("--password", envvar="OPENSEARCH_PASSWORD", help="(or OPENSEARCH_PASSWORD env var)")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option("--since", "since_str", required=True, help="Time window: 30s, 5m, 2h, 7d.")
@click.option(
    "--index-pattern",
    default=None,
    help="Override the source's default index pattern.",
)
def fetch(
    source_name: str,
    url: str,
    username: str,
    password: str | None,
    verify_tls: bool,
    since_str: str,
    index_pattern: str | None,
) -> None:
    """Pull observed hosts from an OpenSearch backend (Malcolm, Security Onion).

    Outputs the normalized Host records as JSON. Does not write to NetBox.
    """
    since = _parse_since(since_str)
    client = OpenSearchClient(
        url, username=username, password=password, verify_tls=verify_tls
    )
    sources: dict[str, type] = {
        "malcolm": MalcolmSource,
        "security-onion": SecurityOnionSource,
    }
    source_cls = sources[source_name]
    source_kwargs: dict = {}
    if index_pattern is not None:
        source_kwargs["index_pattern"] = index_pattern
    source = source_cls(client, **source_kwargs)
    hosts = source.fetch_hosts(since=since)
    click.echo(json.dumps([h.model_dump(mode="json") for h in hosts], indent=2, default=str))


@main.command()
@click.option(
    "--source",
    "source_name",
    type=click.Choice(_SOURCE_NAMES),
    required=True,
)
@click.option("--url", required=True, help="OpenSearch base URL.")
@click.option("--username", required=True)
@click.option("--password", envvar="OPENSEARCH_PASSWORD")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option(
    "--since",
    "since_str",
    default=None,
    help="Optional time window for dataset distribution (e.g. 7d). Format: 30s/5m/2h/7d.",
)
@click.option("--index-pattern", default=None, help="Override the source's default index pattern.")
@click.option("--json", "as_json", is_flag=True)
def probe(
    source_name: str,
    url: str,
    username: str,
    password: str | None,
    verify_tls: bool,
    since_str: str | None,
    index_pattern: str | None,
    as_json: bool,
) -> None:
    """Pre-query introspect the OpenSearch backend.

    Asks the backend itself which indices exist, which fields are populated, and which
    event.dataset values have data. Use this before running fetch/ingest to confirm the
    target deployment will satisfy our query.
    """
    pattern = index_pattern or _SOURCE_DEFAULT_INDEX_PATTERN[source_name]
    since = _since_to_opensearch(since_str) if since_str else None
    client = OpenSearchClient(url, username=username, password=password, verify_tls=verify_tls)
    report = run_probe(client, index_pattern=pattern, since=since)
    click.echo(render_probe_json(report) if as_json else render_probe_human(report))
    if not report.ready:
        raise click.exceptions.Exit(code=2)


if __name__ == "__main__":
    main()
