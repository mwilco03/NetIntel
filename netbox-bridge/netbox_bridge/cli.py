import click

from . import __version__


@click.group()
@click.version_option(__version__)
def main() -> None:
    pass


@main.command()
@click.option("--url", required=True, help="NetBox base URL, e.g. https://netbox.example.com")
@click.option("--token", envvar="NETBOX_TOKEN", help="NetBox API token (or NETBOX_TOKEN env var).")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def discover(url: str, token: str, verify_tls: bool, as_json: bool) -> None:
    """Enumerate NetBox state. Read-only.

    Reports sites, tenants, device roles, platforms, custom fields, tags, and the NetBox version.
    Flags what the bridge needs but does not find (missing custom fields, missing source tags).
    """
    raise NotImplementedError


@main.command()
@click.option("--url", required=True)
@click.option("--token", envvar="NETBOX_TOKEN")
@click.option("--verify-tls/--no-verify-tls", default=True)
@click.option(
    "--apply",
    is_flag=True,
    help="Actually create custom fields and tags. Without this flag, prints a plan only.",
)
def init(url: str, token: str, verify_tls: bool, apply: bool) -> None:
    """Create the custom fields and tags the bridge needs. Dry-run by default."""
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
    token: str,
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
    token: str,
    verify_tls: bool,
    input_path: str,
    strategy: str,
    dry_run: bool,
) -> None:
    """Parse a scan file and upsert into NetBox."""
    raise NotImplementedError


if __name__ == "__main__":
    main()
