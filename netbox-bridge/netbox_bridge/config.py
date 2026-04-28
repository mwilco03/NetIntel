from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, HttpUrl

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "netbox-bridge" / "config.toml"
DEFAULT_OBSERVATION_DB = Path.home() / ".local" / "share" / "netbox-bridge" / "observations.db"


class Config(BaseModel):
    url: HttpUrl
    token: str
    verify_tls: bool = True
    observation_db_path: Path = DEFAULT_OBSERVATION_DB


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config | None:
    """Load config from TOML, with NETBOX_TOKEN env var taking precedence over the file's token."""
    if not path.exists():
        return None
    with path.open("rb") as f:
        data = tomllib.load(f)
    if env_token := os.environ.get("NETBOX_TOKEN"):
        data["token"] = env_token
    return Config(**data)
