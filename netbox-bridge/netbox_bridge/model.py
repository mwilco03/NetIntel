from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Service(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    name: str | None = None
    banner: str | None = None


class Interface(BaseModel):
    mac: str | None = None
    name: str | None = None


class IPAddress(BaseModel):
    address: str


class OSInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    accuracy: int | None = None


class Host(BaseModel):
    primary_ip: str
    fqdn: str | None = None
    interfaces: list[Interface] = Field(default_factory=list)
    addresses: list[IPAddress] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    os: OSInfo | None = None
    source: Literal["nmap", "nessus", "malcolm", "security_onion"]
    observed_at: datetime
