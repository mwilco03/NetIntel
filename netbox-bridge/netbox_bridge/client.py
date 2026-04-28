from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import pynetbox


class AuthAdapter(ABC):
    """Pluggable auth so non-token mechanisms (OIDC, mTLS, basic-auth) can be added later."""

    @abstractmethod
    def apply(self, api: pynetbox.api) -> None: ...


class TokenAdapter(AuthAdapter):
    def __init__(self, token: str) -> None:
        self.token = token

    def apply(self, api: pynetbox.api) -> None:
        api.token = self.token


class NetBoxClient:
    def __init__(self, url: str, auth: AuthAdapter, *, verify_tls: bool = True) -> None:
        self.api = pynetbox.api(url)
        self.api.http_session.verify = verify_tls
        auth.apply(self.api)

    def version(self) -> str:
        return str(self.api.version)

    def list_sites(self) -> list[Any]:
        return list(self.api.dcim.sites.all())

    def list_tenants(self) -> list[Any]:
        return list(self.api.tenancy.tenants.all())

    def list_device_roles(self) -> list[Any]:
        return list(self.api.dcim.device_roles.all())

    def list_platforms(self) -> list[Any]:
        return list(self.api.dcim.platforms.all())

    def list_custom_fields(self, content_type: str) -> list[Any]:
        return list(self.api.extras.custom_fields.filter(content_types=content_type))

    def list_tags(self) -> list[Any]:
        return list(self.api.extras.tags.all())

    def create_custom_field(self, spec: dict) -> Any:
        return self.api.extras.custom_fields.create(spec)

    def create_tag(self, spec: dict) -> Any:
        return self.api.extras.tags.create(spec)

    def find_device_by_mac(self, mac: str) -> Any | None:
        for iface in self.api.dcim.interfaces.filter(mac_address=mac):
            device = getattr(iface, "device", None)
            if device is not None:
                return device
        return None

    def find_device_by_primary_ip(self, ip: str) -> Any | None:
        for ip_obj in self.api.ipam.ip_addresses.filter(address=ip):
            if getattr(ip_obj, "assigned_object_type", None) != "dcim.interface":
                continue
            iface = getattr(ip_obj, "assigned_object", None)
            device = getattr(iface, "device", None) if iface is not None else None
            if device is not None:
                return device
        return None

    def find_device_by_name(self, name: str) -> Any | None:
        for device in self.api.dcim.devices.filter(name=name):
            return device
        return None
