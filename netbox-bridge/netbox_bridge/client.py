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
        raise NotImplementedError

    def list_sites(self) -> list[Any]:
        raise NotImplementedError

    def list_tenants(self) -> list[Any]:
        raise NotImplementedError

    def list_device_roles(self) -> list[Any]:
        raise NotImplementedError

    def list_platforms(self) -> list[Any]:
        raise NotImplementedError

    def list_custom_fields(self, content_type: str) -> list[Any]:
        raise NotImplementedError

    def list_tags(self) -> list[Any]:
        raise NotImplementedError

    def find_device_by_mac(self, mac: str) -> Any | None:
        raise NotImplementedError

    def find_device_by_primary_ip(self, ip: str) -> Any | None:
        raise NotImplementedError

    def find_device_by_name(self, name: str) -> Any | None:
        raise NotImplementedError
