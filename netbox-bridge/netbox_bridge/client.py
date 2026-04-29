from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import pynetbox
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Transient HTTP statuses that should be retried at the urllib3 transport layer. pynetbox uses an
# internal requests.Session for every API call, so mounting an HTTPAdapter with this Retry config
# gives us transparent retry for every CRUD operation without wrapping each method.
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
_DEFAULT_RETRIES = 4
_DEFAULT_BACKOFF = 0.5


class AuthAdapter(ABC):
    """Pluggable auth so non-token mechanisms (OIDC, mTLS, basic-auth) can be added later."""

    @abstractmethod
    def apply(self, api: pynetbox.api) -> None: ...


class TokenAdapter(AuthAdapter):
    def __init__(self, token: str) -> None:
        self.token = token

    def apply(self, api: pynetbox.api) -> None:
        api.token = self.token


def _build_retry_adapter() -> HTTPAdapter:
    retry = Retry(
        total=_DEFAULT_RETRIES,
        backoff_factor=_DEFAULT_BACKOFF,
        status_forcelist=tuple(_TRANSIENT_STATUSES),
        allowed_methods=frozenset({"HEAD", "GET", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    return HTTPAdapter(max_retries=retry)


class NetBoxClient:
    def __init__(self, url: str, auth: AuthAdapter, *, verify_tls: bool = True) -> None:
        self.api = pynetbox.api(url)
        self.api.http_session.verify = verify_tls
        # Mount retry adapter on both HTTP and HTTPS so transient NetBox/proxy hiccups don't kill
        # an entire scan. urllib3 honors Retry-After on 429 automatically.
        adapter = _build_retry_adapter()
        self.api.http_session.mount("http://", adapter)
        self.api.http_session.mount("https://", adapter)
        auth.apply(self.api)
        self._netbox_version: str | None = None

    @property
    def netbox_version(self) -> str:
        """NetBox version string from /api/status/, e.g. '4.2.5'.

        Cached after first call. Used by upsert to choose between the 4.2.5-era Service
        shape (uses `device` field) and the 4.5+ shape (uses parent_object_type/_id).
        Verified 2026-04-29 against:
          - v4.2.5 serializer: device + virtual_machine fields
            https://github.com/netbox-community/netbox/blob/v4.2.5/netbox/ipam/api/serializers_/services.py
          - v4.5 serializer: parent_object_type + parent_object_id (device REMOVED)
            https://github.com/netbox-community/netbox/blob/main/netbox/ipam/api/serializers_/services.py
        """
        if self._netbox_version is None:
            self._netbox_version = str(self.api.version)
        return self._netbox_version

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
        # NetBox 4.2+ promoted MAC to its own model. Filter on dcim.mac_addresses; the assigned
        # object resolves to the Interface, which has a .device. Only handle dcim.interface here
        # (VM interfaces are out of scope for v1).
        for mac_obj in self.api.dcim.mac_addresses.filter(mac_address=mac):
            if getattr(mac_obj, "assigned_object_type", None) != "dcim.interface":
                continue
            iface = getattr(mac_obj, "assigned_object", None)
            device = getattr(iface, "device", None) if iface is not None else None
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

    def create_device(self, spec: dict) -> Any:
        return self.api.dcim.devices.create(spec)

    def create_interface(self, spec: dict) -> Any:
        return self.api.dcim.interfaces.create(spec)

    def create_mac_address(self, spec: dict) -> Any:
        # NetBox 4.2+: MAC is its own model. POST to dcim/mac-addresses with assigned_object_type
        # ("dcim.interface") and assigned_object_id pointing at the Interface that owns it.
        return self.api.dcim.mac_addresses.create(spec)

    def create_ip_address(self, spec: dict) -> Any:
        return self.api.ipam.ip_addresses.create(spec)

    def create_service(self, spec: dict) -> Any:
        # Service uses parent_object_type/parent_object_id (NOT 'device'); see
        # netbox/ipam/api/serializers_/services.py upstream.
        return self.api.ipam.services.create(spec)

    def update_device(self, device_id: int, fields: dict) -> Any | None:
        device = self.api.dcim.devices.get(device_id)
        if device is None:
            return None
        for k, v in fields.items():
            setattr(device, k, v)
        device.save()
        return device

    def update_interface(self, interface_id: int, fields: dict) -> Any | None:
        iface = self.api.dcim.interfaces.get(interface_id)
        if iface is None:
            return None
        for k, v in fields.items():
            setattr(iface, k, v)
        iface.save()
        return iface

    def get_device(self, device_id: int) -> Any | None:
        return self.api.dcim.devices.get(device_id)

    def list_services_for_device(self, device_id: int) -> list[Any]:
        return list(self.api.ipam.services.filter(device_id=device_id))
