"""Asset and identity inventory used to enrich detections (who is privileged, what is internal...)."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from functools import cached_property
from pathlib import Path

from pydantic import Field

from app.models.common import ApiModel, UtcDatetime


class Asset(ApiModel):
    hostname: str
    ip: str
    os: str
    role: str
    criticality: str
    owner: str | None = None
    public_ip: str | None = None
    tags: list[str] = Field(default_factory=list)


class Identity(ApiModel):
    username: str
    display_name: str
    department: str
    title: str
    type: str  # human | admin | service | builtin
    privileged: bool = False
    workstation: str | None = None


class MaintenanceWindow(ApiModel):
    id: str
    description: str
    usernames: list[str]
    hosts: list[str]
    start: UtcDatetime
    end: UtcDatetime


class GeoRange(ApiModel):
    cidr: str
    country: str
    city: str
    asn: str
    organization: str
    reputation: str


class Inventory(ApiModel):
    organization: str
    domain: str
    internal_networks: list[str]
    privileged_groups: list[str]
    assets: list[Asset]
    identities: list[Identity]
    maintenance_windows: list[MaintenanceWindow] = Field(default_factory=list)
    geo: list[GeoRange] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> Inventory:
        with path.open(encoding="utf-8") as fh:
            return cls.model_validate(json.load(fh))

    @cached_property
    def _networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n) for n in self.internal_networks]

    @cached_property
    def _assets(self) -> dict[str, Asset]:
        return {a.hostname: a for a in self.assets}

    @cached_property
    def _assets_by_ip(self) -> dict[str, Asset]:
        return {a.ip: a for a in self.assets}

    @cached_property
    def _identities(self) -> dict[str, Identity]:
        return {i.username: i for i in self.identities}

    def is_internal(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return address.is_loopback or any(address in net for net in self._networks)

    def asset(self, hostname: str | None) -> Asset | None:
        return self._assets.get(hostname or "")

    def asset_by_ip(self, ip: str | None) -> Asset | None:
        return self._assets_by_ip.get(ip or "")

    def identity(self, username: str | None) -> Identity | None:
        return self._identities.get(username or "")

    def is_privileged(self, username: str | None) -> bool:
        identity = self.identity(username)
        return bool(identity and identity.privileged)

    def is_service_account(self, username: str | None) -> bool:
        identity = self.identity(username)
        return bool(identity and identity.type == "service")

    def is_privileged_group(self, group: str | None) -> bool:
        return bool(group) and group.lower() in {g.lower() for g in self.privileged_groups}

    def maintenance_window(self, username: str | None, hostname: str | None, at: datetime) -> MaintenanceWindow | None:
        for window in self.maintenance_windows:
            if window.start <= at <= window.end and (username in window.usernames) and (hostname in window.hosts):
                return window
        return None

    def geo_for(self, ip: str | None) -> GeoRange | None:
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for entry in self.geo:
            if address in ipaddress.ip_network(entry.cidr):
                return entry
        return None
