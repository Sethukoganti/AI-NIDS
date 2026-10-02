"""Admin-managed IP/CIDR policies for labeling analyzed flow data."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.database_models import NetworkBlockRule

ParsedNetwork = IPv4Network | IPv6Network
ParsedAddress = IPv4Address | IPv6Address


def normalize_network(value: str) -> str:
    """Return a canonical IP/CIDR value; reject default routes."""
    try:
        network = ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4/IPv6 address or CIDR network.") from exc
    if network.prefixlen == 0:
        raise ValueError("A default route cannot be added to the blocklist.")
    return str(network)


def active_networks(db: Session) -> list[tuple[str, ParsedNetwork]]:
    """Load active policies once for a batch of flow matches."""
    rules = db.scalars(
        select(NetworkBlockRule).where(NetworkBlockRule.active.is_(True))
    ).all()
    parsed = [(rule.network, ip_network(rule.network)) for rule in rules]
    return sorted(parsed, key=lambda item: item[1].prefixlen, reverse=True)


def matching_network(
    value: str | None,
    rules: list[tuple[str, ParsedNetwork]],
) -> str | None:
    """Return the first active policy matching an observed source address."""
    if not value:
        return None
    try:
        address: ParsedAddress = ip_address(value.strip())
    except ValueError:
        return None
    for name, network in rules:
        if address.version == network.version and address in network:
            return name
    return None
