"""Admin-approved Cisco Meraki MX source-IP firewall blocks."""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from app.core.config import settings

API_BASE_URL = "https://api.meraki.com/api/v1"
MANAGED_COMMENT_PREFIX = "AI-NIDS managed source-IP block: "
REQUEST_TIMEOUT_SECONDS = 10.0


class MerakiIntegrationError(RuntimeError):
    """A safe-to-display Meraki configuration or API failure."""


def is_configured() -> bool:
    return bool(settings.MERAKI_API_KEY.strip() and settings.MERAKI_NETWORK_ID.strip())


def integration_status() -> dict[str, Any]:
    missing = []
    if not settings.MERAKI_API_KEY.strip():
        missing.append("MERAKI_API_KEY")
    if not settings.MERAKI_NETWORK_ID.strip():
        missing.append("MERAKI_NETWORK_ID")
    return {
        "configured": not missing,
        "integration": "Cisco Meraki MX",
        "network_id": settings.MERAKI_NETWORK_ID.strip() if not missing else None,
        "missing_configuration": missing,
    }


def _client() -> httpx.Client:
    if not is_configured():
        raise MerakiIntegrationError(
            "Cisco Meraki integration is not configured. Set MERAKI_API_KEY and "
            "MERAKI_NETWORK_ID on the backend, then restart it."
        )
    return httpx.Client(
        base_url=API_BASE_URL,
        headers={
            "X-Cisco-Meraki-API-Key": settings.MERAKI_API_KEY.strip(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def _firewall_path() -> str:
    return f"/networks/{settings.MERAKI_NETWORK_ID.strip()}/appliance/firewall/l3FirewallRules"


def _read_policy(client: httpx.Client) -> dict[str, Any]:
    try:
        response = client.get(_firewall_path())
        response.raise_for_status()
        policy = response.json()
    except httpx.HTTPStatusError as exc:
        raise MerakiIntegrationError(
            f"Meraki rejected the firewall policy request (HTTP {exc.response.status_code}). "
            "Check the API key, network, and appliance permissions."
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise MerakiIntegrationError("Could not read the Meraki firewall policy.") from exc

    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise MerakiIntegrationError("Meraki returned an unexpected firewall policy response.")
    return policy


def _write_policy(client: httpx.Client, policy: dict[str, Any], rules: list[dict[str, Any]]) -> None:
    payload: dict[str, Any] = {"rules": rules}
    if "syslogDefaultRule" in policy:
        payload["syslogDefaultRule"] = policy["syslogDefaultRule"]
    try:
        response = client.put(_firewall_path(), json=payload)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise MerakiIntegrationError(
            f"Meraki rejected the firewall policy update (HTTP {exc.response.status_code}). "
            "No success was reported; verify the firewall policy in the Meraki Dashboard."
        ) from exc
    except httpx.HTTPError as exc:
        raise MerakiIntegrationError(
            "The Meraki firewall update did not complete. Verify the current policy in the "
            "Meraki Dashboard before retrying."
        ) from exc


def _managed_ip(rule: dict[str, Any]) -> str | None:
    comment = rule.get("comment")
    if not isinstance(comment, str) or not comment.startswith(MANAGED_COMMENT_PREFIX):
        return None
    value = comment[len(MANAGED_COMMENT_PREFIX) :].strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.compressed if address.version == 4 else None


def list_blocked_ips() -> list[dict[str, str]]:
    with _client() as client:
        policy = _read_policy(client)
    blocks: dict[str, dict[str, str]] = {}
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            continue
        ip = _managed_ip(rule)
        if ip is not None and rule.get("policy") == "deny":
            blocks[ip] = {"ip": ip, "comment": str(rule.get("comment", ""))}
    return [{"ip": ip, **blocks[ip]} for ip in sorted(blocks)]


def block_ip(ip: str) -> dict[str, Any]:
    """Insert an exact-host deny rule before existing policy rules."""
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise MerakiIntegrationError("Only individual IPv4 addresses can be blocked.")
    canonical_ip = address.compressed
    with _client() as client:
        policy = _read_policy(client)
        rules = policy["rules"]
        if any(_managed_ip(rule) == canonical_ip for rule in rules if isinstance(rule, dict)):
            return {"ip": canonical_ip, "changed": False}

        managed_rule = {
            "comment": f"{MANAGED_COMMENT_PREFIX}{canonical_ip}",
            "policy": "deny",
            "protocol": "any",
            "srcPort": "Any",
            "srcCidr": f"{canonical_ip}/32",
            "destPort": "Any",
            "destCidr": "Any",
        }
        _write_policy(client, policy, [managed_rule, *rules])
    return {"ip": canonical_ip, "changed": True}


def unblock_ip(ip: str) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        raise MerakiIntegrationError("Only individual IPv4 addresses can be unblocked.")
    canonical_ip = address.compressed
    with _client() as client:
        policy = _read_policy(client)
        rules = policy["rules"]
        remaining = [
            rule
            for rule in rules
            if not (
                isinstance(rule, dict)
                and _managed_ip(rule) == canonical_ip
                and rule.get("policy") == "deny"
            )
        ]
        changed = len(remaining) != len(rules)
        if changed:
            _write_policy(client, policy, remaining)
    return {"ip": canonical_ip, "changed": changed}


def clear_managed_blocks() -> dict[str, Any]:
    """Remove only AI-NIDS-tagged deny rules; preserve all other Meraki rules."""
    with _client() as client:
        policy = _read_policy(client)
        rules = policy["rules"]
        remaining = [
            rule
            for rule in rules
            if not (
                isinstance(rule, dict)
                and _managed_ip(rule) is not None
                and rule.get("policy") == "deny"
            )
        ]
        removed = len(rules) - len(remaining)
        if removed:
            _write_policy(client, policy, remaining)
    return {"removed": removed}
