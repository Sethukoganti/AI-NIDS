"""Persistent, simulation-only IP policy rules for demonstrations."""

from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.database_models import DemoIpRule

POLICIES = {"allow", "deny"}


class DemoIpRuleError(ValueError):
    """A policy input that cannot be represented by the demo firewall."""


def normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise DemoIpRuleError("Enter one valid IPv4 address (CIDR ranges are not accepted).") from exc
    if address.version != 4:
        raise DemoIpRuleError("Only individual IPv4 addresses are supported.")
    return address.compressed


def list_rules(db: Session) -> list[dict]:
    rows = db.scalars(select(DemoIpRule).order_by(DemoIpRule.ip.asc())).all()
    return [row.to_dict() for row in rows]


def set_rule(
    db: Session,
    ip: str,
    policy: str,
    reason: str,
    *,
    user=None,
) -> tuple[dict, bool]:
    if policy not in POLICIES:
        raise DemoIpRuleError("Policy must be 'allow' or 'deny'.")
    address = normalize_ip(ip)
    row = db.scalar(select(DemoIpRule).where(DemoIpRule.ip == address))
    changed = row is None or row.policy != policy or row.reason != reason
    if row is None:
        row = DemoIpRule(ip=address, policy=policy, reason=reason)
    if changed:
        row.policy = policy
        row.reason = reason
        row.changed_by = getattr(user, "id", None)
        db.add(row)
        db.flush()
    return row.to_dict(), changed


def remove_rule(db: Session, ip: str, policy: str) -> bool:
    address = normalize_ip(ip)
    row = db.scalar(
        select(DemoIpRule).where(
            DemoIpRule.ip == address,
            DemoIpRule.policy == policy,
        )
    )
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True


def clear_rules(db: Session) -> int:
    rows = db.scalars(select(DemoIpRule)).all()
    for row in rows:
        db.delete(row)
    db.flush()
    return len(rows)
