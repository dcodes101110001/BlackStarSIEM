"""
Authentication Detection Rules
================================
Detects authentication-based threats: brute force, credential stuffing,
privilege escalation, and account compromise indicators.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from v2.rules.base import CounterRule, Detection, SIEMRule, Severity

# OCSF class UID for authentication events
_AUTH = 3002

_ADMIN_ACCOUNTS: List[str] = ["root", "admin", "administrator", "SYSTEM", "sa"]


class BruteForceRule(CounterRule):
    """Detects brute-force login attacks.

    Triggers when the same source IP accumulates >= ``threshold`` failed
    authentication events.
    """

    rule_id = "AUTH-001"
    name = "SSH / Login Brute Force"
    description = "Multiple failed login attempts from a single source IP"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "Brute Force"
    mitre_technique_id = "T1110"
    tags = ["auth", "brute-force", "credential-access"]

    threshold: int = 5

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        if self._get_int(event, "class_uid") != _AUTH:
            return None
        if self._get_str(event, "status") != "failure":
            return None
        return self._get_str(event, "src_ip") or None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled:
            return None
        key = self._key_for(event)
        if key is None:
            return None
        count = self._increment(key)
        if count >= self.threshold:
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=(
                    f"Brute force from {key}: {count} failures"
                    + (f" (targeting '{user}')" if user else "")
                ),
            )
        return None


class AdminBruteForceRule(BruteForceRule):
    """Like BruteForceRule but specifically targets admin accounts – CRITICAL."""

    rule_id = "AUTH-002"
    name = "Admin Account Brute Force"
    description = "Brute force attack targeting a privileged/admin account"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1110.001"
    tags = ["auth", "brute-force", "admin", "critical"]

    threshold: int = 3   # lower threshold for admin accounts

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        base = super()._key_for(event)
        if base is None:
            return None
        user = self._get_str(event, "user_name").lower()
        if user in [a.lower() for a in _ADMIN_ACCOUNTS]:
            return f"admin:{base}"
        return None


class PrivilegeEscalationRule(SIEMRule):
    """Detects explicit privilege escalation events."""

    rule_id = "AUTH-003"
    name = "Privilege Escalation Attempt"
    description = "User attempting to gain elevated privileges"
    severity = Severity.CRITICAL
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "Exploitation for Privilege Escalation"
    mitre_technique_id = "T1068"
    tags = ["auth", "privilege-escalation", "critical"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _AUTH:
            return None
        action = self._get_str(event, "meta_action")
        sev = self._get_int(event, "severity_id")
        if "privilege_escalation" in action or sev >= int(Severity.CRITICAL):
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=f"Privilege escalation detected for user '{user}'",
            )
        return None


class MultiUserBruteForceRule(CounterRule):
    """Detects a single IP targeting multiple different user accounts.

    This is a credential-stuffing / user enumeration indicator.
    """

    rule_id = "AUTH-004"
    name = "Multi-User Credential Stuffing"
    description = "Single IP targeting multiple distinct user accounts"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "Credential Stuffing"
    mitre_technique_id = "T1110.004"
    tags = ["auth", "credential-stuffing", "enumeration"]

    threshold: int = 3   # number of distinct users

    def __init__(self) -> None:
        super().__init__()
        self._ip_users: Dict[str, set] = defaultdict(set)

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        if self._get_int(event, "class_uid") != _AUTH:
            return None
        if self._get_str(event, "status") != "failure":
            return None
        return self._get_str(event, "src_ip") or None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled:
            return None
        ip = self._key_for(event)
        if ip is None:
            return None
        user = self._get_str(event, "user_name")
        if user:
            self._ip_users[ip].add(user)
        if len(self._ip_users[ip]) >= self.threshold:
            return self._detection(
                event,
                description=(
                    f"Credential stuffing from {ip}: "
                    f"{len(self._ip_users[ip])} different accounts targeted"
                ),
            )
        return None

    def reset(self) -> None:
        super().reset()
        self._ip_users.clear()


class AccountLockedRule(SIEMRule):
    """Alert when an account lockout is detected."""

    rule_id = "AUTH-005"
    name = "Account Lockout Detected"
    description = "User account has been locked after too many failures"
    severity = Severity.MEDIUM
    mitre_tactic = "Impact"
    mitre_technique = "Account Access Removal"
    mitre_technique_id = "T1531"
    tags = ["auth", "lockout"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _AUTH:
            return None
        action = self._get_str(event, "meta_action")
        if "account_locked" in action:
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=f"Account '{user}' locked out",
            )
        return None
