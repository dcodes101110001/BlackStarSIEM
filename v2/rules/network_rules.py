"""
Network Security Detection Rules
=================================
Detects network-based threats: port scans, lateral movement, C2 beaconing,
firewall bypass attempts, and suspicious outbound connections.

All rules are pure Python classes that can be configured by modifying their
class attributes before instantiation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from v2.rules.base import CounterRule, Detection, SIEMRule, Severity

# OCSF class UID for network activity
_NET = 4001


class PortScanRule(CounterRule):
    """Detects horizontal port scanning from a single source IP.

    Triggers when the same source IP connects to >= ``threshold`` distinct
    destination ports within the scanning window.
    """

    rule_id = "NET-001"
    name = "Port Scan Detection"
    description = "Source IP probing multiple destination ports (horizontal scan)"
    severity = Severity.MEDIUM
    mitre_tactic = "Discovery"
    mitre_technique = "Network Service Discovery"
    mitre_technique_id = "T1046"
    tags = ["network", "reconnaissance", "scan"]

    threshold: int = 5

    def __init__(self) -> None:
        super().__init__()
        # src_ip → set of dst_ports seen
        self._port_sets: Dict[str, Set[int]] = defaultdict(set)

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        if self._get_int(event, "class_uid") != _NET:
            return None
        src = self._get_str(event, "src_ip")
        return src if src else None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _NET:
            return None
        src_ip = self._get_str(event, "src_ip")
        dst_port = self._get_int(event, "dst_port")
        if not src_ip or not dst_port:
            return None
        self._port_sets[src_ip].add(dst_port)
        if len(self._port_sets[src_ip]) >= self.threshold:
            return self._detection(
                event,
                description=(
                    f"Port scan from {src_ip}: "
                    f"{len(self._port_sets[src_ip])} unique ports probed"
                ),
            )
        return None

    def reset(self) -> None:
        super().reset()
        self._port_sets.clear()


class LateralMovementRule(SIEMRule):
    """Detects potential lateral movement.

    Looks for internal-to-internal traffic on high-value ports (SMB, RDP,
    WinRM, SSH) from non-server source IPs.
    """

    rule_id = "NET-002"
    name = "Lateral Movement Detection"
    description = "Internal host connecting to sensitive admin ports on other internal hosts"
    severity = Severity.HIGH
    mitre_tactic = "Lateral Movement"
    mitre_technique = "Remote Services"
    mitre_technique_id = "T1021"
    tags = ["network", "lateral-movement", "internal"]

    _LATERAL_PORTS: List[int] = [22, 445, 3389, 5985, 5986, 135, 139]
    _INTERNAL_PREFIXES: List[str] = ["192.168.", "10.", "172.16.", "172.17.", "172.18."]

    def _is_internal(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self._INTERNAL_PREFIXES)

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _NET:
            return None
        src_ip = self._get_str(event, "src_ip")
        dst_ip = self._get_str(event, "dst_ip")
        dst_port = self._get_int(event, "dst_port")
        action = self._get_str(event, "meta_action")

        if (
            src_ip
            and dst_ip
            and src_ip != dst_ip
            and self._is_internal(src_ip)
            and self._is_internal(dst_ip)
            and dst_port in self._LATERAL_PORTS
            and "lateral" in action
        ):
            return self._detection(
                event,
                description=(
                    f"Lateral movement: {src_ip} → {dst_ip}:{dst_port}"
                ),
            )
        return None


class FirewallBypassRule(SIEMRule):
    """Triggers on firewall block events with HIGH or CRITICAL severity."""

    rule_id = "NET-003"
    name = "Firewall Block / Bypass Attempt"
    description = "Traffic blocked by firewall – possible bypass attempt"
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Impair Defenses"
    mitre_technique_id = "T1562"
    tags = ["network", "firewall", "defense-evasion"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _NET:
            return None
        action = self._get_str(event, "meta_action")
        sev = self._get_int(event, "severity_id")
        if "firewall" in action and sev >= int(Severity.HIGH):
            return self._detection(event)
        return None


class C2BeaconingRule(CounterRule):
    """Detect repeated outbound connections to the same external IP (beaconing).

    Threshold: >= ``threshold`` connections from the same internal source to
    the same external destination.
    """

    rule_id = "NET-004"
    name = "C2 Beaconing Suspect"
    description = "Internal host making repeated connections to the same external IP"
    severity = Severity.HIGH
    mitre_tactic = "Command and Control"
    mitre_technique = "Application Layer Protocol"
    mitre_technique_id = "T1071"
    tags = ["network", "c2", "beaconing"]

    threshold: int = 10
    _INTERNAL_PREFIXES: List[str] = ["192.168.", "10.", "172."]

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        if self._get_int(event, "class_uid") != _NET:
            return None
        src = self._get_str(event, "src_ip")
        dst = self._get_str(event, "dst_ip")
        if not src or not dst:
            return None
        # Only internal → external
        is_src_internal = any(src.startswith(p) for p in self._INTERNAL_PREFIXES)
        is_dst_internal = any(dst.startswith(p) for p in self._INTERNAL_PREFIXES)
        if is_src_internal and not is_dst_internal:
            return f"{src}→{dst}"
        return None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled:
            return None
        key = self._key_for(event)
        if key is None:
            return None
        count = self._increment(key)
        if count == self.threshold:
            src, dst = key.split("→")
            return self._detection(
                event,
                description=(
                    f"Beaconing detected: {src} → {dst} "
                    f"({count} repeated connections)"
                ),
            )
        return None
