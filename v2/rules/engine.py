"""
Python SIEM Rule Engine
========================
Orchestrates all registered ``SIEMRule`` instances against a stream of
security events.  The engine is the core of BlackStarSIEM v2's detection
layer.

Key responsibilities:
  1. Register / unregister rules at runtime.
  2. Evaluate each incoming event against all enabled rules.
  3. Accumulate ``Detection`` objects (alerts).
  4. Provide summary statistics for the dashboard.

Usage::

    from v2.rules.engine import RuleEngine
    from v2.rules.network_rules import PortScanRule, LateralMovementRule
    from v2.rules.auth_rules import BruteForceRule

    engine = RuleEngine()
    engine.register_defaults()

    detections = engine.scan_event(event_dict)
    report = engine.scan_events(event_list)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Type

import pandas as pd

from v2.rules.base import Detection, SIEMRule, Severity

logger = logging.getLogger(__name__)


class RuleEngine:
    """Manages and executes Python SIEM detection rules."""

    def __init__(self) -> None:
        self._rules: Dict[str, SIEMRule] = {}
        self._detections: List[Detection] = []

    # ------------------------------------------------------------------
    # Rule registry
    # ------------------------------------------------------------------

    def register(self, rule: SIEMRule) -> None:
        """Register a rule instance."""
        self._rules[rule.rule_id] = rule
        logger.debug("Registered rule: %s (%s)", rule.rule_id, rule.name)

    def register_class(self, rule_cls: Type[SIEMRule]) -> None:
        """Instantiate *rule_cls* and register it."""
        self.register(rule_cls())

    def register_defaults(self) -> None:
        """Register all built-in rules with their default configurations."""
        from v2.rules.auth_rules import (
            AccountLockedRule,
            AdminBruteForceRule,
            BruteForceRule,
            MultiUserBruteForceRule,
            PrivilegeEscalationRule,
        )
        from v2.rules.file_rules import (
            DataExfiltrationRule,
            ExecutableDropRule,
            MalwareStagingRule,
            SensitiveFileAccessRule,
        )
        from v2.rules.network_rules import (
            C2BeaconingRule,
            FirewallBypassRule,
            LateralMovementRule,
            PortScanRule,
        )
        from v2.rules.process_rules import (
            LOLBinAbuseRule,
            PrivilegedProcessRule,
            ProcessInjectionRule,
            SuspiciousChildProcessRule,
        )

        for cls in [
            # Network
            PortScanRule,
            LateralMovementRule,
            FirewallBypassRule,
            C2BeaconingRule,
            # Auth
            BruteForceRule,
            AdminBruteForceRule,
            PrivilegeEscalationRule,
            MultiUserBruteForceRule,
            AccountLockedRule,
            # File
            SensitiveFileAccessRule,
            DataExfiltrationRule,
            MalwareStagingRule,
            ExecutableDropRule,
            # Process
            ProcessInjectionRule,
            LOLBinAbuseRule,
            PrivilegedProcessRule,
            SuspiciousChildProcessRule,
        ]:
            self.register_class(cls)

        logger.info("Registered %d default rules", len(self._rules))

    def unregister(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def enable(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True

    def disable(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False

    @property
    def rules(self) -> List[SIEMRule]:
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[SIEMRule]:
        return self._rules.get(rule_id)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_event(self, event: Dict[str, Any]) -> List[Detection]:
        """Evaluate *event* against all enabled rules."""
        hits: List[Detection] = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            try:
                detection = rule.evaluate(event)
                if detection:
                    hits.append(detection)
                    self._detections.append(detection)
            except Exception as exc:  # noqa: BLE001
                logger.error("Rule %s raised an exception: %s", rule.rule_id, exc)
        return hits

    def scan_events(self, events: List[Dict[str, Any]]) -> "ScanReport":
        """Scan a list of events and return a ``ScanReport``."""
        all_detections: List[Detection] = []
        for event in events:
            all_detections.extend(self.scan_event(event))
        return ScanReport(
            total_events=len(events),
            detections=all_detections,
        )

    def reset_state(self) -> None:
        """Reset all stateful rule counters and clear accumulated detections."""
        for rule in self._rules.values():
            rule.reset()
        self._detections.clear()
        logger.debug("Rule engine state reset")

    @property
    def all_detections(self) -> List[Detection]:
        return list(self._detections)

    def clear_detections(self) -> None:
        self._detections.clear()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def rules_summary(self) -> pd.DataFrame:
        rows = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity.label(),
                "severity_id": int(r.severity),
                "enabled": r.enabled,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique_id": r.mitre_technique_id,
                "tags": ", ".join(r.tags),
            }
            for r in self._rules.values()
        ]
        return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Scan Report
# ---------------------------------------------------------------------------

class ScanReport:
    """Summary of a bulk scan operation."""

    def __init__(self, total_events: int, detections: List[Detection]) -> None:
        self.total_events = total_events
        self.detections = detections

    # ------------------------------------------------------------------
    # Quick accessors
    # ------------------------------------------------------------------

    @property
    def total_detections(self) -> int:
        return len(self.detections)

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for d in self.detections if d.severity == Severity.HIGH)

    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for d in self.detections:
            label = d.severity.label()
            counts[label] = counts.get(label, 0) + 1
        return counts

    def by_rule(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for d in self.detections:
            counts[d.rule_id] = counts.get(d.rule_id, 0) + 1
        return counts

    def to_dataframe(self) -> pd.DataFrame:
        if not self.detections:
            return pd.DataFrame()
        return pd.DataFrame([d.to_dict() for d in self.detections])

    def __repr__(self) -> str:
        return (
            f"ScanReport(events={self.total_events}, "
            f"detections={self.total_detections}, "
            f"critical={self.critical_count}, "
            f"high={self.high_count})"
        )
