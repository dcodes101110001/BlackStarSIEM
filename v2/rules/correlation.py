"""
Correlation Rules Engine for BlackStarSIEM v2
===============================================
Allows users to stack multiple SIEM detection rules sequentially with
logical operators (AND / OR) to build compound threat-detection scenarios.

A *correlation rule* chains N individual SIEM rules. The chain is
evaluated against **all detections produced by the base rule engine**
for a given pipeline run.

Example::

    rule = CorrelationRule(
        name="Brute Force → Privilege Escalation",
        description="SSH brute-force followed by priv-esc on same host",
        stages=[
            CorrelationStage(rule_id="AUTH-001", label="Brute Force"),
            CorrelationStage(rule_id="AUTH-003", label="Privilege Escalation"),
        ],
        operator=LogicOperator.AND,
        severity=CorrelationSeverity.CRITICAL,
    )
    hits = rule.evaluate(detections)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from v2.rules.base import Detection, Severity


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class LogicOperator(str, Enum):
    """Logical operator applied across the stages in a correlation rule."""
    AND = "AND"
    OR = "OR"


class CorrelationSeverity(str, Enum):
    """Severity labels for a triggered correlation alert."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def to_severity(self) -> Severity:
        return Severity.from_label(self.value)


# ---------------------------------------------------------------------------
# Stage – one rule in the chain
# ---------------------------------------------------------------------------

@dataclass
class CorrelationStage:
    """A single step in a correlation rule chain.

    Parameters
    ----------
    rule_id : str
        The ID of the underlying SIEM rule (e.g. ``"AUTH-001"``).
    label : str
        Human-readable label displayed in the UI (defaults to *rule_id*).
    negate : bool
        When ``True`` the stage requires that this rule did **NOT** fire.
    """

    rule_id: str
    label: str = ""
    negate: bool = False

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.rule_id

    def matches(self, detections: List[Detection]) -> bool:
        """Return True if this stage's condition is satisfied."""
        fired = any(d.rule_id == self.rule_id for d in detections)
        return (not fired) if self.negate else fired


# ---------------------------------------------------------------------------
# Correlation Rule
# ---------------------------------------------------------------------------

@dataclass
class CorrelationRule:
    """A compound detection rule composed of sequential stages.

    Parameters
    ----------
    name : str
        Human-readable name for the correlation rule.
    description : str
        Description of what the rule detects.
    stages : list[CorrelationStage]
        Ordered list of SIEM rule stages to evaluate.
    operator : LogicOperator
        ``AND`` – all stages must match.
        ``OR``  – at least one stage must match.
    severity : CorrelationSeverity
        Alert severity when the rule fires.
    mitre_tactic : str
        MITRE ATT&CK tactic associated with this chain.
    mitre_technique_id : str
        MITRE technique identifier (e.g. ``"T1110"``).
    tags : list[str]
        Arbitrary tags for filtering/grouping.
    enabled : bool
        When ``False`` the rule is skipped during evaluation.
    rule_id : str
        Auto-generated UUID if not provided.
    """

    name: str
    description: str = ""
    stages: List[CorrelationStage] = field(default_factory=list)
    operator: LogicOperator = LogicOperator.AND
    severity: CorrelationSeverity = CorrelationSeverity.HIGH
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    rule_id: str = field(default_factory=lambda: f"CORR-{uuid.uuid4().hex[:6].upper()}")

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, detections: List[Detection]) -> Optional[CorrelationAlert]:
        """Evaluate the rule against a list of base detections.

        Parameters
        ----------
        detections : list[Detection]
            Detections produced by the base ``RuleEngine`` for a pipeline run.

        Returns
        -------
        CorrelationAlert | None
            ``CorrelationAlert`` if the rule fires, ``None`` otherwise.
        """
        if not self.enabled or not self.stages:
            return None

        if self.operator == LogicOperator.AND:
            fired = all(stage.matches(detections) for stage in self.stages)
        else:  # OR
            fired = any(stage.matches(detections) for stage in self.stages)

        if not fired:
            return None

        matched_detections = [
            d for d in detections
            if any(d.rule_id == s.rule_id for s in self.stages if not s.negate)
        ]

        return CorrelationAlert(
            correlation_rule_id=self.rule_id,
            correlation_rule_name=self.name,
            description=self.description,
            severity=self.severity.to_severity(),
            operator=self.operator,
            matched_detections=matched_detections,
            mitre_tactic=self.mitre_tactic,
            mitre_technique_id=self.mitre_technique_id,
            tags=list(self.tags),
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "operator": self.operator.value,
            "severity": self.severity.value,
            "stages": [
                {"rule_id": s.rule_id, "label": s.label, "negate": s.negate}
                for s in self.stages
            ],
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "tags": self.tags,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelationRule":
        stages = [
            CorrelationStage(
                rule_id=s["rule_id"],
                label=s.get("label", s["rule_id"]),
                negate=s.get("negate", False),
            )
            for s in data.get("stages", [])
        ]
        return cls(
            rule_id=data.get("rule_id", f"CORR-{uuid.uuid4().hex[:6].upper()}"),
            name=data["name"],
            description=data.get("description", ""),
            stages=stages,
            operator=LogicOperator(data.get("operator", "AND")),
            severity=CorrelationSeverity(data.get("severity", "high")),
            mitre_tactic=data.get("mitre_tactic", ""),
            mitre_technique_id=data.get("mitre_technique_id", ""),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
        )


# ---------------------------------------------------------------------------
# Correlation Alert
# ---------------------------------------------------------------------------

@dataclass
class CorrelationAlert:
    """A triggered correlation rule result."""

    correlation_rule_id: str
    correlation_rule_name: str
    description: str
    severity: Severity
    operator: LogicOperator
    matched_detections: List[Detection]
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_rule_id": self.correlation_rule_id,
            "correlation_rule_name": self.correlation_rule_name,
            "description": self.description,
            "severity": self.severity.label(),
            "severity_id": int(self.severity),
            "operator": self.operator.value,
            "matched_rule_ids": [d.rule_id for d in self.matched_detections],
            "matched_count": len(self.matched_detections),
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Manages and evaluates correlation rules against base detections.

    Usage::

        engine = CorrelationEngine()
        engine.add_rule(rule)
        alerts = engine.evaluate(detections)
    """

    # Predefined library of common correlation rules
    PREDEFINED: List[Dict[str, Any]] = [
        {
            "name": "Brute Force → Privilege Escalation",
            "description": (
                "Credential brute-force attack followed by privilege escalation – "
                "classic account takeover chain."
            ),
            "stages": [
                {"rule_id": "AUTH-001", "label": "SSH Brute Force"},
                {"rule_id": "AUTH-003", "label": "Privilege Escalation"},
            ],
            "operator": "AND",
            "severity": "critical",
            "mitre_tactic": "Credential Access → Privilege Escalation",
            "mitre_technique_id": "T1110 → T1068",
            "tags": ["account-takeover", "lateral-movement"],
        },
        {
            "name": "Port Scan → Lateral Movement",
            "description": (
                "Internal reconnaissance followed by lateral movement – "
                "attacker mapping the network then pivoting."
            ),
            "stages": [
                {"rule_id": "NET-001", "label": "Port Scan"},
                {"rule_id": "NET-002", "label": "Lateral Movement"},
            ],
            "operator": "AND",
            "severity": "high",
            "mitre_tactic": "Discovery → Lateral Movement",
            "mitre_technique_id": "T1046 → T1021",
            "tags": ["reconnaissance", "lateral-movement"],
        },
        {
            "name": "Malware Staging → Data Exfiltration",
            "description": (
                "Malware written to a staging directory followed by data exfiltration – "
                "ransomware / APT double-extortion pattern."
            ),
            "stages": [
                {"rule_id": "FILE-003", "label": "Malware Staging"},
                {"rule_id": "FILE-002", "label": "Data Exfiltration"},
            ],
            "operator": "AND",
            "severity": "critical",
            "mitre_tactic": "Defense Evasion → Exfiltration",
            "mitre_technique_id": "T1036 → T1048",
            "tags": ["ransomware", "exfiltration"],
        },
        {
            "name": "Process Injection OR LOLBin Abuse",
            "description": (
                "Process injection or living-off-the-land binary abuse detected – "
                "either technique indicates possible post-exploitation activity."
            ),
            "stages": [
                {"rule_id": "PROC-001", "label": "Process Injection"},
                {"rule_id": "PROC-002", "label": "LOLBin Abuse"},
            ],
            "operator": "OR",
            "severity": "high",
            "mitre_tactic": "Defense Evasion / Execution",
            "mitre_technique_id": "T1055 / T1059",
            "tags": ["post-exploitation"],
        },
        {
            "name": "C2 Beaconing → Firewall Bypass",
            "description": (
                "Outbound C2 beaconing combined with a firewall bypass attempt – "
                "active exfiltration or C2 tunnel setup."
            ),
            "stages": [
                {"rule_id": "NET-004", "label": "C2 Beaconing"},
                {"rule_id": "NET-003", "label": "Firewall Bypass Attempt"},
            ],
            "operator": "AND",
            "severity": "critical",
            "mitre_tactic": "Command and Control → Defense Evasion",
            "mitre_technique_id": "T1071 → T1562",
            "tags": ["c2", "defense-evasion"],
        },
    ]

    def __init__(self) -> None:
        self._rules: List[CorrelationRule] = []

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule to the engine."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by its ID. Returns True if found and removed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < before

    def update_rule(self, updated: CorrelationRule) -> bool:
        """Replace the rule with the same rule_id. Returns True if found."""
        for i, r in enumerate(self._rules):
            if r.rule_id == updated.rule_id:
                self._rules[i] = updated
                return True
        return False

    def move_rule(self, rule_id: str, direction: int) -> None:
        """Move a rule up (-1) or down (+1) in the ordered list."""
        idx = next((i for i, r in enumerate(self._rules) if r.rule_id == rule_id), None)
        if idx is None:
            return
        new_idx = idx + direction
        if 0 <= new_idx < len(self._rules):
            self._rules[idx], self._rules[new_idx] = self._rules[new_idx], self._rules[idx]

    @property
    def rules(self) -> List[CorrelationRule]:
        return list(self._rules)

    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        return next((r for r in self._rules if r.rule_id == rule_id), None)

    def load_predefined(self) -> None:
        """Load all predefined correlation rules."""
        for rule_data in self.PREDEFINED:
            self.add_rule(CorrelationRule.from_dict(rule_data))

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, detections: List[Detection]) -> List[CorrelationAlert]:
        """Evaluate all enabled correlation rules against a detection list."""
        alerts: List[CorrelationAlert] = []
        for rule in self._rules:
            alert = rule.evaluate(detections)
            if alert:
                alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules if r.enabled),
            "disabled_rules": sum(1 for r in self._rules if not r.enabled),
        }
