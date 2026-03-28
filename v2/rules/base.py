"""
Python SIEM Rules – Base Classes
==================================
Rules in BlackStarSIEM v2 are **pure Python classes**, not YARAL/JSON
configuration files.  This gives analysts full programming-language
expressiveness: complex state, regex, ML model calls, external lookups, etc.

Every rule:
  1. Inherits from ``SIEMRule``.
  2. Implements ``evaluate(event) -> Optional[Detection]``.
  3. Returns a ``Detection`` dataclass when the event matches, or ``None``.

Rules can also maintain state (e.g. sliding-window counters) by storing
data in instance attributes.  Stateful rules should implement ``reset()``
to clear counters between scan windows.

Usage::

    rule = SSHBruteForceRule()
    for event in events:
        detection = rule.evaluate(event)
        if detection:
            print(detection)
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Severity enum (mirrors schemas.Severity to avoid circular imports)
# ---------------------------------------------------------------------------
class Severity(IntEnum):
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        mapping = {s.label(): s for s in cls}
        return mapping.get(label.lower(), cls.INFORMATIONAL)


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------
@dataclass
class Detection:
    """Represents a rule match (an alert/finding)."""

    rule_id: str
    rule_name: str
    severity: Severity
    event: Dict[str, Any]
    description: str
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    confidence: float = 1.0           # 0.0 – 1.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.label(),
            "severity_id": int(self.severity),
            "description": self.description,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "tags": self.tags,
            "event_id": self.event.get("event_id", ""),
            "event_time": self.event.get("time", ""),
            "event_message": self.event.get("message", ""),
        }


# ---------------------------------------------------------------------------
# Abstract base rule
# ---------------------------------------------------------------------------
class SIEMRule(ABC):
    """Abstract base class for all BlackStarSIEM v2 detection rules.

    Subclasses must implement ``evaluate()``.  All other functionality
    is provided here: field extraction helpers, pattern matching, etc.
    """

    # Subclasses should override these class-level attributes
    rule_id: str = "RULE-000"
    name: str = "Unnamed Rule"
    description: str = ""
    severity: Severity = Severity.MEDIUM
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    tags: List[str] = []  # subclasses replace with their own list literal

    def __init__(self) -> None:
        self.enabled: bool = True
        # Each instance gets its own copy so rule subclass lists don't share state
        self.tags = list(self.__class__.tags)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        """Evaluate *event* against this rule.

        Parameters
        ----------
        event : dict
            Flat security event dict (as produced by ``SecurityEvent.to_dict()``).

        Returns
        -------
        Detection | None
            ``Detection`` if the event matched the rule, ``None`` otherwise.
        """

    def reset(self) -> None:
        """Reset stateful counters.  Override in stateful rules."""

    # ------------------------------------------------------------------
    # Helper: build Detection from a matched event
    # ------------------------------------------------------------------

    def _detection(
        self,
        event: Dict[str, Any],
        description: str = "",
        severity: Optional[Severity] = None,
        confidence: float = 1.0,
    ) -> Detection:
        return Detection(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=severity or self.severity,
            event=event,
            description=description or self.description,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            mitre_technique_id=self.mitre_technique_id,
            confidence=confidence,
            tags=list(self.tags),
        )

    # ------------------------------------------------------------------
    # Field extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get(event: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Get a field from the flat event dict, with a default."""
        return event.get(key, default)

    @staticmethod
    def _get_str(event: Dict[str, Any], key: str, default: str = "") -> str:
        val = event.get(key)
        return str(val) if val is not None else default

    @staticmethod
    def _get_int(event: Dict[str, Any], key: str, default: int = 0) -> int:
        try:
            return int(event.get(key, default))
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # Condition helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_any(value: str, patterns: List[str]) -> bool:
        return value in patterns

    @staticmethod
    def _matches_regex(value: str, pattern: str) -> bool:
        return bool(re.search(pattern, value, re.IGNORECASE))

    @staticmethod
    def _contains(haystack: str, needle: str) -> bool:
        return needle.lower() in haystack.lower()


# ---------------------------------------------------------------------------
# Stateful base: sliding-window counter
# ---------------------------------------------------------------------------
class CounterRule(SIEMRule, ABC):
    """Base for rules that count events per key within a sliding window.

    The window is purely *count-based* (no time-based TTL in demo mode).
    Production deployments should override ``_key_for()`` and use a
    time-aware store (Redis, Flink state, etc.).
    """

    threshold: int = 5

    def __init__(self) -> None:
        super().__init__()
        self._counts: Dict[str, int] = {}

    def _increment(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    def reset(self) -> None:
        self._counts.clear()

    @abstractmethod
    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        """Return the grouping key for this event, or None to skip."""
