"""
Correlation Rules Engine
=========================
Allows analysts to combine multiple SIEM detection rules into higher-level
"correlation rules" that fire only when a specific combination or sequence of
individual rules has been triggered.

A correlation rule is a named, ordered stack of *steps*.  Each step references
either a pre-existing rule ID (e.g. ``"AUTH-001"``) or a custom field-match
condition.  Steps are joined by a logical operator:

- **AND** – the step *and* the previous step must both have produced a
  detection in the current detection set.
- **OR** – the step *or* the previous step is sufficient.
- **THEN** – the step's detection must appear *after* the previous step's
  detection (temporal sequence).

Usage::

    from v2.rules.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationStep,
        CorrelationOperator,
    )

    engine = CorrelationEngine()

    rule = CorrelationRule(
        correlation_id="CORR-001",
        name="Brute-Force then Lateral Movement",
        description="Auth brute-force followed by lateral movement",
        steps=[
            CorrelationStep(rule_id="AUTH-001", label="Brute Force"),
            CorrelationStep(rule_id="NET-002", label="Lateral Movement",
                            operator=CorrelationOperator.THEN),
        ],
    )
    engine.add_rule(rule)

    matches = engine.evaluate(detections)          # list of CorrelationMatch
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Operator
# ---------------------------------------------------------------------------

class CorrelationOperator(str, Enum):
    """Logical operator joining a step to the preceding step."""

    AND = "AND"   # Both the current *and* previous step must match
    OR = "OR"     # Either the current *or* previous step must match
    THEN = "THEN" # Current step must match *after* previous step (temporal)


# ---------------------------------------------------------------------------
# Step
# ---------------------------------------------------------------------------

@dataclass
class CorrelationStep:
    """One step in a correlation rule stack.

    Parameters
    ----------
    rule_id:
        ID of an existing SIEM rule (e.g. ``"AUTH-001"``).  Use
        ``"CUSTOM"`` together with *custom_condition* for ad-hoc matching.
    label:
        Human-readable name shown in the UI.
    operator:
        How this step combines with the *previous* step.  Ignored for the
        first step in a rule.
    custom_condition:
        Optional dict of ``{field: value}`` pairs used when *rule_id* is
        ``"CUSTOM"``.  A detection matches the custom condition if all
        pairs appear in ``detection.event``.
    """

    rule_id: str
    label: str = ""
    operator: CorrelationOperator = CorrelationOperator.AND
    custom_condition: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.rule_id


# ---------------------------------------------------------------------------
# Correlation Rule
# ---------------------------------------------------------------------------

@dataclass
class CorrelationRule:
    """A named, ordered stack of correlation steps.

    Parameters
    ----------
    correlation_id:
        Unique identifier (e.g. ``"CORR-001"``).
    name:
        Human-readable rule name.
    description:
        Optional description.
    steps:
        Ordered list of :class:`CorrelationStep` objects.
    enabled:
        Whether the rule is active.
    """

    correlation_id: str
    name: str
    description: str = ""
    steps: List[CorrelationStep] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "steps": [
                {
                    "rule_id": s.rule_id,
                    "label": s.label,
                    "operator": s.operator.value,
                    **(
                        {"custom_condition": getattr(s, "custom_condition", None)}
                        if getattr(s, "custom_condition", None) is not None
                        else {}
                    ),
                }
                for s in self.steps
            ],
        }


# ---------------------------------------------------------------------------
# Correlation Match
# ---------------------------------------------------------------------------

@dataclass
class CorrelationMatch:
    """Result when a correlation rule fires against a detection set.

    Parameters
    ----------
    correlation_id:
        ID of the correlation rule that matched.
    correlation_name:
        Name of the correlation rule.
    matched_rule_ids:
        Ordered list of individual rule IDs that contributed to the match.
    matched_detections:
        The individual :class:`~v2.rules.base.Detection` objects involved.
    timestamp:
        UTC ISO-8601 timestamp when the correlation was evaluated.
    """

    correlation_id: str
    correlation_name: str
    matched_rule_ids: List[str]
    matched_detections: List[Any]  # List[Detection] – avoids circular import
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "correlation_name": self.correlation_name,
            "matched_rule_ids": self.matched_rule_ids,
            "num_matched": len(self.matched_detections),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Evaluates a set of correlation rules against accumulated detections."""

    def __init__(self) -> None:
        self._rules: Dict[str, CorrelationRule] = {}

    # ------------------------------------------------------------------
    # Rule registry
    # ------------------------------------------------------------------

    def add_rule(self, rule: CorrelationRule) -> None:
        """Register (or replace) a correlation rule."""
        self._rules[rule.correlation_id] = rule
        logger.debug("Registered correlation rule: %s", rule.correlation_id)

    def remove_rule(self, correlation_id: str) -> bool:
        """Remove a correlation rule.  Returns True if it existed."""
        if correlation_id in self._rules:
            del self._rules[correlation_id]
            return True
        return False

    def get_rule(self, correlation_id: str) -> Optional[CorrelationRule]:
        return self._rules.get(correlation_id)

    @property
    def rules(self) -> List[CorrelationRule]:
        return list(self._rules.values())

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, detections: List[Any]) -> List[CorrelationMatch]:
        """Evaluate all enabled correlation rules against *detections*.

        Parameters
        ----------
        detections:
            List of :class:`~v2.rules.base.Detection` objects (typically
            from :meth:`~v2.rules.engine.RuleEngine.all_detections`).

        Returns
        -------
        list[CorrelationMatch]
            One entry for every correlation rule that fired.
        """
        matches: List[CorrelationMatch] = []
        # Index detections by rule_id for O(1) look-up
        by_rule: Dict[str, List[Any]] = {}
        for d in detections:
            by_rule.setdefault(d.rule_id, []).append(d)

        for rule in self._rules.values():
            if not rule.enabled or not rule.steps:
                continue
            try:
                match = self._evaluate_rule(rule, detections, by_rule)
                if match:
                    matches.append(match)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Correlation rule %s raised an exception: %s",
                    rule.correlation_id,
                    exc,
                )
        return matches

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_rule(
        self,
        rule: CorrelationRule,
        all_detections: List[Any],
        by_rule: Dict[str, List[Any]],
    ) -> Optional[CorrelationMatch]:
        """Dispatch to the appropriate evaluation strategy."""
        uses_then = any(
            s.operator == CorrelationOperator.THEN
            for s in rule.steps[1:]
        )
        if uses_then:
            return self._evaluate_then(rule, all_detections, by_rule)
        return self._evaluate_logical(rule, by_rule)

    def _matches_step(
        self,
        step: CorrelationStep,
        by_rule: Dict[str, List[Any]],
    ) -> List[Any]:
        """Return the detections that satisfy *step*."""
        if step.rule_id == "CUSTOM" and step.custom_condition:
            # Custom condition: match on event fields
            matches = []
            for dets in by_rule.values():
                for d in dets:
                    if all(
                        d.event.get(k) == v
                        for k, v in step.custom_condition.items()
                    ):
                        matches.append(d)
            return matches
        return list(by_rule.get(step.rule_id, []))

    def _evaluate_logical(
        self,
        rule: CorrelationRule,
        by_rule: Dict[str, List[Any]],
    ) -> Optional[CorrelationMatch]:
        """Evaluate AND / OR logic (no temporal ordering)."""
        steps = rule.steps
        matched_rule_ids: List[str] = []
        matched_dets: List[Any] = []

        # First step is always evaluated
        first_dets = self._matches_step(steps[0], by_rule)
        if first_dets:
            matched_rule_ids.append(steps[0].rule_id)
            matched_dets.extend(first_dets)

        for step in steps[1:]:
            step_dets = self._matches_step(step, by_rule)
            if step.operator == CorrelationOperator.AND:
                if not step_dets:
                    return None  # AND requires this step to be present
                if not matched_rule_ids:
                    # Previous AND chain broke – nothing matched yet
                    return None
                matched_rule_ids.append(step.rule_id)
                matched_dets.extend(step_dets)
            else:  # OR
                if step_dets:
                    matched_rule_ids.append(step.rule_id)
                    matched_dets.extend(step_dets)

        if not matched_rule_ids:
            return None

        return CorrelationMatch(
            correlation_id=rule.correlation_id,
            correlation_name=rule.name,
            matched_rule_ids=matched_rule_ids,
            matched_detections=matched_dets,
        )

    def _evaluate_then(
        self,
        rule: CorrelationRule,
        all_detections: List[Any],
        by_rule: Dict[str, List[Any]],
    ) -> Optional[CorrelationMatch]:
        """Evaluate THEN (temporal sequence) logic.

        Each step's detection must occur *at or after* the previous
        step's detection timestamp.
        """

        def _parse_ts(d: Any) -> datetime:
            try:
                ts = d.timestamp
                if ts.endswith("Z"):
                    ts = ts[:-1] + "+00:00"
                return datetime.fromisoformat(ts)
            except Exception:  # noqa: BLE001
                return datetime.min.replace(tzinfo=timezone.utc)

        steps = rule.steps
        last_ts = datetime.min.replace(tzinfo=timezone.utc)
        matched_rule_ids: List[str] = []
        matched_dets: List[Any] = []

        for step in steps:
            candidates = self._matches_step(step, by_rule)
            # Sort candidates by timestamp and take the earliest that is
            # >= last_ts
            candidates_sorted = sorted(candidates, key=_parse_ts)
            found: Optional[Any] = None
            for d in candidates_sorted:
                if _parse_ts(d) >= last_ts:
                    found = d
                    last_ts = _parse_ts(d)
                    break

            if found is None:
                # For THEN operators this breaks the chain
                op = step.operator
                if op == CorrelationOperator.THEN or step is steps[0]:
                    return None
                # OR step – allowed to be missing
            else:
                matched_rule_ids.append(step.rule_id)
                matched_dets.append(found)

        if not matched_rule_ids:
            return None

        return CorrelationMatch(
            correlation_id=rule.correlation_id,
            correlation_name=rule.name,
            matched_rule_ids=matched_rule_ids,
            matched_detections=matched_dets,
        )
