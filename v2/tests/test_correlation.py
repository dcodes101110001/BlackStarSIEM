"""
Tests for the Correlation Rules Engine
=======================================
Covers:
  * CorrelationStep and CorrelationRule dataclasses
  * CorrelationEngine rule registration / removal
  * AND logic evaluation
  * OR logic evaluation
  * THEN (temporal sequence) logic evaluation
  * Custom condition matching
  * Disabled rules are skipped
  * Broken evaluation does not crash the engine
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from v2.rules.base import Detection, Severity
from v2.rules.correlation import (
    CorrelationEngine,
    CorrelationMatch,
    CorrelationOperator,
    CorrelationRule,
    CorrelationStep,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _det(rule_id: str, sev: Severity = Severity.MEDIUM, ts: str = "", event: dict | None = None) -> Detection:
    """Build a minimal Detection for testing."""
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()
    return Detection(
        rule_id=rule_id,
        rule_name=rule_id,
        severity=sev,
        event=event or {"event_id": "test"},
        description="test detection",
        timestamp=ts,
    )


def _ts(offset_seconds: int = 0) -> str:
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


# ---------------------------------------------------------------------------
# CorrelationStep
# ---------------------------------------------------------------------------

class TestCorrelationStep:
    def test_label_defaults_to_rule_id(self):
        step = CorrelationStep(rule_id="AUTH-001")
        assert step.label == "AUTH-001"

    def test_explicit_label(self):
        step = CorrelationStep(rule_id="AUTH-001", label="Brute Force")
        assert step.label == "Brute Force"

    def test_default_operator_is_and(self):
        step = CorrelationStep(rule_id="AUTH-001")
        assert step.operator == CorrelationOperator.AND


# ---------------------------------------------------------------------------
# CorrelationRule
# ---------------------------------------------------------------------------

class TestCorrelationRule:
    def test_to_dict_has_required_fields(self):
        rule = CorrelationRule(
            correlation_id="CORR-001",
            name="Test Rule",
            steps=[CorrelationStep(rule_id="AUTH-001")],
        )
        d = rule.to_dict()
        assert d["correlation_id"] == "CORR-001"
        assert d["name"] == "Test Rule"
        assert len(d["steps"]) == 1
        assert d["steps"][0]["rule_id"] == "AUTH-001"

    def test_enabled_defaults_to_true(self):
        rule = CorrelationRule(correlation_id="CORR-001", name="R")
        assert rule.enabled is True


# ---------------------------------------------------------------------------
# CorrelationEngine – registry
# ---------------------------------------------------------------------------

class TestCorrelationEngineRegistry:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_add_and_retrieve_rule(self):
        rule = CorrelationRule(correlation_id="CORR-001", name="R1")
        self.engine.add_rule(rule)
        assert self.engine.get_rule("CORR-001") is rule

    def test_rules_property(self):
        for i in range(3):
            self.engine.add_rule(CorrelationRule(correlation_id=f"CORR-{i:03d}", name=f"R{i}"))
        assert len(self.engine.rules) == 3

    def test_remove_existing_rule(self):
        self.engine.add_rule(CorrelationRule(correlation_id="CORR-001", name="R"))
        removed = self.engine.remove_rule("CORR-001")
        assert removed is True
        assert self.engine.get_rule("CORR-001") is None

    def test_remove_nonexistent_rule_returns_false(self):
        assert self.engine.remove_rule("DOES-NOT-EXIST") is False

    def test_replace_existing_rule(self):
        self.engine.add_rule(CorrelationRule(correlation_id="CORR-001", name="Old"))
        self.engine.add_rule(CorrelationRule(correlation_id="CORR-001", name="New"))
        assert self.engine.get_rule("CORR-001").name == "New"


# ---------------------------------------------------------------------------
# AND logic
# ---------------------------------------------------------------------------

class TestAndLogic:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_and_fires_when_both_present(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Brute + Lateral",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.AND),
            ],
        ))
        dets = [_det("AUTH-001"), _det("NET-002")]
        matches = self.engine.evaluate(dets)
        assert len(matches) == 1
        assert matches[0].correlation_id == "CORR-001"
        assert "AUTH-001" in matches[0].matched_rule_ids
        assert "NET-002" in matches[0].matched_rule_ids

    def test_and_does_not_fire_when_second_missing(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Brute + Lateral",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.AND),
            ],
        ))
        matches = self.engine.evaluate([_det("AUTH-001")])
        assert len(matches) == 0

    def test_and_does_not_fire_when_first_missing(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Brute + Lateral",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.AND),
            ],
        ))
        matches = self.engine.evaluate([_det("NET-002")])
        assert len(matches) == 0

    def test_three_step_and(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Three-step",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.AND),
                CorrelationStep(rule_id="FILE-001", operator=CorrelationOperator.AND),
            ],
        ))
        matches = self.engine.evaluate([_det("AUTH-001"), _det("NET-002"), _det("FILE-001")])
        assert len(matches) == 1

        # Missing the third step
        matches2 = self.engine.evaluate([_det("AUTH-001"), _det("NET-002")])
        assert len(matches2) == 0


# ---------------------------------------------------------------------------
# OR logic
# ---------------------------------------------------------------------------

class TestOrLogic:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_or_fires_when_only_first_present(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Auth OR Net",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.OR),
            ],
        ))
        matches = self.engine.evaluate([_det("AUTH-001")])
        assert len(matches) == 1

    def test_or_fires_when_only_second_present(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Auth OR Net",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.OR),
            ],
        ))
        # The first step has no match, but OR step does
        matches = self.engine.evaluate([_det("NET-002")])
        assert len(matches) == 1
        assert "NET-002" in matches[0].matched_rule_ids

    def test_or_fires_when_both_present(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Auth OR Net",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.OR),
            ],
        ))
        matches = self.engine.evaluate([_det("AUTH-001"), _det("NET-002")])
        assert len(matches) == 1
        assert len(matches[0].matched_rule_ids) == 2


# ---------------------------------------------------------------------------
# THEN logic (temporal sequence)
# ---------------------------------------------------------------------------

class TestThenLogic:
    def setup_method(self):
        self.engine = CorrelationEngine()
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-THEN",
            name="Brute then Lateral",
            steps=[
                CorrelationStep(rule_id="AUTH-001", label="Brute Force"),
                CorrelationStep(rule_id="NET-002", label="Lateral", operator=CorrelationOperator.THEN),
            ],
        ))

    def test_then_fires_in_correct_order(self):
        dets = [
            _det("AUTH-001", ts=_ts(0)),
            _det("NET-002", ts=_ts(60)),
        ]
        matches = self.engine.evaluate(dets)
        assert len(matches) == 1

    def test_then_does_not_fire_in_wrong_order(self):
        dets = [
            _det("NET-002", ts=_ts(0)),
            _det("AUTH-001", ts=_ts(60)),
        ]
        # NET-002 appears first but should be second
        matches = self.engine.evaluate(dets)
        assert len(matches) == 0

    def test_then_does_not_fire_when_second_missing(self):
        matches = self.engine.evaluate([_det("AUTH-001", ts=_ts(0))])
        assert len(matches) == 0

    def test_then_does_not_fire_when_first_missing(self):
        matches = self.engine.evaluate([_det("NET-002", ts=_ts(60))])
        assert len(matches) == 0

    def test_then_fires_with_same_timestamp(self):
        ts = _ts(0)
        dets = [_det("AUTH-001", ts=ts), _det("NET-002", ts=ts)]
        matches = self.engine.evaluate(dets)
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Custom condition
# ---------------------------------------------------------------------------

class TestCustomCondition:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_custom_condition_matches(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-CUSTOM",
            name="Custom",
            steps=[
                CorrelationStep(
                    rule_id="CUSTOM",
                    label="SSH login failure",
                    custom_condition={"meta_action": "login_failure", "user_name": "root"},
                ),
            ],
        ))
        det = _det("AUTH-001", event={"event_id": "x", "meta_action": "login_failure", "user_name": "root"})
        matches = self.engine.evaluate([det])
        assert len(matches) == 1

    def test_custom_condition_no_match_when_field_differs(self):
        self.engine.add_rule(CorrelationRule(
            correlation_id="CORR-CUSTOM",
            name="Custom",
            steps=[
                CorrelationStep(
                    rule_id="CUSTOM",
                    custom_condition={"meta_action": "login_failure", "user_name": "root"},
                ),
            ],
        ))
        det = _det("AUTH-001", event={"meta_action": "login_failure", "user_name": "alice"})
        matches = self.engine.evaluate([det])
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Disabled rules
# ---------------------------------------------------------------------------

class TestDisabledRules:
    def test_disabled_rule_is_skipped(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="Disabled",
            enabled=False,
            steps=[CorrelationStep(rule_id="AUTH-001")],
        ))
        matches = engine.evaluate([_det("AUTH-001")])
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Empty rules
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_rule_with_no_steps_does_not_fire(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(correlation_id="CORR-EMPTY", name="Empty"))
        matches = engine.evaluate([_det("AUTH-001")])
        assert len(matches) == 0

    def test_empty_detections_no_match(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="R",
            steps=[CorrelationStep(rule_id="AUTH-001")],
        ))
        matches = engine.evaluate([])
        assert len(matches) == 0

    def test_multiple_rules_evaluated_independently(self):
        engine = CorrelationEngine()
        engine.add_rule(CorrelationRule(
            correlation_id="CORR-001",
            name="R1",
            steps=[CorrelationStep(rule_id="AUTH-001")],
        ))
        engine.add_rule(CorrelationRule(
            correlation_id="CORR-002",
            name="R2",
            steps=[
                CorrelationStep(rule_id="AUTH-001"),
                CorrelationStep(rule_id="NET-002", operator=CorrelationOperator.AND),
            ],
        ))
        # Only AUTH-001 present – CORR-001 should fire, CORR-002 should not
        matches = engine.evaluate([_det("AUTH-001")])
        assert len(matches) == 1
        assert matches[0].correlation_id == "CORR-001"

    def test_broken_rule_does_not_crash_engine(self):
        """Exception during evaluation must not propagate."""
        engine = CorrelationEngine()

        class BadStep(CorrelationStep):
            def __init__(self):
                super().__init__(rule_id="BAD")

        # Patch a rule with a step whose rule_id causes a downstream error
        bad_rule = CorrelationRule(correlation_id="CORR-BAD", name="Bad")
        bad_rule.steps = [BadStep()]

        # Monkey-patch to force an exception
        original_matches_step = engine._matches_step

        def _raise(*_args, **_kwargs):
            raise RuntimeError("deliberate error")

        engine._matches_step = _raise
        engine.add_rule(bad_rule)
        # Should not raise
        matches = engine.evaluate([_det("AUTH-001")])
        assert isinstance(matches, list)

    def test_correlation_match_to_dict(self):
        match = CorrelationMatch(
            correlation_id="CORR-001",
            correlation_name="Test",
            matched_rule_ids=["AUTH-001", "NET-002"],
            matched_detections=[],
        )
        d = match.to_dict()
        assert d["correlation_id"] == "CORR-001"
        assert d["num_matched"] == 0
        assert "timestamp" in d
