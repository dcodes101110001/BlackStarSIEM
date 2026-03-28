"""
Tests for BlackStarSIEM v2 – Correlation Rules Engine
======================================================
Tests cover:
  * CorrelationStage matching logic (positive, negative, negate)
  * CorrelationRule AND / OR operators
  * CorrelationRule serialisation (to_dict / from_dict)
  * CorrelationEngine add / remove / update / move / evaluate
  * Predefined rules loading
"""

from v2.rules.base import Detection, Severity
from v2.rules.correlation import (
    CorrelationAlert,
    CorrelationEngine,
    CorrelationRule,
    CorrelationSeverity,
    CorrelationStage,
    LogicOperator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detection(rule_id: str, severity: Severity = Severity.HIGH) -> Detection:
    """Create a minimal Detection for testing."""
    return Detection(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        event={"event_id": "test-evt"},
        description="test detection",
    )


# ---------------------------------------------------------------------------
# CorrelationStage
# ---------------------------------------------------------------------------

class TestCorrelationStage:
    def test_matches_when_rule_fired(self):
        stage = CorrelationStage(rule_id="AUTH-001")
        detections = [_detection("AUTH-001")]
        assert stage.matches(detections) is True

    def test_no_match_when_rule_not_fired(self):
        stage = CorrelationStage(rule_id="AUTH-001")
        detections = [_detection("NET-001")]
        assert stage.matches(detections) is False

    def test_negate_matches_when_rule_not_fired(self):
        stage = CorrelationStage(rule_id="AUTH-001", negate=True)
        detections = [_detection("NET-001")]
        assert stage.matches(detections) is True

    def test_negate_no_match_when_rule_fired(self):
        stage = CorrelationStage(rule_id="AUTH-001", negate=True)
        detections = [_detection("AUTH-001")]
        assert stage.matches(detections) is False

    def test_empty_detections_no_match(self):
        stage = CorrelationStage(rule_id="AUTH-001")
        assert stage.matches([]) is False

    def test_label_defaults_to_rule_id(self):
        stage = CorrelationStage(rule_id="NET-002")
        assert stage.label == "NET-002"

    def test_custom_label_preserved(self):
        stage = CorrelationStage(rule_id="NET-002", label="Lateral Movement")
        assert stage.label == "Lateral Movement"


# ---------------------------------------------------------------------------
# CorrelationRule – AND operator
# ---------------------------------------------------------------------------

class TestCorrelationRuleAND:
    def _rule(self, stages=None):
        return CorrelationRule(
            name="Test AND Rule",
            stages=stages or [
                CorrelationStage(rule_id="AUTH-001"),
                CorrelationStage(rule_id="AUTH-003"),
            ],
            operator=LogicOperator.AND,
            severity=CorrelationSeverity.HIGH,
        )

    def test_fires_when_all_stages_match(self):
        rule = self._rule()
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        alert = rule.evaluate(detections)
        assert alert is not None
        assert isinstance(alert, CorrelationAlert)

    def test_no_fire_when_one_stage_missing(self):
        rule = self._rule()
        detections = [_detection("AUTH-001")]
        assert rule.evaluate(detections) is None

    def test_no_fire_when_no_detections(self):
        rule = self._rule()
        assert rule.evaluate([]) is None

    def test_no_fire_when_all_stages_missing(self):
        rule = self._rule()
        detections = [_detection("NET-001"), _detection("NET-002")]
        assert rule.evaluate(detections) is None

    def test_alert_has_correct_rule_name(self):
        rule = self._rule()
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        alert = rule.evaluate(detections)
        assert alert.correlation_rule_name == "Test AND Rule"

    def test_alert_severity_matches_rule(self):
        rule = self._rule()
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        alert = rule.evaluate(detections)
        assert alert.severity == Severity.HIGH

    def test_disabled_rule_does_not_fire(self):
        rule = self._rule()
        rule.enabled = False
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        assert rule.evaluate(detections) is None

    def test_empty_stages_does_not_fire(self):
        rule = CorrelationRule(name="Empty", stages=[], operator=LogicOperator.AND)
        assert rule.evaluate([_detection("AUTH-001")]) is None


# ---------------------------------------------------------------------------
# CorrelationRule – OR operator
# ---------------------------------------------------------------------------

class TestCorrelationRuleOR:
    def _rule(self):
        return CorrelationRule(
            name="Test OR Rule",
            stages=[
                CorrelationStage(rule_id="PROC-001"),
                CorrelationStage(rule_id="PROC-002"),
            ],
            operator=LogicOperator.OR,
            severity=CorrelationSeverity.HIGH,
        )

    def test_fires_when_first_stage_matches(self):
        rule = self._rule()
        assert rule.evaluate([_detection("PROC-001")]) is not None

    def test_fires_when_second_stage_matches(self):
        rule = self._rule()
        assert rule.evaluate([_detection("PROC-002")]) is not None

    def test_fires_when_both_stages_match(self):
        rule = self._rule()
        assert rule.evaluate([_detection("PROC-001"), _detection("PROC-002")]) is not None

    def test_no_fire_when_no_stage_matches(self):
        rule = self._rule()
        assert rule.evaluate([_detection("NET-001")]) is None

    def test_no_fire_when_empty(self):
        rule = self._rule()
        assert rule.evaluate([]) is None


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

class TestCorrelationRuleSerialisation:
    def test_round_trip(self):
        original = CorrelationRule(
            name="Round Trip Rule",
            description="testing serialisation",
            stages=[
                CorrelationStage(rule_id="AUTH-001", label="Brute Force"),
                CorrelationStage(rule_id="AUTH-003", label="Priv Esc", negate=False),
            ],
            operator=LogicOperator.AND,
            severity=CorrelationSeverity.CRITICAL,
            mitre_tactic="Credential Access",
            mitre_technique_id="T1110",
            tags=["test-tag"],
        )
        data = original.to_dict()
        restored = CorrelationRule.from_dict(data)

        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.operator == original.operator
        assert restored.severity == original.severity
        assert restored.mitre_tactic == original.mitre_tactic
        assert restored.mitre_technique_id == original.mitre_technique_id
        assert restored.tags == original.tags
        assert len(restored.stages) == len(original.stages)
        assert restored.stages[0].rule_id == "AUTH-001"
        assert restored.stages[0].label == "Brute Force"
        assert restored.stages[1].rule_id == "AUTH-003"

    def test_to_dict_keys(self):
        rule = CorrelationRule(name="Dict Test")
        d = rule.to_dict()
        for key in ("rule_id", "name", "description", "operator", "severity",
                    "stages", "mitre_tactic", "mitre_technique_id", "tags", "enabled"):
            assert key in d

    def test_from_dict_missing_optional_fields(self):
        minimal = {"name": "Minimal Rule", "stages": []}
        rule = CorrelationRule.from_dict(minimal)
        assert rule.name == "Minimal Rule"
        assert rule.stages == []
        assert rule.operator == LogicOperator.AND
        assert rule.severity == CorrelationSeverity.HIGH


# ---------------------------------------------------------------------------
# CorrelationAlert
# ---------------------------------------------------------------------------

class TestCorrelationAlert:
    def test_to_dict_structure(self):
        alert = CorrelationAlert(
            correlation_rule_id="CORR-001",
            correlation_rule_name="Test Alert",
            description="desc",
            severity=Severity.HIGH,
            operator=LogicOperator.AND,
            matched_detections=[_detection("AUTH-001")],
            mitre_tactic="Credential Access",
            mitre_technique_id="T1110",
            tags=["tag1"],
        )
        d = alert.to_dict()
        assert d["correlation_rule_id"] == "CORR-001"
        assert d["correlation_rule_name"] == "Test Alert"
        assert d["severity"] == "high"
        assert d["severity_id"] == 4
        assert d["operator"] == "AND"
        assert d["matched_rule_ids"] == ["AUTH-001"]
        assert d["matched_count"] == 1


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class TestCorrelationEngine:
    def _make_engine_with_rules(self):
        engine = CorrelationEngine()
        rule = CorrelationRule(
            name="Auth Chain",
            stages=[
                CorrelationStage(rule_id="AUTH-001"),
                CorrelationStage(rule_id="AUTH-003"),
            ],
            operator=LogicOperator.AND,
        )
        engine.add_rule(rule)
        return engine, rule

    def test_add_and_retrieve_rule(self):
        engine, rule = self._make_engine_with_rules()
        assert len(engine.rules) == 1
        assert engine.get_rule(rule.rule_id) is rule

    def test_remove_rule(self):
        engine, rule = self._make_engine_with_rules()
        removed = engine.remove_rule(rule.rule_id)
        assert removed is True
        assert len(engine.rules) == 0

    def test_remove_nonexistent_rule(self):
        engine = CorrelationEngine()
        assert engine.remove_rule("CORR-XXXX") is False

    def test_update_rule(self):
        engine, rule = self._make_engine_with_rules()
        updated = CorrelationRule(
            rule_id=rule.rule_id,
            name="Updated Name",
            stages=rule.stages,
        )
        result = engine.update_rule(updated)
        assert result is True
        assert engine.get_rule(rule.rule_id).name == "Updated Name"

    def test_evaluate_fires_matching_rule(self):
        engine, rule = self._make_engine_with_rules()
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        alerts = engine.evaluate(detections)
        assert len(alerts) == 1
        assert alerts[0].correlation_rule_name == "Auth Chain"

    def test_evaluate_does_not_fire_non_matching(self):
        engine, _ = self._make_engine_with_rules()
        detections = [_detection("NET-001")]
        assert engine.evaluate(detections) == []

    def test_evaluate_empty_detections(self):
        engine, _ = self._make_engine_with_rules()
        assert engine.evaluate([]) == []

    def test_multiple_rules_evaluated(self):
        engine = CorrelationEngine()
        r1 = CorrelationRule(
            name="Rule 1",
            stages=[CorrelationStage(rule_id="AUTH-001")],
            operator=LogicOperator.OR,
        )
        r2 = CorrelationRule(
            name="Rule 2",
            stages=[CorrelationStage(rule_id="NET-001")],
            operator=LogicOperator.OR,
        )
        engine.add_rule(r1)
        engine.add_rule(r2)
        detections = [_detection("AUTH-001"), _detection("NET-001")]
        alerts = engine.evaluate(detections)
        assert len(alerts) == 2

    def test_move_rule_up(self):
        engine = CorrelationEngine()
        r1 = CorrelationRule(name="Rule1", stages=[])
        r2 = CorrelationRule(name="Rule2", stages=[])
        engine.add_rule(r1)
        engine.add_rule(r2)
        engine.move_rule(r2.rule_id, -1)
        assert engine.rules[0].name == "Rule2"
        assert engine.rules[1].name == "Rule1"

    def test_move_rule_down(self):
        engine = CorrelationEngine()
        r1 = CorrelationRule(name="Rule1", stages=[])
        r2 = CorrelationRule(name="Rule2", stages=[])
        engine.add_rule(r1)
        engine.add_rule(r2)
        engine.move_rule(r1.rule_id, 1)
        assert engine.rules[0].name == "Rule2"
        assert engine.rules[1].name == "Rule1"

    def test_move_out_of_bounds_does_nothing(self):
        engine = CorrelationEngine()
        r1 = CorrelationRule(name="Rule1", stages=[])
        engine.add_rule(r1)
        engine.move_rule(r1.rule_id, -1)  # already at top
        assert engine.rules[0].name == "Rule1"

    def test_summary(self):
        engine, rule = self._make_engine_with_rules()
        s = engine.summary()
        assert s["total_rules"] == 1
        assert s["enabled_rules"] == 1
        assert s["disabled_rules"] == 0

    def test_summary_with_disabled_rule(self):
        engine, rule = self._make_engine_with_rules()
        rule.enabled = False
        s = engine.summary()
        assert s["enabled_rules"] == 0
        assert s["disabled_rules"] == 1


# ---------------------------------------------------------------------------
# Predefined rules
# ---------------------------------------------------------------------------

class TestPredefinedRules:
    def test_load_predefined_adds_rules(self):
        engine = CorrelationEngine()
        engine.load_predefined()
        assert len(engine.rules) == len(CorrelationEngine.PREDEFINED)

    def test_predefined_rules_have_names(self):
        engine = CorrelationEngine()
        engine.load_predefined()
        for rule in engine.rules:
            assert rule.name != ""

    def test_predefined_rules_have_stages(self):
        engine = CorrelationEngine()
        engine.load_predefined()
        for rule in engine.rules:
            assert len(rule.stages) >= 2

    def test_brute_force_priv_esc_fires(self):
        engine = CorrelationEngine()
        engine.load_predefined()
        detections = [_detection("AUTH-001"), _detection("AUTH-003")]
        alerts = engine.evaluate(detections)
        names = [a.correlation_rule_name for a in alerts]
        assert "Brute Force → Privilege Escalation" in names

    def test_or_rule_fires_on_single_match(self):
        engine = CorrelationEngine()
        engine.load_predefined()
        # Only PROC-001 fires – the OR rule should still trigger
        detections = [_detection("PROC-001")]
        alerts = engine.evaluate(detections)
        or_alerts = [a for a in alerts if a.operator == LogicOperator.OR]
        assert len(or_alerts) >= 1
