"""
Tests for BlackStarSIEM v2 – Python SIEM Rules
================================================
Tests cover:
  * Base abstractions (Detection, Severity, SIEMRule helpers)
  * Individual rule classes (network, auth, file, process)
  * Rule engine (registration, scanning, statistics)
  * Stateful rule counter behaviour
"""

import pytest

from v2.rules.base import Detection, Severity, CounterRule
from v2.rules.engine import RuleEngine, ScanReport
from v2.rules.network_rules import (
    C2BeaconingRule,
    FirewallBypassRule,
    LateralMovementRule,
    PortScanRule,
)
from v2.rules.auth_rules import (
    AccountLockedRule,
    AdminBruteForceRule,
    BruteForceRule,
    MultiUserBruteForceRule,
    PrivilegeEscalationRule,
)
from v2.rules.file_rules import (
    DataExfiltrationRule,
    MalwareStagingRule,
    SensitiveFileAccessRule,
)
from v2.rules.process_rules import (
    LOLBinAbuseRule,
    PrivilegedProcessRule,
    ProcessInjectionRule,
    SuspiciousChildProcessRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _net_event(**kwargs):
    base = {
        "event_id": "test-001",
        "class_uid": 4001,
        "severity_id": 2,
        "severity": "low",
        "status": "unknown",
        "message": "test net event",
        "src_ip": "192.168.1.10",
        "src_port": 54321,
        "dst_ip": "8.8.8.8",
        "dst_port": 80,
        "meta_action": "connection",
    }
    base.update(kwargs)
    return base


def _auth_event(**kwargs):
    base = {
        "event_id": "test-002",
        "class_uid": 3002,
        "severity_id": 3,
        "severity": "medium",
        "status": "failure",
        "message": "login failure",
        "src_ip": "10.0.0.5",
        "user_name": "bob",
        "meta_action": "login_failure",
    }
    base.update(kwargs)
    return base


def _file_event(**kwargs):
    base = {
        "event_id": "test-003",
        "class_uid": 1001,
        "severity_id": 4,
        "severity": "high",
        "status": "success",
        "message": "file access",
        "file_path": "/etc/passwd",
        "file_name": "passwd",
        "user_name": "alice",
        "meta_action": "sensitive_access",
    }
    base.update(kwargs)
    return base


def _proc_event(**kwargs):
    base = {
        "event_id": "test-004",
        "class_uid": 1007,
        "severity_id": 5,
        "severity": "critical",
        "status": "success",
        "message": "process created",
        "proc_name": "mimikatz",
        "proc_pid": 1234,
        "proc_cmd_line": "mimikatz.exe sekurlsa::logonpasswords",
        "proc_parent": "cmd",
        "user_name": "admin",
        "meta_action": "inject",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------

class TestSeverity:
    def test_labels(self):
        assert Severity.INFORMATIONAL.label() == "informational"
        assert Severity.CRITICAL.label() == "critical"

    def test_from_label_roundtrip(self):
        for sev in Severity:
            assert Severity.from_label(sev.label()) == sev

    def test_from_label_unknown_defaults_to_informational(self):
        assert Severity.from_label("unknown_xyz") == Severity.INFORMATIONAL

    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestDetection:
    def test_to_dict_has_required_fields(self):
        d = Detection(
            rule_id="TEST-001",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            event={"event_id": "abc", "message": "test"},
            description="A test detection",
            mitre_tactic="Discovery",
            mitre_technique_id="T1046",
        )
        d_dict = d.to_dict()
        assert d_dict["rule_id"] == "TEST-001"
        assert d_dict["severity"] == "high"
        assert d_dict["severity_id"] == 4
        assert "timestamp" in d_dict


# ---------------------------------------------------------------------------
# Network Rules
# ---------------------------------------------------------------------------

class TestPortScanRule:
    def test_no_detection_below_threshold(self):
        rule = PortScanRule()
        rule.threshold = 5
        for port in [22, 80, 443, 8080]:
            result = rule.evaluate(_net_event(dst_port=port))
            assert result is None

    def test_detects_at_threshold(self):
        rule = PortScanRule()
        rule.threshold = 5
        for port in [22, 80, 443, 8080, 3306]:
            result = rule.evaluate(_net_event(dst_port=port))
        assert result is not None
        assert result.rule_id == "NET-001"
        assert result.severity == Severity.MEDIUM

    def test_counts_per_src_ip(self):
        rule = PortScanRule()
        rule.threshold = 3
        # IP A does 3 ports
        for port in [22, 80, 443]:
            rule.evaluate(_net_event(src_ip="192.168.1.1", dst_port=port))
        # IP B only 2 ports – no detection
        result_b = None
        for port in [22, 80]:
            result_b = rule.evaluate(_net_event(src_ip="192.168.1.2", dst_port=port))
        assert result_b is None

    def test_reset_clears_counts(self):
        rule = PortScanRule()
        rule.threshold = 3
        for port in [22, 80, 443]:
            rule.evaluate(_net_event(dst_port=port))
        rule.reset()
        # After reset, 3 new ports should not fire
        result = None
        for port in [8080, 3306, 5432]:
            result = rule.evaluate(_net_event(dst_port=port))
        # The 3rd port hits threshold again after reset
        assert result is not None

    def test_disabled_rule_returns_none(self):
        rule = PortScanRule()
        rule.threshold = 1
        rule.enabled = False
        result = rule.evaluate(_net_event(dst_port=22))
        assert result is None

    def test_ignores_non_network_events(self):
        rule = PortScanRule()
        rule.threshold = 1
        result = rule.evaluate(_auth_event())
        assert result is None


class TestLateralMovementRule:
    def test_detects_lateral_movement(self):
        rule = LateralMovementRule()
        event = _net_event(
            src_ip="192.168.1.5",
            dst_ip="192.168.1.20",
            dst_port=445,
            meta_action="lateral_movement",
            severity_id=5,
        )
        result = rule.evaluate(event)
        assert result is not None
        assert result.rule_id == "NET-002"

    def test_no_detect_external_to_external(self):
        rule = LateralMovementRule()
        event = _net_event(
            src_ip="8.8.8.8",
            dst_ip="1.1.1.1",
            dst_port=445,
            meta_action="lateral_movement",
        )
        result = rule.evaluate(event)
        assert result is None


class TestFirewallBypassRule:
    def test_detects_firewall_block(self):
        rule = FirewallBypassRule()
        event = _net_event(meta_action="firewall_block", severity_id=4)
        result = rule.evaluate(event)
        assert result is not None

    def test_no_detect_low_severity_firewall(self):
        rule = FirewallBypassRule()
        event = _net_event(meta_action="firewall_block", severity_id=2)
        result = rule.evaluate(event)
        assert result is None


class TestC2BeaconingRule:
    def test_detects_beaconing_at_threshold(self):
        rule = C2BeaconingRule()
        rule.threshold = 3
        result = None
        for _ in range(3):
            result = rule.evaluate(_net_event(src_ip="192.168.1.5", dst_ip="203.0.113.1"))
        assert result is not None
        assert result.rule_id == "NET-004"

    def test_no_detect_before_threshold(self):
        rule = C2BeaconingRule()
        rule.threshold = 5
        result = None
        for _ in range(4):
            result = rule.evaluate(_net_event(src_ip="192.168.1.5", dst_ip="203.0.113.1"))
        assert result is None

    def test_no_detect_internal_to_internal(self):
        rule = C2BeaconingRule()
        rule.threshold = 1
        result = rule.evaluate(_net_event(src_ip="192.168.1.5", dst_ip="192.168.1.6"))
        assert result is None


# ---------------------------------------------------------------------------
# Auth Rules
# ---------------------------------------------------------------------------

class TestBruteForceRule:
    def test_no_detect_below_threshold(self):
        rule = BruteForceRule()
        rule.threshold = 5
        for _ in range(4):
            result = rule.evaluate(_auth_event())
        assert result is None

    def test_detects_at_threshold(self):
        rule = BruteForceRule()
        rule.threshold = 5
        result = None
        for _ in range(5):
            result = rule.evaluate(_auth_event())
        assert result is not None
        assert result.rule_id == "AUTH-001"

    def test_ignores_successful_auth(self):
        rule = BruteForceRule()
        rule.threshold = 1
        result = rule.evaluate(_auth_event(status="success"))
        assert result is None


class TestAdminBruteForceRule:
    def test_detects_admin_attack(self):
        rule = AdminBruteForceRule()
        result = None
        for _ in range(3):
            result = rule.evaluate(_auth_event(user_name="root"))
        assert result is not None
        assert result.rule_id == "AUTH-002"
        assert result.severity == Severity.CRITICAL

    def test_ignores_normal_user(self):
        rule = AdminBruteForceRule()
        result = None
        for _ in range(10):
            result = rule.evaluate(_auth_event(user_name="bob"))
        assert result is None


class TestPrivilegeEscalationRule:
    def test_detects_escalation(self):
        rule = PrivilegeEscalationRule()
        result = rule.evaluate(_auth_event(meta_action="privilege_escalation", severity_id=5))
        assert result is not None
        assert result.rule_id == "AUTH-003"


class TestMultiUserBruteForceRule:
    def test_detects_multiple_users(self):
        rule = MultiUserBruteForceRule()
        rule.threshold = 3
        users = ["alice", "bob", "carol"]
        result = None
        for user in users:
            result = rule.evaluate(_auth_event(user_name=user))
        assert result is not None
        assert result.rule_id == "AUTH-004"

    def test_same_user_not_counted_twice(self):
        rule = MultiUserBruteForceRule()
        rule.threshold = 3
        result = None
        for _ in range(5):
            result = rule.evaluate(_auth_event(user_name="alice"))
        # Only 1 unique user – should not fire
        assert result is None


class TestAccountLockedRule:
    def test_detects_lockout(self):
        rule = AccountLockedRule()
        result = rule.evaluate(_auth_event(meta_action="account_locked"))
        assert result is not None
        assert result.rule_id == "AUTH-005"

    def test_ignores_login_failure(self):
        rule = AccountLockedRule()
        result = rule.evaluate(_auth_event(meta_action="login_failure"))
        assert result is None


# ---------------------------------------------------------------------------
# File Rules
# ---------------------------------------------------------------------------

class TestSensitiveFileAccessRule:
    def test_detects_passwd(self):
        rule = SensitiveFileAccessRule()
        result = rule.evaluate(_file_event(file_path="/etc/passwd", meta_action="sensitive_access"))
        assert result is not None
        assert result.rule_id == "FILE-001"

    def test_ignores_normal_file(self):
        rule = SensitiveFileAccessRule()
        result = rule.evaluate(_file_event(file_path="/var/data/report.csv", meta_action="read"))
        assert result is None


class TestDataExfiltrationRule:
    def test_detects_at_threshold(self):
        rule = DataExfiltrationRule()
        rule.threshold = 3
        result = None
        for _ in range(3):
            result = rule.evaluate(_file_event(meta_action="exfiltration", user_name="alice"))
        assert result is not None
        assert result.rule_id == "FILE-002"


class TestMalwareStagingRule:
    def test_detects_write_to_tmp(self):
        rule = MalwareStagingRule()
        result = rule.evaluate(
            _file_event(file_path="/tmp/malware.sh", meta_action="write")
        )
        assert result is not None
        assert result.rule_id == "FILE-003"


# ---------------------------------------------------------------------------
# Process Rules
# ---------------------------------------------------------------------------

class TestProcessInjectionRule:
    def test_detects_mimikatz(self):
        rule = ProcessInjectionRule()
        result = rule.evaluate(
            _proc_event(proc_name="mimikatz", meta_action="inject")
        )
        assert result is not None
        assert result.rule_id == "PROC-001"

    def test_ignores_normal_process(self):
        rule = ProcessInjectionRule()
        result = rule.evaluate(
            _proc_event(proc_name="nginx", proc_cmd_line="nginx -g daemon off", meta_action="launch")
        )
        assert result is None


class TestLOLBinAbuseRule:
    def test_detects_encoded_powershell(self):
        rule = LOLBinAbuseRule()
        result = rule.evaluate(
            _proc_event(
                proc_name="powershell",
                proc_cmd_line="powershell -enc SQBtAHAAbwByAHQ=",
                meta_action="launch",
                severity_id=3,
                class_uid=1007,
            )
        )
        assert result is not None
        assert result.rule_id == "PROC-002"

    def test_no_detect_normal_powershell(self):
        rule = LOLBinAbuseRule()
        result = rule.evaluate(
            _proc_event(
                proc_name="powershell",
                proc_cmd_line="powershell Get-Process",
                meta_action="launch",
                severity_id=1,
                class_uid=1007,
            )
        )
        assert result is None


class TestPrivilegedProcessRule:
    def test_detects_high_severity(self):
        rule = PrivilegedProcessRule()
        result = rule.evaluate(
            _proc_event(meta_action="privilege_process", severity_id=4)
        )
        assert result is not None
        assert result.rule_id == "PROC-003"


class TestSuspiciousChildProcessRule:
    def test_detects_suspicious_child(self):
        rule = SuspiciousChildProcessRule()
        result = rule.evaluate(
            _proc_event(
                proc_name="cmd",
                proc_parent="winword",
                meta_action="suspicious_child",
            )
        )
        assert result is not None
        assert result.rule_id == "PROC-004"


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def setup_method(self):
        self.engine = RuleEngine()
        self.engine.register_defaults()

    def test_register_defaults_loads_rules(self):
        assert len(self.engine.rules) >= 16

    def test_enable_disable(self):
        self.engine.disable("NET-001")
        rule = self.engine.get_rule("NET-001")
        assert not rule.enabled
        self.engine.enable("NET-001")
        assert rule.enabled

    def test_unregister(self):
        count_before = len(self.engine.rules)
        removed = self.engine.unregister("NET-001")
        assert removed
        assert len(self.engine.rules) == count_before - 1

    def test_scan_event_returns_list(self):
        event = _net_event(meta_action="firewall_block", severity_id=5)
        result = self.engine.scan_event(event)
        assert isinstance(result, list)

    def test_scan_event_detects_firewall_block(self):
        event = _net_event(meta_action="firewall_block", severity_id=4)
        detections = self.engine.scan_event(event)
        rule_ids = [d.rule_id for d in detections]
        assert "NET-003" in rule_ids

    def test_scan_events_returns_report(self):
        events = [
            _auth_event() for _ in range(6)
        ]
        report = self.engine.scan_events(events)
        assert isinstance(report, ScanReport)
        assert report.total_events == 6
        assert report.total_detections >= 1

    def test_reset_state_clears_detections(self):
        events = [_auth_event() for _ in range(6)]
        self.engine.scan_events(events)
        self.engine.reset_state()
        assert len(self.engine.all_detections) == 0

    def test_rules_summary_returns_dataframe(self):
        df = self.engine.rules_summary()
        assert not df.empty
        assert "rule_id" in df.columns
        assert "severity" in df.columns

    def test_exception_in_rule_does_not_crash_engine(self):
        """A broken rule must not crash the engine."""
        from v2.rules.base import SIEMRule

        class BrokenRule(SIEMRule):
            rule_id = "BROKEN-001"
            name = "Broken Rule"

            def evaluate(self, event):
                raise RuntimeError("deliberate error")

        self.engine.register(BrokenRule())
        # Should not raise
        detections = self.engine.scan_event(_net_event())
        assert isinstance(detections, list)


class TestScanReport:
    def test_empty_report(self):
        report = ScanReport(total_events=0, detections=[])
        assert report.total_detections == 0
        assert report.critical_count == 0

    def test_counts_by_severity(self):
        detections = [
            Detection(
                rule_id="TEST-001",
                rule_name="T",
                severity=Severity.CRITICAL,
                event={},
                description="",
            ),
            Detection(
                rule_id="TEST-002",
                rule_name="T",
                severity=Severity.HIGH,
                event={},
                description="",
            ),
        ]
        report = ScanReport(total_events=10, detections=detections)
        assert report.critical_count == 1
        assert report.high_count == 1

    def test_to_dataframe(self):
        detection = Detection(
            rule_id="TEST-001",
            rule_name="Test",
            severity=Severity.MEDIUM,
            event={"event_id": "x"},
            description="test",
        )
        report = ScanReport(total_events=1, detections=[detection])
        df = report.to_dataframe()
        assert len(df) == 1
        assert "rule_id" in df.columns
