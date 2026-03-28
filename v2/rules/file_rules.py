"""
File Activity Detection Rules
==============================
Detects suspicious file-system operations: sensitive file access,
data exfiltration indicators, and malware-staging paths.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from v2.rules.base import CounterRule, Detection, SIEMRule, Severity

# OCSF class UID for file activity
_FILE = 1001

_SENSITIVE_PATHS: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh",
    "/home/",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.bash_history",
    "/var/log/auth.log",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Users\\",
    "ntds.dit",
    "lsass",
]

_STAGING_DIRS: List[str] = [
    "/tmp/",
    "/dev/shm/",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\",
    "AppData\\Roaming\\",
]


class SensitiveFileAccessRule(SIEMRule):
    """Triggers when a known sensitive file is read or written."""

    rule_id = "FILE-001"
    name = "Sensitive File Access"
    description = "Access to a known sensitive file path"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "OS Credential Dumping"
    mitre_technique_id = "T1003"
    tags = ["file", "sensitive", "credential-access"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _FILE:
            return None
        path = self._get_str(event, "file_path").lower()
        action = self._get_str(event, "meta_action")
        if not path or "sensitive" not in action:
            return None
        matched = next(
            (s for s in _SENSITIVE_PATHS if s.lower() in path), None
        )
        if matched:
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=(
                    f"Sensitive file accessed by '{user}': {path}"
                ),
            )
        return None


class DataExfiltrationRule(CounterRule):
    """Detects potential data exfiltration by counting file reads per user."""

    rule_id = "FILE-002"
    name = "Data Exfiltration Indicator"
    description = "Unusually high number of file reads from a single user"
    severity = Severity.CRITICAL
    mitre_tactic = "Exfiltration"
    mitre_technique = "Exfiltration Over Alternative Protocol"
    mitre_technique_id = "T1048"
    tags = ["file", "exfiltration", "data-loss"]

    threshold: int = 3

    def _key_for(self, event: Dict[str, Any]) -> Optional[str]:
        if self._get_int(event, "class_uid") != _FILE:
            return None
        action = self._get_str(event, "meta_action")
        if "exfil" not in action:
            return None
        return self._get_str(event, "user_name") or None

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled:
            return None
        key = self._key_for(event)
        if key is None:
            return None
        count = self._increment(key)
        if count >= self.threshold:
            return self._detection(
                event,
                description=(
                    f"Possible data exfiltration by '{key}': "
                    f"{count} suspicious file accesses"
                ),
            )
        return None


class MalwareStagingRule(SIEMRule):
    """Detects file writes to known staging / malware-drop directories."""

    rule_id = "FILE-003"
    name = "Malware Staging Directory Write"
    description = "File written to a known malware staging location"
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Masquerading"
    mitre_technique_id = "T1036"
    tags = ["file", "malware", "staging"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _FILE:
            return None
        path = self._get_str(event, "file_path")
        action = self._get_str(event, "meta_action")
        if "write" not in action and "delete" not in action:
            return None
        matched = next(
            (d for d in _STAGING_DIRS if d.lower() in path.lower()), None
        )
        if matched:
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=(
                    f"File written to staging dir by '{user}': {path}"
                ),
            )
        return None


class ExecutableDropRule(SIEMRule):
    """Detects executable files written to suspicious locations."""

    rule_id = "FILE-004"
    name = "Executable Dropped to Suspicious Location"
    description = "Binary or script written to a world-writable or temp directory"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "User Execution"
    mitre_technique_id = "T1204"
    tags = ["file", "executable", "drop"]

    _EXE_EXTENSIONS = re.compile(
        r"\.(exe|dll|sh|bat|ps1|py|elf|so)$", re.IGNORECASE
    )

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _FILE:
            return None
        path = self._get_str(event, "file_path")
        action = self._get_str(event, "meta_action")
        if "write" not in action:
            return None
        is_exec = bool(self._EXE_EXTENSIONS.search(path))
        in_staging = any(d.lower() in path.lower() for d in _STAGING_DIRS)
        if is_exec and in_staging:
            user = self._get_str(event, "user_name")
            return self._detection(
                event,
                description=(
                    f"Executable '{path}' written to staging location by '{user}'"
                ),
            )
        return None
