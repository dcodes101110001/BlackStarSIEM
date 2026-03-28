"""
Process Activity Detection Rules
==================================
Detects process-based threats: suspicious command lines, process injection,
living-off-the-land (LOLBin) abuse, and SYSTEM-spawned shells.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from v2.rules.base import Detection, SIEMRule, Severity

# OCSF class UID for process activity
_PROC = 1007


class ProcessInjectionRule(SIEMRule):
    """Detects known process injection tool names."""

    rule_id = "PROC-001"
    name = "Process Injection Tool Detected"
    description = "Known process injection or credential-dumping tool launched"
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "Process Injection"
    mitre_technique_id = "T1055"
    tags = ["process", "injection", "critical"]

    _INJECTION_TOOLS: List[str] = [
        "mimikatz", "meterpreter", "cobalt", "beacon",
        "empire", "metasploit", "shellcode",
    ]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _PROC:
            return None
        action = self._get_str(event, "meta_action")
        proc = self._get_str(event, "proc_name").lower()
        cmd = self._get_str(event, "proc_cmd_line").lower()
        if "inject" not in action and "suspicious" not in action:
            return None
        matched_tool = next(
            (t for t in self._INJECTION_TOOLS if t in proc or t in cmd), None
        )
        if matched_tool:
            return self._detection(
                event,
                description=(
                    f"Injection tool '{matched_tool}' detected: {proc}"
                ),
            )
        return None


class LOLBinAbuseRule(SIEMRule):
    """Detects Living-Off-the-Land binary abuse.

    LOLBins are legitimate system tools used for malicious purposes (e.g.
    powershell -enc, certutil -decode, wmic /format).
    """

    rule_id = "PROC-002"
    name = "LOLBin Abuse Detected"
    description = "Living-off-the-land binary used with suspicious arguments"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "Command and Scripting Interpreter"
    mitre_technique_id = "T1059"
    tags = ["process", "lolbin", "execution"]

    # (binary_name, suspicious_arg_pattern)
    _LOLBINS: List[tuple] = [
        ("powershell", r"-enc\b|-nop\b|-w hidden|-exec bypass"),
        ("certutil", r"-decode\b|-urlcache\b"),
        ("wmic", r"/format:"),
        ("regsvr32", r"/s\s+/n\s+/u"),
        ("mshta", r"vbscript:|javascript:"),
        ("bitsadmin", r"/transfer\b"),
        ("curl", r"-o\s+.*\.(exe|dll|bat|ps1)"),
        ("wget", r"-O\s+.*\.(exe|dll|bat|ps1)"),
    ]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _PROC:
            return None
        proc = self._get_str(event, "proc_name").lower()
        cmd = self._get_str(event, "proc_cmd_line").lower()
        for binary, pattern in self._LOLBINS:
            if binary in proc and re.search(pattern, cmd, re.IGNORECASE):
                return self._detection(
                    event,
                    description=(
                        f"LOLBin abuse: '{proc}' with suspicious args: '{cmd[:120]}'"
                    ),
                )
        return None


class PrivilegedProcessRule(SIEMRule):
    """Triggers when a new process is spawned by a SYSTEM/root-level parent."""

    rule_id = "PROC-003"
    name = "Privileged Process Creation"
    description = "High-privilege process spawned – possible post-exploitation"
    severity = Severity.HIGH
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "Create or Modify System Process"
    mitre_technique_id = "T1543"
    tags = ["process", "privilege", "post-exploitation"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _PROC:
            return None
        action = self._get_str(event, "meta_action")
        sev = self._get_int(event, "severity_id")
        if "privilege_process" in action or sev >= int(Severity.HIGH):
            proc = self._get_str(event, "proc_name")
            user = self._get_str(event, "user_name")
            parent = self._get_str(event, "proc_parent")
            return self._detection(
                event,
                description=(
                    f"Privileged process '{proc}' created"
                    + (f" by '{user}'" if user else "")
                    + (f" (parent: {parent})" if parent else "")
                ),
            )
        return None


class SuspiciousChildProcessRule(SIEMRule):
    """Detects when office/browser apps spawn unexpected child processes."""

    rule_id = "PROC-004"
    name = "Suspicious Child Process"
    description = "Office/browser application spawned a shell or interpreter"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "Exploitation for Client Execution"
    mitre_technique_id = "T1203"
    tags = ["process", "child-process", "office-macro"]

    _SUSPICIOUS_PARENTS: List[str] = [
        "winword", "excel", "outlook", "powerpnt",
        "chrome", "firefox", "msedge", "iexplore",
        "acrobat", "acrord32",
    ]
    _SUSPICIOUS_CHILDREN: List[str] = [
        "cmd", "powershell", "wscript", "cscript",
        "bash", "sh", "python", "nc", "ncat",
    ]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if not self.enabled or self._get_int(event, "class_uid") != _PROC:
            return None
        action = self._get_str(event, "meta_action")
        if "suspicious_child" not in action:
            return None
        proc = self._get_str(event, "proc_name").lower()
        parent = self._get_str(event, "proc_parent").lower()
        is_sus_parent = any(p in parent for p in self._SUSPICIOUS_PARENTS)
        is_sus_child = any(c in proc for c in self._SUSPICIOUS_CHILDREN)
        if is_sus_parent or is_sus_child:
            return self._detection(
                event,
                description=(
                    f"Suspicious child '{proc}' spawned from '{parent}'"
                ),
            )
        return None
