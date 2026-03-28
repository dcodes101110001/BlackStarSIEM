"""
Security Event Producer
========================
Produces security events to Kafka topics.

The producer supports two modes:
  1. **Live mode** – connects to a real Kafka broker (local Docker or Confluent Cloud).
  2. **Mock mode** – writes events directly to an in-memory queue so the rest
     of the pipeline can be exercised without a running Kafka cluster.

Usage (mock mode)::

    from v2.ingestion.producer import EventProducer, MockQueue

    queue: MockQueue = {}
    producer = EventProducer(mock_queue=queue)
    producer.produce(event)
    # events appear in queue[topic]

Usage (live mode)::

    producer = EventProducer()
    producer.produce(event)
    producer.flush()
"""

from __future__ import annotations

import json
import logging
import random
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from v2.ingestion.schemas import (
    EventClass,
    FileInfo,
    NetworkEndpoint,
    ProcessInfo,
    SecurityEvent,
    Severity,
    UserInfo,
)

logger = logging.getLogger(__name__)

# Type alias: maps topic → list of serialised event dicts
MockQueue = Dict[str, List[dict]]


class EventProducer:
    """Sends security events to Kafka topics (or a mock queue)."""

    def __init__(
        self,
        kafka_config: Optional[dict] = None,
        mock_queue: Optional[MockQueue] = None,
        on_delivery: Optional[Callable] = None,
    ) -> None:
        self._mock_queue = mock_queue
        self._on_delivery = on_delivery
        self._producer = None

        if mock_queue is None:
            self._init_kafka(kafka_config or {})

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_kafka(self, kafka_config: dict) -> None:
        try:
            from confluent_kafka import Producer  # type: ignore

            self._producer = Producer(kafka_config)
            logger.info("Kafka producer connected: %s", kafka_config.get("bootstrap.servers"))
        except ImportError:
            logger.warning(
                "confluent-kafka not installed; falling back to mock mode. "
                "Install with: pip install confluent-kafka"
            )
            self._mock_queue = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def produce(self, event: SecurityEvent) -> None:
        """Serialise and send *event* to the appropriate Kafka topic."""
        topic = self._topic_for(event)
        payload = json.dumps(event.to_dict()).encode("utf-8")

        if self._mock_queue is not None:
            self._mock_queue.setdefault(topic, []).append(event.to_dict())
            logger.debug("Mock-queued event %s → %s", event.event_id, topic)
            return

        self._producer.produce(  # type: ignore[union-attr]
            topic=topic,
            value=payload,
            key=event.event_id.encode("utf-8"),
            callback=self._on_delivery or self._default_delivery_report,
        )

    def flush(self, timeout: float = 10.0) -> None:
        if self._producer:
            self._producer.flush(timeout)

    def close(self) -> None:
        self.flush()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _topic_for(event: SecurityEvent) -> str:
        mapping = {
            EventClass.NETWORK_ACTIVITY: "security.network",
            EventClass.AUTHENTICATION: "security.auth",
            EventClass.FILE_ACTIVITY: "security.file",
            EventClass.PROCESS_ACTIVITY: "security.process",
        }
        return mapping.get(event.class_uid, "security.network")

    @staticmethod
    def _default_delivery_report(err, msg) -> None:
        if err:
            logger.error("Delivery failed for %s: %s", msg.key(), err)
        else:
            logger.debug(
                "Delivered %s to %s [%s]@%s",
                msg.key(),
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )


# ---------------------------------------------------------------------------
# Simulated event generator
# ---------------------------------------------------------------------------

class SecurityEventSimulator:
    """Generates realistic, randomised security events for demo / testing."""

    _NETWORK_ACTIONS = [
        ("port_scan", Severity.MEDIUM, "Port scan detected"),
        ("connection", Severity.INFORMATIONAL, "Outbound connection established"),
        ("dns_query", Severity.INFORMATIONAL, "DNS query"),
        ("firewall_block", Severity.HIGH, "Firewall blocked connection"),
        ("lateral_movement", Severity.CRITICAL, "Potential lateral movement detected"),
    ]

    _AUTH_ACTIONS = [
        ("login_success", Severity.INFORMATIONAL, "Successful login"),
        ("login_failure", Severity.MEDIUM, "Login failure"),
        ("brute_force", Severity.HIGH, "Multiple failed login attempts"),
        ("privilege_escalation", Severity.CRITICAL, "Privilege escalation attempt"),
        ("account_locked", Severity.MEDIUM, "Account locked after failures"),
    ]

    _FILE_ACTIONS = [
        ("read", Severity.INFORMATIONAL, "File read"),
        ("write", Severity.INFORMATIONAL, "File write"),
        ("delete", Severity.MEDIUM, "File deleted"),
        ("sensitive_access", Severity.HIGH, "Sensitive file accessed"),
        ("exfiltration", Severity.CRITICAL, "Possible data exfiltration"),
    ]

    _PROCESS_ACTIONS = [
        ("launch", Severity.INFORMATIONAL, "Process launched"),
        ("terminate", Severity.INFORMATIONAL, "Process terminated"),
        ("inject", Severity.CRITICAL, "Process injection detected"),
        ("privilege_process", Severity.HIGH, "Privileged process creation"),
        ("suspicious_child", Severity.HIGH, "Suspicious child process"),
    ]

    _SENSITIVE_FILES = [
        "/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa",
        "/var/log/auth.log", "C:\\Windows\\System32\\config\\SAM",
        "/home/user/.bash_history",
    ]

    _SUSPICIOUS_PROCS = ["nc", "ncat", "mimikatz", "meterpreter", "powershell -enc", "cmd /c"]
    _ADMIN_USERS = ["root", "admin", "administrator", "SYSTEM"]
    _NORMAL_USERS = [f"user{i}" for i in range(1, 20)]

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    def _ip(self) -> str:
        return ".".join(str(self._rng.randint(1, 254)) for _ in range(4))

    def _private_ip(self) -> str:
        return f"192.168.{self._rng.randint(0, 10)}.{self._rng.randint(1, 254)}"

    def network_event(self) -> SecurityEvent:
        action, sev, msg = self._rng.choice(self._NETWORK_ACTIONS)
        src_port = self._rng.randint(1024, 65535)
        dst_port = self._rng.choice([22, 80, 443, 3389, 8080, 445, 3306, 5432])
        return SecurityEvent(
            class_uid=EventClass.NETWORK_ACTIVITY,
            category_uid=4,
            activity_id=1,
            severity_id=int(sev),
            status="unknown",
            message=f"{msg} from {self._private_ip()}:{src_port}",
            src_endpoint=NetworkEndpoint(ip=self._private_ip(), port=src_port),
            dst_endpoint=NetworkEndpoint(ip=self._ip(), port=dst_port),
            metadata={"action": action},
        )

    def auth_event(self) -> SecurityEvent:
        action, sev, msg = self._rng.choice(self._AUTH_ACTIONS)
        user = self._rng.choice(
            self._ADMIN_USERS if self._rng.random() < 0.3 else self._NORMAL_USERS
        )
        status = "success" if "success" in action else "failure"
        return SecurityEvent(
            class_uid=EventClass.AUTHENTICATION,
            category_uid=3,
            activity_id=2 if status == "success" else 3,
            severity_id=int(sev),
            status=status,
            message=f"{msg}: user '{user}'",
            src_endpoint=NetworkEndpoint(ip=self._private_ip(), port=self._rng.randint(1024, 65535)),
            user=UserInfo(
                name=user,
                uid=str(self._rng.randint(0, 65535)),
                is_admin=user in self._ADMIN_USERS,
            ),
            metadata={"action": action},
        )

    def file_event(self) -> SecurityEvent:
        action, sev, msg = self._rng.choice(self._FILE_ACTIONS)
        path = self._rng.choice(self._SENSITIVE_FILES) if "sensitive" in action or "exfil" in action \
               else f"/var/data/file{self._rng.randint(1, 1000)}.dat"
        user = self._rng.choice(self._NORMAL_USERS + self._ADMIN_USERS)
        return SecurityEvent(
            class_uid=EventClass.FILE_ACTIVITY,
            category_uid=1,
            activity_id=4,
            severity_id=int(sev),
            status="success",
            message=f"{msg}: {path}",
            user=UserInfo(name=user, uid=str(self._rng.randint(0, 65535))),
            file=FileInfo(path=path, name=path.split("/")[-1]),
            metadata={"action": action},
        )

    def process_event(self) -> SecurityEvent:
        action, sev, msg = self._rng.choice(self._PROCESS_ACTIONS)
        proc_name = self._rng.choice(self._SUSPICIOUS_PROCS) if "inject" in action or "suspicious" in action \
                    else self._rng.choice(["bash", "python", "nginx", "sshd", "cron"])
        user = self._rng.choice(self._NORMAL_USERS + self._ADMIN_USERS)
        return SecurityEvent(
            class_uid=EventClass.PROCESS_ACTIVITY,
            category_uid=1,
            activity_id=7,
            severity_id=int(sev),
            status="success",
            message=f"{msg}: {proc_name}",
            user=UserInfo(name=user, uid=str(self._rng.randint(0, 65535))),
            process=ProcessInfo(
                name=proc_name,
                pid=self._rng.randint(100, 65000),
                cmd_line=f"{proc_name} --arg{self._rng.randint(1, 9)}",
                parent_name=self._rng.choice(["systemd", "bash", "sshd", "init"]),
            ),
            metadata={"action": action},
        )

    def generate_batch(self, count: int = 100) -> List[SecurityEvent]:
        """Return *count* mixed events."""
        generators = [
            self.network_event,
            self.auth_event,
            self.file_event,
            self.process_event,
        ]
        return [self._rng.choice(generators)() for _ in range(count)]
