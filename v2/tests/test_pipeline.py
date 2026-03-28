"""
Tests for BlackStarSIEM v2 – Ingestion Pipeline
=================================================
Tests cover:
  * SecurityEvent schema (creation, serialisation, round-trip)
  * SecurityEventSimulator (batch generation)
  * EventProducer mock mode
  * EventConsumer mock drain
  * IcebergWriter in-memory fallback
  * DuckDB analytics on in-memory data
"""

import pytest
import pandas as pd

from v2.ingestion.schemas import (
    EventClass,
    FileInfo,
    NetworkEndpoint,
    ProcessInfo,
    SecurityEvent,
    Severity,
    UserInfo,
)
from v2.ingestion.producer import EventProducer, MockQueue, SecurityEventSimulator
from v2.ingestion.consumer import EventConsumer
from v2.storage.writer import IcebergWriter
from v2.processing.duckdb_analytics import DuckDBAnalytics


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

class TestSecurityEvent:
    def test_creates_with_defaults(self):
        evt = SecurityEvent(
            class_uid=EventClass.NETWORK_ACTIVITY,
            category_uid=4,
            activity_id=1,
            severity_id=int(Severity.LOW),
            status="unknown",
            message="test event",
        )
        assert evt.event_id != ""
        assert evt.time != ""

    def test_to_dict_has_required_keys(self):
        evt = SecurityEvent(
            class_uid=EventClass.AUTHENTICATION,
            category_uid=3,
            activity_id=2,
            severity_id=int(Severity.HIGH),
            status="failure",
            message="login failed",
            src_endpoint=NetworkEndpoint(ip="10.0.0.1", port=22),
            user=UserInfo(name="root", is_admin=True),
        )
        d = evt.to_dict()
        assert d["class_uid"] == EventClass.AUTHENTICATION
        assert d["severity"] == "high"
        assert d["src_ip"] == "10.0.0.1"
        assert d["user_name"] == "root"
        assert d["user_is_admin"] is True

    def test_from_dict_roundtrip(self):
        evt = SecurityEvent(
            class_uid=EventClass.FILE_ACTIVITY,
            category_uid=1,
            activity_id=4,
            severity_id=int(Severity.MEDIUM),
            status="success",
            message="file read",
            file=FileInfo(path="/etc/passwd", name="passwd"),
            user=UserInfo(name="alice"),
        )
        d = evt.to_dict()
        evt2 = SecurityEvent.from_dict(d)
        assert evt2.class_uid == EventClass.FILE_ACTIVITY
        assert evt2.file is not None
        assert evt2.file.path == "/etc/passwd"
        assert evt2.user is not None
        assert evt2.user.name == "alice"

    def test_process_event_roundtrip(self):
        evt = SecurityEvent(
            class_uid=EventClass.PROCESS_ACTIVITY,
            category_uid=1,
            activity_id=7,
            severity_id=int(Severity.CRITICAL),
            status="success",
            message="suspicious process",
            process=ProcessInfo(name="mimikatz", pid=1234, cmd_line="mimikatz.exe"),
        )
        d = evt.to_dict()
        assert d["proc_name"] == "mimikatz"
        assert d["proc_pid"] == 1234

    def test_metadata_keys_prefixed(self):
        evt = SecurityEvent(
            class_uid=EventClass.NETWORK_ACTIVITY,
            category_uid=4,
            activity_id=1,
            severity_id=1,
            status="unknown",
            message="test",
            metadata={"action": "port_scan", "count": 5},
        )
        d = evt.to_dict()
        assert "meta_action" in d
        assert d["meta_action"] == "port_scan"


# ---------------------------------------------------------------------------
# Simulator tests
# ---------------------------------------------------------------------------

class TestSecurityEventSimulator:
    def setup_method(self):
        self.sim = SecurityEventSimulator(seed=42)

    def test_generate_network_event(self):
        evt = self.sim.network_event()
        assert evt.class_uid == EventClass.NETWORK_ACTIVITY
        assert evt.src_endpoint is not None
        assert evt.src_endpoint.ip != ""

    def test_generate_auth_event(self):
        evt = self.sim.auth_event()
        assert evt.class_uid == EventClass.AUTHENTICATION
        assert evt.user is not None
        assert evt.user.name != ""

    def test_generate_file_event(self):
        evt = self.sim.file_event()
        assert evt.class_uid == EventClass.FILE_ACTIVITY
        assert evt.file is not None

    def test_generate_process_event(self):
        evt = self.sim.process_event()
        assert evt.class_uid == EventClass.PROCESS_ACTIVITY
        assert evt.process is not None
        assert evt.process.pid > 0

    def test_batch_size(self):
        batch = self.sim.generate_batch(50)
        assert len(batch) == 50

    def test_batch_has_mixed_classes(self):
        batch = self.sim.generate_batch(200)
        class_uids = {e.class_uid for e in batch}
        # Should have at least 3 different event types
        assert len(class_uids) >= 3

    def test_deterministic_with_seed(self):
        sim1 = SecurityEventSimulator(seed=99)
        sim2 = SecurityEventSimulator(seed=99)
        batch1 = [e.to_dict() for e in sim1.generate_batch(10)]
        batch2 = [e.to_dict() for e in sim2.generate_batch(10)]
        # Messages should match (event_ids are random UUIDs, skip those)
        for b1, b2 in zip(batch1, batch2):
            assert b1["message"] == b2["message"]
            assert b1["class_uid"] == b2["class_uid"]


# ---------------------------------------------------------------------------
# Producer (mock mode) tests
# ---------------------------------------------------------------------------

class TestEventProducer:
    def test_mock_queue_populated(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        sim = SecurityEventSimulator(seed=1)
        event = sim.network_event()
        producer.produce(event)
        assert "security.network" in queue
        assert len(queue["security.network"]) == 1

    def test_topic_routing(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        sim = SecurityEventSimulator(seed=2)
        producer.produce(sim.network_event())
        producer.produce(sim.auth_event())
        producer.produce(sim.file_event())
        producer.produce(sim.process_event())
        assert "security.network" in queue
        assert "security.auth" in queue
        assert "security.file" in queue
        assert "security.process" in queue

    def test_event_dict_stored(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        sim = SecurityEventSimulator(seed=3)
        evt = sim.auth_event()
        producer.produce(evt)
        stored = queue["security.auth"][0]
        assert stored["class_uid"] == EventClass.AUTHENTICATION


# ---------------------------------------------------------------------------
# Consumer (mock mode) tests
# ---------------------------------------------------------------------------

class TestEventConsumer:
    def test_drain_mock_queue(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=5)
        # Put 10 events into queue
        for evt in sim.generate_batch(10):
            producer.produce(evt)
        total_queued = sum(len(v) for v in queue.values())
        assert total_queued == 10

        consumer = EventConsumer(
            topics=list(queue.keys()),
            writer=writer,
            mock_queue=queue,
        )
        processed = consumer.drain_mock()
        assert processed == 10

    def test_drain_writes_to_writer(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=6)
        for evt in sim.generate_batch(5):
            producer.produce(evt)

        consumer = EventConsumer(
            topics=list(queue.keys()),
            writer=writer,
            mock_queue=queue,
        )
        consumer.drain_mock()
        assert writer.event_count() == 5

    def test_on_event_callback_called(self):
        queue: MockQueue = {}
        producer = EventProducer(mock_queue=queue)
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=7)
        for evt in sim.generate_batch(3):
            producer.produce(evt)

        received = []
        consumer = EventConsumer(
            topics=list(queue.keys()),
            writer=writer,
            mock_queue=queue,
            on_event=received.append,
        )
        consumer.drain_mock()
        assert len(received) == 3


# ---------------------------------------------------------------------------
# IcebergWriter (in-memory fallback) tests
# ---------------------------------------------------------------------------

class TestIcebergWriter:
    def test_write_returns_count(self):
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=10)
        events = sim.generate_batch(5)
        count = writer.write(events)
        assert count == 5

    def test_empty_write(self):
        writer = IcebergWriter()
        count = writer.write([])
        assert count == 0

    def test_get_dataframe_returns_df(self):
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=11)
        writer.write(sim.generate_batch(20))
        df = writer.get_dataframe()
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 20
        assert "event_id" in df.columns
        assert "severity" in df.columns

    def test_event_count(self):
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=12)
        writer.write(sim.generate_batch(15))
        assert writer.event_count() == 15

    def test_memory_store_accessible(self):
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=13)
        events = sim.generate_batch(3)
        writer.write(events)
        assert len(writer.memory_store) == 3


# ---------------------------------------------------------------------------
# DuckDB Analytics tests
# ---------------------------------------------------------------------------

class TestDuckDBAnalytics:
    def setup_method(self):
        """Build a writer with sample data and register with DuckDB."""
        writer = IcebergWriter()
        sim = SecurityEventSimulator(seed=42)
        writer.write(sim.generate_batch(200))
        self.df = writer.get_dataframe()
        self.analytics = DuckDBAnalytics()
        self.analytics.connect()
        self.analytics.register_dataframe(self.df, "events")

    def teardown_method(self):
        self.analytics.close()

    def test_severity_distribution(self):
        df = self.analytics.severity_distribution()
        assert not df.empty
        assert "severity" in df.columns
        assert "count" in df.columns

    def test_top_source_ips(self):
        df = self.analytics.top_source_ips(n=5)
        assert len(df) <= 5
        assert "src_ip" in df.columns
        assert "event_count" in df.columns

    def test_class_distribution(self):
        df = self.analytics.class_distribution()
        assert not df.empty
        assert "class_uid" in df.columns

    def test_alert_summary(self):
        df = self.analytics.alert_summary()
        assert isinstance(df, pd.DataFrame)

    def test_failed_auth_by_user(self):
        df = self.analytics.failed_auth_by_user(threshold=1)
        assert isinstance(df, pd.DataFrame)

    def test_run_custom_sql(self):
        df = self.analytics.run_sql("SELECT COUNT(*) AS total FROM events")
        assert df.iloc[0]["total"] == 200

    def test_brute_force_candidates(self):
        df = self.analytics.brute_force_candidates(min_failures=1)
        assert isinstance(df, pd.DataFrame)

    def test_lateral_movement_candidates(self):
        df = self.analytics.lateral_movement_candidates()
        assert isinstance(df, pd.DataFrame)
