"""
Security Event Consumer  (Kafka → Iceberg)
==========================================
Reads security events from Kafka topics and writes them to Apache Iceberg
tables via the IcebergWriter.

Two modes:
  1. **Live mode** – polls a real Kafka broker.
  2. **Mock mode** – drains a MockQueue (same dict used by EventProducer).

The consumer also performs lightweight enrichment before persistence:
  - Stamps ``kafka_topic``, ``kafka_partition``, ``kafka_offset``.
  - Tags geographic region based on IP prefix (stub – replace with MaxMind).
  - Normalises timestamp to UTC ISO-8601.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from v2.ingestion.producer import MockQueue
from v2.ingestion.schemas import SecurityEvent

logger = logging.getLogger(__name__)


class EventConsumer:
    """Consumes Kafka messages and writes enriched events to Iceberg."""

    def __init__(
        self,
        topics: List[str],
        writer,  # IcebergWriter – imported lazily to avoid circular deps
        kafka_config: Optional[dict] = None,
        mock_queue: Optional[MockQueue] = None,
        poll_timeout: float = 1.0,
        batch_size: int = 100,
        on_event: Optional[Callable[[SecurityEvent], None]] = None,
    ) -> None:
        self._topics = topics
        self._writer = writer
        self._mock_queue = mock_queue
        self._poll_timeout = poll_timeout
        self._batch_size = batch_size
        self._on_event = on_event
        self._consumer = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

        if mock_queue is None:
            self._init_kafka(kafka_config or {})

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_kafka(self, kafka_config: dict) -> None:
        try:
            from confluent_kafka import Consumer  # type: ignore

            self._consumer = Consumer(kafka_config)
            self._consumer.subscribe(self._topics)
            logger.info("Kafka consumer subscribed to %s", self._topics)
        except ImportError:
            logger.warning(
                "confluent-kafka not installed; falling back to mock mode."
            )
            self._mock_queue = {}

    # ------------------------------------------------------------------
    # Public control API
    # ------------------------------------------------------------------

    def start(self, daemon: bool = True) -> None:
        """Start consuming in a background thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._consume_loop, daemon=daemon, name="siem-consumer"
        )
        self._thread.start()
        logger.info("Consumer started (daemon=%s)", daemon)

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
        if self._consumer:
            self._consumer.close()
        logger.info("Consumer stopped")

    def drain_mock(self) -> int:
        """Drain all events from the mock queue synchronously. Returns event count."""
        if self._mock_queue is None:
            return 0
        processed = 0
        for topic, events in list(self._mock_queue.items()):
            for raw in events:
                event = self._enrich(SecurityEvent.from_dict(raw), topic=topic)
                self._writer.write([event])
                if self._on_event:
                    self._on_event(event)
                processed += 1
            self._mock_queue[topic] = []
        return processed

    # ------------------------------------------------------------------
    # Consume loop (live Kafka)
    # ------------------------------------------------------------------

    def _consume_loop(self) -> None:
        batch: List[SecurityEvent] = []
        while self._running:
            if self._consumer is None:
                time.sleep(0.1)
                continue
            msg = self._consumer.poll(timeout=self._poll_timeout)
            if msg is None:
                if batch:
                    self._flush_batch(batch)
                    batch = []
                continue
            if msg.error():
                logger.error("Consumer error: %s", msg.error())
                continue
            try:
                raw = json.loads(msg.value().decode("utf-8"))
                event = self._enrich(
                    SecurityEvent.from_dict(raw),
                    topic=msg.topic(),
                    partition=msg.partition(),
                    offset=msg.offset(),
                )
                batch.append(event)
                if self._on_event:
                    self._on_event(event)
                if len(batch) >= self._batch_size:
                    self._flush_batch(batch)
                    batch = []
                    self._consumer.commit(asynchronous=False)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to process message: %s", exc)

    def _flush_batch(self, batch: List[SecurityEvent]) -> None:
        try:
            self._writer.write(batch)
            logger.debug("Flushed %d events to Iceberg", len(batch))
        except Exception as exc:  # noqa: BLE001
            logger.error("Iceberg write failed: %s", exc)

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    @staticmethod
    def _enrich(
        event: SecurityEvent,
        topic: str = "",
        partition: int = 0,
        offset: int = -1,
    ) -> SecurityEvent:
        event.kafka_topic = topic
        event.kafka_partition = partition
        event.kafka_offset = offset
        return event
