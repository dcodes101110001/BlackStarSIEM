"""
BlackStarSIEM v2 - Central Configuration
=========================================
Centralised settings for the entire data pipeline.  Values are read first
from environment variables so that the same code works in Docker, CI and
local demo mode without any code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Kafka / Confluent
# ---------------------------------------------------------------------------
@dataclass
class KafkaConfig:
    bootstrap_servers: str = field(
        default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    )
    schema_registry_url: str = field(
        default_factory=lambda: os.getenv(
            "SCHEMA_REGISTRY_URL", "http://localhost:8081"
        )
    )
    security_protocol: str = field(
        default_factory=lambda: os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    )
    # Confluent Cloud SASL settings (optional)
    sasl_mechanism: str = field(
        default_factory=lambda: os.getenv("KAFKA_SASL_MECHANISM", "")
    )
    sasl_username: str = field(
        default_factory=lambda: os.getenv("KAFKA_SASL_USERNAME", "")
    )
    sasl_password: str = field(
        default_factory=lambda: os.getenv("KAFKA_SASL_PASSWORD", "")
    )

    # Topic names
    network_topic: str = "security.network"
    auth_topic: str = "security.auth"
    file_topic: str = "security.file"
    process_topic: str = "security.process"
    alerts_topic: str = "security.alerts"

    @property
    def all_topics(self) -> List[str]:
        return [
            self.network_topic,
            self.auth_topic,
            self.file_topic,
            self.process_topic,
        ]

    def producer_config(self) -> dict:
        cfg: dict = {
            "bootstrap.servers": self.bootstrap_servers,
            "acks": "all",
            "enable.idempotence": True,
        }
        self._add_sasl(cfg)
        return cfg

    def consumer_config(self, group_id: str = "siem-consumer") -> dict:
        cfg: dict = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
        self._add_sasl(cfg)
        return cfg

    def _add_sasl(self, cfg: dict) -> None:
        if self.sasl_mechanism:
            cfg["security.protocol"] = "SASL_SSL"
            cfg["sasl.mechanisms"] = self.sasl_mechanism
            cfg["sasl.username"] = self.sasl_username
            cfg["sasl.password"] = self.sasl_password


# ---------------------------------------------------------------------------
# Iceberg / Storage
# ---------------------------------------------------------------------------
@dataclass
class IcebergConfig:
    catalog_type: str = field(
        default_factory=lambda: os.getenv("ICEBERG_CATALOG_TYPE", "sql")
    )
    # Local SQLite catalog URI for demo mode; swap for a Hive / AWS Glue URI
    catalog_uri: str = field(
        default_factory=lambda: os.getenv(
            "ICEBERG_CATALOG_URI", "sqlite:///./blackstar_catalog.db"
        )
    )
    warehouse_path: str = field(
        default_factory=lambda: os.getenv(
            "ICEBERG_WAREHOUSE", "./blackstar_warehouse"
        )
    )
    namespace: str = "security"
    table_name: str = "events"

    # S3 / MinIO settings (used when catalog_type != "sql")
    s3_endpoint: str = field(
        default_factory=lambda: os.getenv("S3_ENDPOINT", "http://localhost:9000")
    )
    s3_access_key: str = field(
        default_factory=lambda: os.getenv("S3_ACCESS_KEY", "minioadmin")
    )
    s3_secret_key: str = field(
        default_factory=lambda: os.getenv("S3_SECRET_KEY", "minioadmin")
    )

    @property
    def full_table_name(self) -> str:
        return f"{self.namespace}.{self.table_name}"


# ---------------------------------------------------------------------------
# Spark
# ---------------------------------------------------------------------------
@dataclass
class SparkConfig:
    app_name: str = "BlackStarSIEM-v2"
    master: str = field(
        default_factory=lambda: os.getenv("SPARK_MASTER", "local[*]")
    )
    # Iceberg JAR - users must provide this or use the Docker image
    iceberg_jar: str = field(
        default_factory=lambda: os.getenv(
            "SPARK_ICEBERG_JAR",
            "org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.5.0",
        )
    )


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
@dataclass
class AppConfig:
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    iceberg: IcebergConfig = field(default_factory=IcebergConfig)
    spark: SparkConfig = field(default_factory=SparkConfig)
    demo_mode: bool = field(
        default_factory=lambda: os.getenv("DEMO_MODE", "true").lower() == "true"
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )


# Singleton
settings = AppConfig()
