"""
Apache Spark Analytics
=======================
Provides PySpark-based analytics against the Iceberg security lake.

Reference architecture (Confluent blog):
  Kafka → Iceberg (via Tableflow) → Spark SQL analytics → Alerts

The ``SparkAnalytics`` class abstracts session management.  For
production it connects to an existing Spark cluster; for demos it
creates a local[*] session using the Iceberg Spark extensions.

Java 8+ and the Iceberg Spark runtime JAR must be available for the
Spark path.  If PySpark is not installed, ``is_available()`` returns
False and callers should fall back to ``DuckDBAnalytics``.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_SPARK_AVAILABLE: Optional[bool] = None


def is_spark_available() -> bool:
    global _SPARK_AVAILABLE
    if _SPARK_AVAILABLE is None:
        try:
            import pyspark  # noqa: F401  # type: ignore
            _SPARK_AVAILABLE = True
        except ImportError:
            _SPARK_AVAILABLE = False
    return _SPARK_AVAILABLE


class SparkAnalytics:
    """PySpark analytics engine with Apache Iceberg integration.

    This is the **production** analytics path following the open security
    lake reference architecture.  It:
      1. Connects to an Iceberg REST / Hive catalog.
      2. Registers the ``security.events`` table.
      3. Exposes helper methods for common SOC queries.
    """

    def __init__(
        self,
        app_name: str = "BlackStarSIEM-v2",
        master: str = "local[*]",
        iceberg_jar: str = "org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.5.0",
        catalog_uri: str = "sqlite:///./blackstar_catalog.db",
        warehouse_path: str = "./blackstar_warehouse",
    ) -> None:
        self._app_name = app_name
        self._master = master
        self._iceberg_jar = iceberg_jar
        self._catalog_uri = catalog_uri
        self._warehouse_path = warehouse_path
        self._spark = None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def start(self) -> "SparkAnalytics":
        """Initialise and return the Spark session with Iceberg extensions."""
        from pyspark.sql import SparkSession  # type: ignore

        self._spark = (
            SparkSession.builder.appName(self._app_name)
            .master(self._master)
            # Iceberg Spark extensions
            .config(
                "spark.sql.extensions",
                "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions",
            )
            # Register a local Iceberg catalog named 'blackstar'
            .config("spark.sql.catalog.blackstar", "org.apache.iceberg.spark.SparkCatalog")
            .config("spark.sql.catalog.blackstar.type", "jdbc")
            .config("spark.sql.catalog.blackstar.uri", self._catalog_uri)
            .config("spark.sql.catalog.blackstar.warehouse", self._warehouse_path)
            # Suppress verbose logs
            .config("spark.ui.enabled", "false")
            .config("spark.sql.shuffle.partitions", "4")
            .getOrCreate()
        )
        self._spark.sparkContext.setLogLevel("WARN")
        logger.info("Spark session started: %s (%s)", self._app_name, self._master)
        return self

    def stop(self) -> None:
        if self._spark:
            self._spark.stop()
            self._spark = None
            logger.info("Spark session stopped")

    @property
    def spark(self):
        if self._spark is None:
            raise RuntimeError("SparkAnalytics session not started. Call .start() first.")
        return self._spark

    # ------------------------------------------------------------------
    # Analytic queries (Spark SQL on Iceberg)
    # ------------------------------------------------------------------

    def run_sql(self, sql: str):
        """Execute arbitrary Spark SQL and return a DataFrame."""
        return self.spark.sql(sql)

    def top_source_ips(self, n: int = 10):
        return self.spark.sql(f"""
            SELECT src_ip, COUNT(*) AS event_count
            FROM blackstar.security.events
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY event_count DESC
            LIMIT {n}
        """)

    def severity_distribution(self):
        return self.spark.sql("""
            SELECT severity, COUNT(*) AS count
            FROM blackstar.security.events
            GROUP BY severity
            ORDER BY count DESC
        """)

    def failed_auth_by_user(self, threshold: int = 3):
        return self.spark.sql(f"""
            SELECT user_name, COUNT(*) AS failure_count
            FROM blackstar.security.events
            WHERE class_uid = 3002
              AND status = 'failure'
              AND user_name IS NOT NULL
            GROUP BY user_name
            HAVING failure_count >= {threshold}
            ORDER BY failure_count DESC
        """)

    def recent_critical_events(self, limit: int = 50):
        return self.spark.sql(f"""
            SELECT event_id, time, message, src_ip, user_name
            FROM blackstar.security.events
            WHERE severity_id = 5
            ORDER BY time DESC
            LIMIT {limit}
        """)

    def event_timeline(self, window: str = "1 hour"):
        """Aggregate event counts by tumbling time window."""
        return self.spark.sql(f"""
            SELECT
                window(CAST(time AS TIMESTAMP), '{window}').start AS window_start,
                severity,
                COUNT(*) AS count
            FROM blackstar.security.events
            GROUP BY 1, 2
            ORDER BY window_start DESC
        """)

    def process_injection_candidates(self):
        """Find process injection candidates (suspicious procs under trusted parents)."""
        return self.spark.sql("""
            SELECT proc_name, proc_parent, user_name, src_ip, time
            FROM blackstar.security.events
            WHERE class_uid = 1007
              AND severity_id >= 4
              AND proc_name IN ('nc', 'ncat', 'mimikatz', 'meterpreter')
            ORDER BY time DESC
        """)
