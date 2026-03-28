"""
DuckDB Analytics
=================
Lightweight SQL analytics engine for the Iceberg security lake.

DuckDB can query Iceberg tables natively via its ``iceberg`` extension
(``INSTALL iceberg; LOAD iceberg;``).  It also works directly against
in-memory Pandas DataFrames, making it ideal for the demo / dev mode
where a full Spark cluster is not available.

This module is the **demo-mode** fallback.  In production use
``SparkAnalytics`` instead.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import pandas as pd

logger = logging.getLogger(__name__)


def is_duckdb_available() -> bool:
    try:
        import duckdb  # noqa: F401  # type: ignore
        return True
    except ImportError:
        return False


class DuckDBAnalytics:
    """DuckDB-backed analytics that can query either Iceberg or a Pandas DF."""

    def __init__(self, iceberg_warehouse: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        iceberg_warehouse : str | None
            If provided, DuckDB will attempt to load the Iceberg extension
            and query the warehouse directly.
            If None, use ``register_dataframe()`` to query in-memory data.
        """
        self._warehouse = iceberg_warehouse
        self._con = None
        self._registered = False

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> "DuckDBAnalytics":
        import duckdb  # type: ignore

        self._con = duckdb.connect(":memory:")

        if self._warehouse:
            try:
                self._con.execute("INSTALL iceberg; LOAD iceberg;")
                logger.info("DuckDB Iceberg extension loaded")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load DuckDB iceberg extension: %s", exc)
        return self

    def close(self) -> None:
        if self._con:
            self._con.close()
            self._con = None

    # ------------------------------------------------------------------
    # Data registration
    # ------------------------------------------------------------------

    def register_dataframe(self, df: pd.DataFrame, view_name: str = "events") -> None:
        """Register a Pandas DataFrame as a queryable DuckDB view."""
        if self._con is None:
            self.connect()
        self._con.register(view_name, df)
        self._registered = True
        logger.debug("Registered DataFrame as DuckDB view '%s' (%d rows)", view_name, len(df))

    def register_iceberg_table(
        self,
        metadata_path: str,
        view_name: str = "events",
    ) -> None:
        """Register an Iceberg table from its metadata.json path."""
        if self._con is None:
            self.connect()
        self._con.execute(
            f"CREATE OR REPLACE VIEW {view_name} AS "
            f"SELECT * FROM iceberg_scan('{metadata_path}');"
        )
        self._registered = True

    # ------------------------------------------------------------------
    # Common SOC queries
    # ------------------------------------------------------------------

    def run_sql(self, sql: str) -> pd.DataFrame:
        if self._con is None:
            self.connect()
        return self._con.execute(sql).df()

    def top_source_ips(self, n: int = 10) -> pd.DataFrame:
        return self.run_sql(f"""
            SELECT src_ip, COUNT(*) AS event_count
            FROM events
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY event_count DESC
            LIMIT {n}
        """)

    def severity_distribution(self) -> pd.DataFrame:
        return self.run_sql("""
            SELECT severity, COUNT(*) AS count
            FROM events
            WHERE severity IS NOT NULL
            GROUP BY severity
            ORDER BY count DESC
        """)

    def failed_auth_by_user(self, threshold: int = 3) -> pd.DataFrame:
        return self.run_sql(f"""
            SELECT user_name, COUNT(*) AS failure_count
            FROM events
            WHERE class_uid = 3002
              AND status = 'failure'
              AND user_name IS NOT NULL
              AND user_name != ''
            GROUP BY user_name
            HAVING failure_count >= {threshold}
            ORDER BY failure_count DESC
        """)

    def recent_critical_events(self, limit: int = 50) -> pd.DataFrame:
        return self.run_sql(f"""
            SELECT event_id, time, message, src_ip, user_name
            FROM events
            WHERE severity_id = 5
            ORDER BY time DESC
            LIMIT {limit}
        """)

    def event_timeline(self, bucket_hours: int = 1) -> pd.DataFrame:
        """Count events per N-hour bucket."""
        return self.run_sql(f"""
            SELECT
                DATE_TRUNC('hour', CAST(time AS TIMESTAMP)) AS hour_bucket,
                severity,
                COUNT(*) AS count
            FROM events
            WHERE time IS NOT NULL AND time != ''
            GROUP BY 1, 2
            ORDER BY hour_bucket DESC
        """)

    def class_distribution(self) -> pd.DataFrame:
        class_labels = {
            4001: "Network",
            3002: "Authentication",
            1001: "File",
            1007: "Process",
            2001: "Security Finding",
        }
        df = self.run_sql("""
            SELECT class_uid, COUNT(*) AS count
            FROM events
            GROUP BY class_uid
            ORDER BY count DESC
        """)
        if not df.empty and "class_uid" in df.columns:
            df["class_name"] = df["class_uid"].map(class_labels).fillna("Unknown")
        return df

    def alert_summary(self) -> pd.DataFrame:
        """Return count of high/critical events per topic."""
        return self.run_sql("""
            SELECT kafka_topic, severity, COUNT(*) AS count
            FROM events
            WHERE severity_id >= 4
            GROUP BY kafka_topic, severity
            ORDER BY count DESC
        """)

    def brute_force_candidates(self, min_failures: int = 5) -> pd.DataFrame:
        """Users with >= min_failures failed auth events."""
        return self.run_sql(f"""
            SELECT user_name, src_ip, COUNT(*) AS failure_count
            FROM events
            WHERE class_uid = 3002 AND status = 'failure'
              AND user_name != '' AND user_name IS NOT NULL
            GROUP BY user_name, src_ip
            HAVING failure_count >= {min_failures}
            ORDER BY failure_count DESC
        """)

    def lateral_movement_candidates(self) -> pd.DataFrame:
        """Internal IPs appearing as source for network events to multiple dst IPs."""
        return self.run_sql("""
            SELECT src_ip,
                   COUNT(DISTINCT dst_ip) AS unique_destinations,
                   COUNT(*) AS total_events
            FROM events
            WHERE class_uid = 4001
              AND src_ip LIKE '192.168.%'
              AND dst_ip IS NOT NULL AND dst_ip != ''
            GROUP BY src_ip
            HAVING unique_destinations >= 3
            ORDER BY unique_destinations DESC
        """)
