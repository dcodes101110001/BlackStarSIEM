"""
Iceberg Writer
==============
Writes batches of ``SecurityEvent`` objects to the Iceberg table managed by
``IcebergCatalog``.

When PyIceberg is not available (or the catalog hasn't been initialised) the
writer falls back to an **in-memory store** backed by a plain Python list.
This allows the Streamlit dashboard and unit tests to run without any
infrastructure.

The in-memory store can be queried with DuckDB via ``get_dataframe()``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from v2.ingestion.schemas import SecurityEvent

logger = logging.getLogger(__name__)


class IcebergWriter:
    """Writes security events to an Iceberg table (or in-memory fallback)."""

    def __init__(self, catalog=None) -> None:
        """
        Parameters
        ----------
        catalog : IcebergCatalog | None
            If provided and ``catalog.is_live`` is True, events are written
            to the actual Iceberg table.  Otherwise an in-memory list is used.
        """
        self._catalog = catalog
        self._memory: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def write(self, events: List[SecurityEvent]) -> int:
        """Write *events* and return the number persisted."""
        if not events:
            return 0

        rows = [e.to_dict() for e in events]

        if self._catalog is not None and self._catalog.is_live:
            return self._write_iceberg(rows)

        # In-memory fallback
        self._memory.extend(rows)
        logger.debug(
            "In-memory store: %d new events (total %d)", len(rows), len(self._memory)
        )
        return len(rows)

    def _write_iceberg(self, rows: List[Dict[str, Any]]) -> int:
        try:
            import pyarrow as pa  # type: ignore

            table = self._catalog.table
            schema = table.schema()

            # Build PyArrow table from rows
            df = pd.DataFrame(rows)
            # Ensure all schema columns exist
            for field in schema.fields:
                if field.name not in df.columns:
                    df[field.name] = None

            arrow_table = pa.Table.from_pandas(df, preserve_index=False)
            table.append(arrow_table)
            logger.info("Appended %d events to Iceberg table", len(rows))
            return len(rows)
        except (ImportError, ValueError, OSError) as exc:
            logger.error("Iceberg write error, falling back to memory: %s", exc)
            self._memory.extend(rows)
            return len(rows)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_dataframe(self) -> pd.DataFrame:
        """Return all stored events as a Pandas DataFrame.

        Uses the Iceberg table if live, otherwise the in-memory list.
        """
        if self._catalog is not None and self._catalog.is_live:
            try:
                arrow = self._catalog.scan_to_arrow()
                return arrow.to_pandas()
            except (ImportError, OSError, ValueError) as exc:
                logger.error("Iceberg scan failed, using memory: %s", exc)

        return pd.DataFrame(self._memory) if self._memory else pd.DataFrame()

    def event_count(self) -> int:
        if self._catalog is not None and self._catalog.is_live:
            try:
                df = self.get_dataframe()
                return len(df)
            except Exception:
                pass
        return len(self._memory)

    @property
    def memory_store(self) -> List[Dict[str, Any]]:
        """Direct access to the in-memory store (testing / introspection)."""
        return self._memory
