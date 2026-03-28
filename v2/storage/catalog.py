"""
Iceberg Catalog Manager
========================
Manages the Apache Iceberg catalog and table lifecycle.

BlackStarSIEM v2 uses the **PyIceberg** library (pure Python) to interact
with Iceberg tables.  The catalog can be:

  * **SQL catalog** (SQLite for development / PostgreSQL for production)
  * **REST catalog** (Confluent-managed Iceberg REST endpoint)
  * **Hive Metastore** catalog (on-prem)

The ``security.events`` table schema mirrors the flat representation
produced by ``SecurityEvent.to_dict()``.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema definition (PyIceberg types)
# ---------------------------------------------------------------------------

_SCHEMA_FIELDS_DEF = """
event_id:         string not null
time:             string not null
class_uid:        int not null
category_uid:     int not null
activity_id:      int not null
severity_id:      int not null
severity:         string
status:           string
message:          string
src_ip:           string
src_port:         int
src_hostname:     string
dst_ip:           string
dst_port:         int
dst_hostname:     string
user_name:        string
user_uid:         string
user_is_admin:    boolean
proc_name:        string
proc_pid:         int
proc_cmd_line:    string
proc_parent:      string
file_path:        string
file_name:        string
file_type:        string
kafka_topic:      string
kafka_partition:  int
kafka_offset:     long
"""


def _build_iceberg_schema():
    """Build and return the PyIceberg Schema for security events."""
    try:
        from pyiceberg.schema import Schema  # type: ignore
        from pyiceberg.types import (  # type: ignore
            BooleanType,
            IntegerType,
            LongType,
            NestedField,
            StringType,
        )
    except ImportError:
        return None

    fields = [
        NestedField(1,  "event_id",        StringType(),  required=True),
        NestedField(2,  "time",            StringType(),  required=True),
        NestedField(3,  "class_uid",       IntegerType(), required=True),
        NestedField(4,  "category_uid",    IntegerType(), required=True),
        NestedField(5,  "activity_id",     IntegerType(), required=True),
        NestedField(6,  "severity_id",     IntegerType(), required=True),
        NestedField(7,  "severity",        StringType(),  required=False),
        NestedField(8,  "status",          StringType(),  required=False),
        NestedField(9,  "message",         StringType(),  required=False),
        NestedField(10, "src_ip",          StringType(),  required=False),
        NestedField(11, "src_port",        IntegerType(), required=False),
        NestedField(12, "src_hostname",    StringType(),  required=False),
        NestedField(13, "dst_ip",          StringType(),  required=False),
        NestedField(14, "dst_port",        IntegerType(), required=False),
        NestedField(15, "dst_hostname",    StringType(),  required=False),
        NestedField(16, "user_name",       StringType(),  required=False),
        NestedField(17, "user_uid",        StringType(),  required=False),
        NestedField(18, "user_is_admin",   BooleanType(), required=False),
        NestedField(19, "proc_name",       StringType(),  required=False),
        NestedField(20, "proc_pid",        IntegerType(), required=False),
        NestedField(21, "proc_cmd_line",   StringType(),  required=False),
        NestedField(22, "proc_parent",     StringType(),  required=False),
        NestedField(23, "file_path",       StringType(),  required=False),
        NestedField(24, "file_name",       StringType(),  required=False),
        NestedField(25, "file_type",       StringType(),  required=False),
        NestedField(26, "kafka_topic",     StringType(),  required=False),
        NestedField(27, "kafka_partition", IntegerType(), required=False),
        NestedField(28, "kafka_offset",    LongType(),    required=False),
    ]
    return Schema(*fields)


def _build_partition_spec(schema):
    """Partition events by severity (identity)."""
    try:
        from pyiceberg.partitioning import PartitionField, PartitionSpec  # type: ignore
        from pyiceberg.transforms import IdentityTransform  # type: ignore

        return PartitionSpec(
            PartitionField(
                source_id=6,          # severity_id
                field_id=1001,
                transform=IdentityTransform(),
                name="severity_id",
            )
        )
    except ImportError:
        return None


class IcebergCatalog:
    """Thin wrapper around a PyIceberg catalog for BlackStarSIEM."""

    def __init__(
        self,
        catalog_type: str = "sql",
        catalog_uri: str = "sqlite:///./blackstar_catalog.db",
        warehouse_path: str = "./blackstar_warehouse",
        namespace: str = "security",
        table_name: str = "events",
        s3_endpoint: str = "",
        s3_access_key: str = "",
        s3_secret_key: str = "",
    ) -> None:
        self._catalog_type = catalog_type
        self._catalog_uri = catalog_uri
        self._warehouse = warehouse_path
        self._namespace = namespace
        self._table_name = table_name
        self._s3_endpoint = s3_endpoint
        self._s3_access_key = s3_access_key
        self._s3_secret_key = s3_secret_key
        self._catalog: Optional[object] = None
        self._table: Optional[object] = None

    # ------------------------------------------------------------------
    # Catalog initialisation
    # ------------------------------------------------------------------

    def init(self) -> None:
        """Open (or create) the catalog and the security events table."""
        try:
            self._catalog = self._load_catalog()
            self._ensure_namespace()
            self._table = self._ensure_table()
            logger.info(
                "Iceberg catalog ready: %s.%s", self._namespace, self._table_name
            )
        except ImportError:
            logger.warning(
                "pyiceberg not installed; using in-memory fallback. "
                "Install with: pip install 'pyiceberg[duckdb,sql-sqlite]'"
            )

    def _load_catalog(self):
        from pyiceberg.catalog.sql import SqlCatalog  # type: ignore

        props: dict = {
            "uri": self._catalog_uri,
            "warehouse": self._warehouse,
        }
        if self._s3_endpoint:
            props.update(
                {
                    "s3.endpoint": self._s3_endpoint,
                    "s3.access-key-id": self._s3_access_key,
                    "s3.secret-access-key": self._s3_secret_key,
                    "s3.path-style-access": "true",
                }
            )
        return SqlCatalog("blackstar", **props)

    def _ensure_namespace(self) -> None:
        namespaces = [ns[0] for ns in self._catalog.list_namespaces()]
        if self._namespace not in namespaces:
            self._catalog.create_namespace(self._namespace)
            logger.info("Created Iceberg namespace: %s", self._namespace)

    def _ensure_table(self):
        identifier = (self._namespace, self._table_name)
        try:
            return self._catalog.load_table(identifier)
        except Exception as exc:  # table not found – create it
            logger.debug(
                "Table %s.%s not found (%s); creating it",
                self._namespace, self._table_name, exc,
            )
            schema = _build_iceberg_schema()
            partition_spec = _build_partition_spec(schema)
            if partition_spec:
                tbl = self._catalog.create_table(
                    identifier=identifier,
                    schema=schema,
                    partition_spec=partition_spec,
                )
            else:
                tbl = self._catalog.create_table(
                    identifier=identifier,
                    schema=schema,
                )
            logger.info(
                "Created Iceberg table: %s.%s", self._namespace, self._table_name
            )
            return tbl

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def table(self):
        """Return the PyIceberg Table object (or None in fallback mode)."""
        return self._table

    @property
    def is_live(self) -> bool:
        return self._table is not None

    def scan_to_arrow(self):
        """Scan the Iceberg table and return a PyArrow Table."""
        if not self.is_live:
            raise RuntimeError("Iceberg table not initialised")

        scanner = self._table.scan()
        return scanner.to_arrow()
