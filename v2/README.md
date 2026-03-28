# BlackStarSIEM v2 – Open Security Lake

> **Implements the [Confluent Open Security Lake Architecture](https://www.confluent.io/blog/open-security-lake-architecture-ciso-iceberg/) for CISOs** – real-time Kafka ingestion, Apache Iceberg storage, Spark/DuckDB analytics, and Python-class detection rules.

---

## Architecture

```
Security Event Sources (endpoints, cloud, network, auth)
              │
              ▼
     ┌────────────────┐
     │  Kafka Topics  │   security.network / .auth / .file / .process
     │  (Confluent)   │
     └───────┬────────┘
             │  Stream
             ▼
     ┌────────────────────────────────────┐
     │  Ingestion Pipeline                │
     │  • OCSF schema validation          │
     │  • Enrichment (topic stamping)     │
     │  • Batched consumer                │
     └───────┬────────────────────────────┘
             │  Write
             ▼
     ┌────────────────────────────────────┐
     │  Apache Iceberg Tables             │  ← open table format
     │  security.events                   │
     │  Partitioned by severity_id        │
     │  Warehouse: local / MinIO / S3     │
     └──────┬───────────────┬─────────────┘
            │               │
     ┌──────▼──────┐  ┌─────▼──────────┐
     │  Spark SQL  │  │  DuckDB        │
     │  (prod)     │  │  (demo/dev)    │
     └──────┬──────┘  └─────┬──────────┘
            └───────┬────────┘
                    │  Query
                    ▼
     ┌────────────────────────────────────┐
     │  Python SIEM Rules Engine          │
     │  17 rules across 4 categories:    │
     │  Network / Auth / File / Process  │
     └───────┬────────────────────────────┘
             │  Detections
             ▼
     ┌────────────────────────────────────┐
     │  Streamlit v2 Dashboard            │
     │  Architecture / Events / Analytics │
     │  Detection Rules / Alerts / Spark  │
     └────────────────────────────────────┘
```

---

## Quick Start (Demo Mode)

No Kafka or Spark installation required – the pipeline runs with in-memory
mocks automatically.

```bash
# 1. Install dependencies
pip install -r v2/requirements_v2.txt

# 2. Launch dashboard
streamlit run v2/app_v2.py

# Open http://localhost:8501
# Click "▶ Run Pipeline" to simulate events and see detections
```

---

## Full Stack (Docker Compose)

Starts Kafka, Schema Registry, MinIO (S3-compatible Iceberg warehouse), and
Apache Spark alongside the SIEM dashboard.

```bash
cd v2/
docker compose up -d

# Services:
#   http://localhost:8502  – BlackStarSIEM v2 dashboard
#   http://localhost:9001  – MinIO console (minioadmin / minioadmin)
#   http://localhost:9090  – Spark master UI
#   localhost:9092         – Kafka bootstrap
#   http://localhost:8081  – Schema Registry
```

---

## Python SIEM Rules

Rules are **Python classes** – not JSON/YARAL configuration files.
This gives analysts the full power of the language: regex, state, ML models,
external API calls, etc.

```python
# v2/rules/network_rules.py  (simplified)

from v2.rules.base import CounterRule, Severity, Detection
from typing import Dict, Any, Optional

class PortScanRule(CounterRule):
    rule_id = "NET-001"
    name = "Port Scan Detection"
    severity = Severity.MEDIUM
    mitre_tactic = "Discovery"
    mitre_technique_id = "T1046"
    threshold = 5                          # ← configurable

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if event.get("class_uid") != 4001:  # NetworkActivity only
            return None
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port", 0)
        self._port_sets[src_ip].add(dst_port)
        if len(self._port_sets[src_ip]) >= self.threshold:
            return self._detection(event,
                description=f"Port scan from {src_ip}: "
                             f"{len(self._port_sets[src_ip])} ports probed")
        return None
```

### Built-in Rules

| ID | Name | Severity | MITRE |
|----|------|----------|-------|
| NET-001 | Port Scan Detection | MEDIUM | T1046 |
| NET-002 | Lateral Movement Detection | HIGH | T1021 |
| NET-003 | Firewall Block / Bypass Attempt | HIGH | T1562 |
| NET-004 | C2 Beaconing Suspect | HIGH | T1071 |
| AUTH-001 | SSH / Login Brute Force | HIGH | T1110 |
| AUTH-002 | Admin Account Brute Force | CRITICAL | T1110.001 |
| AUTH-003 | Privilege Escalation Attempt | CRITICAL | T1068 |
| AUTH-004 | Multi-User Credential Stuffing | HIGH | T1110.004 |
| AUTH-005 | Account Lockout Detected | MEDIUM | T1531 |
| FILE-001 | Sensitive File Access | HIGH | T1003 |
| FILE-002 | Data Exfiltration Indicator | CRITICAL | T1048 |
| FILE-003 | Malware Staging Directory Write | HIGH | T1036 |
| FILE-004 | Executable Dropped (Suspicious Location) | HIGH | T1204 |
| PROC-001 | Process Injection Tool Detected | CRITICAL | T1055 |
| PROC-002 | LOLBin Abuse Detected | HIGH | T1059 |
| PROC-003 | Privileged Process Creation | HIGH | T1543 |
| PROC-004 | Suspicious Child Process | HIGH | T1203 |

### Writing a Custom Rule

```python
from v2.rules.base import SIEMRule, Severity, Detection
from typing import Dict, Any, Optional

class MyCustomRule(SIEMRule):
    rule_id = "CUSTOM-001"
    name = "My Detection"
    description = "Detects something suspicious"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059"
    tags = ["custom", "my-team"]

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if event.get("user_name") == "badactor":
            return self._detection(event, description="Bad actor detected!")
        return None

# Register with the engine
from v2.rules.engine import RuleEngine
engine = RuleEngine()
engine.register_defaults()
engine.register(MyCustomRule())
```

---

## Data Pipeline Components

### Ingestion

```python
from v2.ingestion.producer import EventProducer, SecurityEventSimulator
from v2.ingestion.consumer import EventConsumer
from v2.storage.writer import IcebergWriter

# Simulate and produce events to Kafka (mock mode)
queue = {}
producer = EventProducer(mock_queue=queue)
sim = SecurityEventSimulator()
for event in sim.generate_batch(500):
    producer.produce(event)

# Consume from Kafka and write to Iceberg
writer = IcebergWriter()
consumer = EventConsumer(topics=list(queue.keys()), writer=writer, mock_queue=queue)
consumer.drain_mock()

# Query the data lake
df = writer.get_dataframe()
```

### Iceberg Storage

```python
from v2.storage.catalog import IcebergCatalog

# Local dev catalog (SQLite)
catalog = IcebergCatalog(
    catalog_type="sql",
    catalog_uri="sqlite:///./catalog.db",
    warehouse_path="./warehouse",
)
catalog.init()

# Production (MinIO / S3)
catalog = IcebergCatalog(
    catalog_type="sql",
    catalog_uri="postgresql://user:pass@localhost/catalog",
    warehouse_path="s3://my-bucket/warehouse/",
    s3_endpoint="http://minio:9000",
)
```

### Analytics

```python
# DuckDB (no Java required)
from v2.processing.duckdb_analytics import DuckDBAnalytics

db = DuckDBAnalytics().connect()
db.register_dataframe(df)

top_ips  = db.top_source_ips(n=10)
brute    = db.brute_force_candidates(min_failures=5)
lateral  = db.lateral_movement_candidates()

# Apache Spark (requires Java 8+ and Iceberg JAR)
from v2.processing.spark_analytics import SparkAnalytics

spark = SparkAnalytics(master="spark://spark:7077").start()
spark.failed_auth_by_user(threshold=3).show()
spark.stop()
```

---

## Project Structure

```
v2/
├── app_v2.py                   # Streamlit v2 dashboard
├── config.py                   # Central configuration (env vars)
├── requirements_v2.txt         # Python dependencies
├── docker-compose.yml          # Full stack (Kafka, MinIO, Spark)
├── Dockerfile.v2               # Container for the dashboard
│
├── ingestion/
│   ├── schemas.py              # OCSF-aligned SecurityEvent dataclasses
│   ├── producer.py             # Kafka producer + SecurityEventSimulator
│   └── consumer.py             # Kafka→Iceberg consumer (mock + live)
│
├── storage/
│   ├── catalog.py              # PyIceberg catalog management
│   └── writer.py               # Iceberg writer (+ in-memory fallback)
│
├── processing/
│   ├── spark_analytics.py      # PySpark queries on Iceberg tables
│   └── duckdb_analytics.py     # DuckDB queries (demo/dev mode)
│
├── rules/
│   ├── base.py                 # SIEMRule, Detection, Severity, CounterRule
│   ├── network_rules.py        # NET-001 … NET-004
│   ├── auth_rules.py           # AUTH-001 … AUTH-005
│   ├── file_rules.py           # FILE-001 … FILE-004
│   ├── process_rules.py        # PROC-001 … PROC-004
│   └── engine.py               # RuleEngine, ScanReport
│
└── tests/
    ├── test_rules.py           # 50+ rule unit tests
    └── test_pipeline.py        # 31+ pipeline/ingestion tests
```

---

## Configuration

All settings can be overridden with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker(s) |
| `SCHEMA_REGISTRY_URL` | `http://localhost:8081` | Confluent Schema Registry |
| `ICEBERG_CATALOG_TYPE` | `sql` | Catalog type (sql / rest / hive / glue) |
| `ICEBERG_CATALOG_URI` | `sqlite:///./blackstar_catalog.db` | Catalog URI |
| `ICEBERG_WAREHOUSE` | `./blackstar_warehouse` | Warehouse root path |
| `S3_ENDPOINT` | `http://localhost:9000` | MinIO / S3 endpoint |
| `S3_ACCESS_KEY` | `minioadmin` | S3 access key |
| `S3_SECRET_KEY` | `minioadmin` | S3 secret key |
| `SPARK_MASTER` | `local[*]` | Spark master URL |
| `DEMO_MODE` | `true` | Use in-memory mocks (no Kafka/Spark needed) |

---

## Running Tests

```bash
# Install test dependencies
pip install -r v2/requirements_v2.txt

# Run all v2 tests
pytest v2/tests/ -v

# Example output:
# 81 passed in 1.21s
```

---

## v1 vs v2 Comparison

| Feature | v1 | v2 |
|---------|----|----|
| Data Ingestion | Static Pandas mock | **Kafka streaming pipeline** |
| Storage | Elasticsearch / memory | **Apache Iceberg (open table format)** |
| Processing | Pandas only | **Spark SQL + DuckDB** |
| Detection Rules | YARAL (JSON config files) | **Python classes** (full language power) |
| Event Schema | UDM/ECS | **OCSF** (Open Cybersecurity Schema Framework) |
| Partitioning | None | **By severity_id** |
| Schema Evolution | No | **Yes (Iceberg)** |
| Time Travel | No | **Yes (Iceberg snapshots)** |
| Infrastructure | Elasticsearch (optional) | **Kafka + Iceberg + Spark/DuckDB** |
| MITRE ATT&CK | No | **Yes (all 17 rules)** |
| Stateful Detection | No | **Yes (sliding-window counters)** |
| Tests | Excluded from repo | **81 tests committed** |
