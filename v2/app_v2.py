"""
BlackStarSIEM v2 – Streamlit Dashboard
========================================
Implements the Open Security Lake architecture:

  Security Events
       │
       ▼
  Kafka Topics  ←──── EventProducer (simulated events)
       │
       ▼
  Iceberg Tables  ←── EventConsumer → IcebergWriter
       │
       ▼
  DuckDB / Spark Analytics
       │
       ▼
  Python SIEM Rules Engine
       │
       ▼
  Streamlit Dashboard (this file)

Run locally:
    pip install -r v2/requirements_v2.txt
    streamlit run v2/app_v2.py
"""

from __future__ import annotations

import sys
import os

# Make the repo root importable when running from the v2/ directory
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import logging
from typing import Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from v2.config import settings
from v2.ingestion.producer import EventProducer, MockQueue, SecurityEventSimulator
from v2.ingestion.consumer import EventConsumer
from v2.storage.writer import IcebergWriter
from v2.processing.duckdb_analytics import DuckDBAnalytics
from v2.rules.engine import RuleEngine
from v2.rules.correlation import (
    CorrelationEngine,
    CorrelationOperator,
    CorrelationRule,
    CorrelationStep,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="BlackStarSIEM v2",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------

def _init_state() -> None:
    defaults = {
        "writer": IcebergWriter(),
        "engine": None,
        "analytics": None,
        "mock_queue": {},
        "pipeline_initialised": False,
        "events_ingested": 0,
        "detections": [],
        "scan_run": False,
        "sim_batch_size": 200,
        # Correlation rules state
        "corr_engine": CorrelationEngine(),
        "corr_matches": [],
        "corr_draft_steps": [],      # steps being built for a new rule
        "corr_next_id": 1,           # counter for auto-generated IDs
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # Initialise rule engine once
    if st.session_state["engine"] is None:
        engine = RuleEngine()
        engine.register_defaults()
        st.session_state["engine"] = engine


_init_state()


# ---------------------------------------------------------------------------
# Helper: run the full pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(batch_size: int = 200) -> None:
    """Simulate events → Kafka → Iceberg → SIEM rules."""
    progress = st.progress(0, text="Simulating events…")
    writer: IcebergWriter = st.session_state["writer"]
    mock_queue: MockQueue = st.session_state["mock_queue"]
    engine: RuleEngine = st.session_state["engine"]

    # 1. Generate events via simulator
    sim = SecurityEventSimulator()
    events = sim.generate_batch(batch_size)
    progress.progress(20, text="Producing to Kafka topics…")

    # 2. Produce to Kafka mock queue
    producer = EventProducer(mock_queue=mock_queue)
    for evt in events:
        producer.produce(evt)

    progress.progress(40, text="Consuming and writing to Iceberg…")

    # 3. Consume from mock queue → write to IcebergWriter
    consumer = EventConsumer(
        topics=list(mock_queue.keys()),
        writer=writer,
        mock_queue=mock_queue,
    )
    consumer.drain_mock()
    st.session_state["events_ingested"] = writer.event_count()

    progress.progress(70, text="Running DuckDB analytics…")

    # 4. DuckDB analytics
    df = writer.get_dataframe()
    analytics = DuckDBAnalytics()
    analytics.connect()
    analytics.register_dataframe(df, "events")
    st.session_state["analytics"] = analytics

    progress.progress(85, text="Running SIEM detection rules…")

    # 5. SIEM rules
    engine.reset_state()
    report = engine.scan_events(df.to_dict(orient="records"))
    st.session_state["detections"] = report.detections
    st.session_state["scan_run"] = True

    progress.progress(100, text="Pipeline complete ✓")
    progress.empty()

    st.success(
        f"✅ Pipeline run complete: "
        f"**{writer.event_count()}** events stored │ "
        f"**{len(report.detections)}** detections"
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_sidebar() -> None:
    with st.sidebar:
        st.image(
            "https://img.shields.io/badge/BlackStarSIEM-v2-blue?style=for-the-badge",
            width=250,
        )
        st.markdown("## 🛡️ BlackStarSIEM v2")
        st.caption("Open Security Lake Architecture")

        st.divider()
        st.markdown("### ⚙️ Pipeline Configuration")

        batch_size = st.slider(
            "Events per run",
            min_value=50,
            max_value=1000,
            value=st.session_state["sim_batch_size"],
            step=50,
        )
        st.session_state["sim_batch_size"] = batch_size

        if st.button("▶ Run Pipeline", type="primary", use_container_width=True):
            _run_pipeline(batch_size)

        if st.button("🗑 Reset", use_container_width=True):
            for k in ["writer", "engine", "analytics", "mock_queue",
                      "events_ingested", "detections", "scan_run"]:
                if k in st.session_state:
                    del st.session_state[k]
            st.rerun()

        st.divider()
        st.markdown("### 📊 Status")
        total = st.session_state.get("events_ingested", 0)
        detections = st.session_state.get("detections", [])
        st.metric("Events in Iceberg Lake", total)
        st.metric("Detections (this run)", len(detections))
        critical = sum(1 for d in detections if int(d.severity) >= 5)
        st.metric("Critical Alerts", critical, delta=None)

        st.divider()
        st.markdown("### 🏗 Architecture")
        st.markdown("""
```
Security Sources
     │
     ▼
 Kafka Topics
     │
     ▼
 Iceberg Tables    ← open table format
     │
 ┌───┴────┐
 │ Spark  │  ← production path
 │ DuckDB │  ← demo path
 └───┬────┘
     │
  Python SIEM Rules
     │
     ▼
  Streamlit UI
```
        """)


# ---------------------------------------------------------------------------
# Tab: Architecture Overview
# ---------------------------------------------------------------------------

def _tab_architecture() -> None:
    st.header("🏗️ Open Security Lake Architecture")

    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
### Reference Architecture

BlackStarSIEM v2 implements the
[Confluent Open Security Lake](https://www.confluent.io/blog/open-security-lake-architecture-ciso-iceberg/)
reference architecture for CISOs:

| Layer | Technology | Role |
|-------|-----------|------|
| **Ingestion** | Apache Kafka / Confluent | Real-time event streaming |
| **Storage** | Apache Iceberg (open table format) | Immutable, versioned event lake |
| **Processing** | Apache Spark / DuckDB | SQL analytics on the lake |
| **Detection** | Python SIEM Rules | Flexible, stateful detection logic |
| **Visualisation** | Streamlit | Interactive SOC dashboard |

### Key Differentiators vs v1

| Feature | v1 | v2 |
|---------|----|-----|
| Ingestion | Static mock | Kafka streaming pipeline |
| Storage | Elasticsearch / memory | Apache Iceberg (open format) |
| Processing | Pandas | Spark SQL / DuckDB |
| Rules | YARAL (JSON config) | **Python classes** |
| Schema | UDM/ECS | **OCSF** |
| Scale | 100 demo events | Unlimited (partitioned lake) |
        """)

    with col2:
        st.markdown("### Pipeline Stages")
        stages = [
            ("1️⃣", "Event Sources", "Endpoints, cloud, network, auth logs"),
            ("2️⃣", "Kafka Topics", "security.network / .auth / .file / .process"),
            ("3️⃣", "Ingestion", "Schema validation (OCSF) + enrichment"),
            ("4️⃣", "Iceberg Lake", "Partitioned by severity & date"),
            ("5️⃣", "Analytics", "Spark SQL or DuckDB queries"),
            ("6️⃣", "SIEM Rules", "17 Python detection rules across 4 categories"),
            ("7️⃣", "Alerts", "Detections with MITRE ATT&CK mapping"),
        ]
        for emoji, stage, detail in stages:
            with st.expander(f"{emoji} **{stage}**", expanded=False):
                st.write(detail)

        st.markdown("### OCSF Event Classes")
        ocsf_df = pd.DataFrame([
            {"Class UID": 4001, "Name": "Network Activity", "Kafka Topic": "security.network"},
            {"Class UID": 3002, "Name": "Authentication", "Kafka Topic": "security.auth"},
            {"Class UID": 1001, "Name": "File Activity", "Kafka Topic": "security.file"},
            {"Class UID": 1007, "Name": "Process Activity", "Kafka Topic": "security.process"},
        ])
        st.dataframe(ocsf_df, hide_index=True, use_container_width=True)


# ---------------------------------------------------------------------------
# Tab: Events
# ---------------------------------------------------------------------------

def _tab_events() -> None:
    st.header("📋 Security Events (Iceberg Lake)")
    writer: IcebergWriter = st.session_state["writer"]
    df = writer.get_dataframe()

    if df.empty:
        st.info("No events yet. Click **▶ Run Pipeline** in the sidebar.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        severities = ["all"] + sorted(df["severity"].dropna().unique().tolist())
        sel_sev = st.selectbox("Severity", severities)
    with col2:
        classes = ["all", "network", "auth", "file", "process"]
        sel_class = st.selectbox("Event Class", classes)
    with col3:
        statuses = ["all"] + sorted(df["status"].dropna().unique().tolist())
        sel_status = st.selectbox("Status", statuses)

    filtered = df.copy()
    if sel_sev != "all":
        filtered = filtered[filtered["severity"] == sel_sev]
    if sel_class != "all":
        class_map = {"network": 4001, "auth": 3002, "file": 1001, "process": 1007}
        filtered = filtered[filtered["class_uid"] == class_map[sel_class]]
    if sel_status != "all":
        filtered = filtered[filtered["status"] == sel_status]

    st.metric("Filtered Events", len(filtered))

    display_cols = [
        c for c in [
            "time", "severity", "status", "message",
            "src_ip", "user_name", "proc_name", "file_path", "kafka_topic",
        ]
        if c in filtered.columns
    ]
    st.dataframe(
        filtered[display_cols].head(500),
        hide_index=True,
        use_container_width=True,
    )

    if st.button("⬇️ Export CSV"):
        csv = filtered.to_csv(index=False)
        st.download_button(
            "Download events.csv",
            data=csv,
            file_name="blackstar_events.csv",
            mime="text/csv",
        )


# ---------------------------------------------------------------------------
# Tab: Analytics
# ---------------------------------------------------------------------------

def _tab_analytics() -> None:
    st.header("📈 Security Analytics")
    analytics: DuckDBAnalytics = st.session_state.get("analytics")
    writer: IcebergWriter = st.session_state["writer"]
    df = writer.get_dataframe()

    if df.empty or analytics is None:
        st.info("Run the pipeline first to see analytics.")
        return

    # Re-register in case of new data
    analytics.register_dataframe(df, "events")

    col1, col2 = st.columns(2)

    with col1:
        # Severity distribution pie
        sev_df = analytics.severity_distribution()
        if not sev_df.empty:
            _SEV_COLOURS = {
                "informational": "#28a745",
                "low": "#17a2b8",
                "medium": "#ffc107",
                "high": "#fd7e14",
                "critical": "#dc3545",
            }
            sev_df["colour"] = sev_df["severity"].map(_SEV_COLOURS)
            fig = px.pie(
                sev_df,
                names="severity",
                values="count",
                title="Events by Severity",
                color="severity",
                color_discrete_map=_SEV_COLOURS,
                hole=0.4,
            )
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Event class distribution bar
        class_df = analytics.class_distribution()
        if not class_df.empty and "class_name" in class_df.columns:
            fig2 = px.bar(
                class_df,
                x="class_name",
                y="count",
                title="Events by OCSF Class",
                color="class_name",
            )
            st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("🔝 Top Source IPs")
        ip_df = analytics.top_source_ips(n=10)
        if not ip_df.empty:
            fig3 = px.bar(ip_df, x="event_count", y="src_ip", orientation="h",
                          title="Top 10 Source IPs")
            st.plotly_chart(fig3, use_container_width=True)

    with col4:
        st.subheader("🔐 Failed Auth by User")
        auth_df = analytics.failed_auth_by_user(threshold=1)
        if not auth_df.empty:
            fig4 = px.bar(auth_df.head(10), x="failure_count", y="user_name",
                          orientation="h", title="Failed Logins by User")
            st.plotly_chart(fig4, use_container_width=True)
        else:
            st.info("No failed auth events in current dataset.")

    st.subheader("🚨 Alert Summary (High/Critical Events by Topic)")
    alert_df = analytics.alert_summary()
    if not alert_df.empty:
        fig5 = px.bar(
            alert_df,
            x="kafka_topic",
            y="count",
            color="severity",
            barmode="group",
            title="High/Critical Events by Kafka Topic",
        )
        st.plotly_chart(fig5, use_container_width=True)

    # Lateral movement
    st.subheader("↔️ Lateral Movement Candidates")
    lm_df = analytics.lateral_movement_candidates()
    if not lm_df.empty:
        st.dataframe(lm_df, hide_index=True, use_container_width=True)
    else:
        st.info("No lateral movement candidates detected in current dataset.")

    # Custom SQL
    st.subheader("🗄️ Custom SQL Query (DuckDB)")
    default_sql = "SELECT severity, COUNT(*) AS cnt FROM events GROUP BY severity ORDER BY cnt DESC"
    user_sql = st.text_area("Enter DuckDB SQL", value=default_sql, height=80)
    if st.button("Run Query"):
        try:
            result_df = analytics.run_sql(user_sql)
            st.dataframe(result_df, hide_index=True, use_container_width=True)
        except Exception as exc:
            st.error(f"Query error: {exc}")


# ---------------------------------------------------------------------------
# Tab: Detection Rules
# ---------------------------------------------------------------------------

def _tab_rules() -> None:
    st.header("🔎 Python SIEM Detection Rules")
    engine: RuleEngine = st.session_state["engine"]

    st.info(
        "Rules in BlackStarSIEM v2 are **Python classes**, not JSON/YARAL config files. "
        "Each rule inherits from `SIEMRule`, implements `evaluate()`, and can maintain "
        "state (e.g. sliding-window counters)."
    )

    rules_df = engine.rules_summary()

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader(f"📋 Registered Rules ({len(rules_df)})")
        # Editable enable/disable
        edited = st.data_editor(
            rules_df[["rule_id", "name", "severity", "enabled", "mitre_tactic",
                       "mitre_technique_id", "tags"]],
            hide_index=True,
            use_container_width=True,
            column_config={
                "enabled": st.column_config.CheckboxColumn("Enabled"),
                "rule_id": st.column_config.TextColumn("Rule ID", disabled=True),
                "name": st.column_config.TextColumn("Name", disabled=True),
                "severity": st.column_config.TextColumn("Severity", disabled=True),
            },
        )
        if st.button("Apply Changes"):
            for _, row in edited.iterrows():
                if row["enabled"]:
                    engine.enable(row["rule_id"])
                else:
                    engine.disable(row["rule_id"])
            st.success("Rule states updated.")

    with col2:
        st.subheader("📊 Rules by Severity")
        sev_counts = rules_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig = px.bar(sev_counts, x="severity", y="count",
                     color="severity", title="Rules by Severity")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("🎯 MITRE Tactics")
        tactic_counts = (
            rules_df["mitre_tactic"]
            .value_counts()
            .reset_index()
        )
        tactic_counts.columns = ["tactic", "count"]
        fig2 = px.pie(tactic_counts, names="tactic", values="count",
                      title="Rules by MITRE Tactic")
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("📝 Example: Python Rule Implementation")
    st.code("""
# All rules are pure Python classes – no JSON/YAML needed!
from v2.rules.base import SIEMRule, Severity, Detection, CounterRule
from typing import Dict, Any, Optional

class PortScanRule(CounterRule):
    rule_id = "NET-001"
    name = "Port Scan Detection"
    severity = Severity.MEDIUM
    mitre_tactic = "Discovery"
    mitre_technique_id = "T1046"
    threshold = 5            # configurable class attribute

    def evaluate(self, event: Dict[str, Any]) -> Optional[Detection]:
        if event.get("class_uid") != 4001:  # NetworkActivity
            return None
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port", 0)
        self._port_sets[src_ip].add(dst_port)
        if len(self._port_sets[src_ip]) >= self.threshold:
            return self._detection(event,
                description=f"Port scan from {src_ip}: "
                             f"{len(self._port_sets[src_ip])} ports probed")
        return None
""", language="python")


# ---------------------------------------------------------------------------
# Tab: Detections / Alerts
# ---------------------------------------------------------------------------

def _tab_detections() -> None:
    st.header("🚨 Detections & Alerts")
    detections = st.session_state.get("detections", [])

    if not detections:
        if st.session_state.get("scan_run"):
            st.success("✅ No detections – all clear for this run!")
        else:
            st.info("Run the pipeline to generate detections.")
        return

    # Summary metrics
    sev_counts = {}
    for d in detections:
        label = d.severity.label()
        sev_counts[label] = sev_counts.get(label, 0) + 1

    cols = st.columns(5)
    for idx, sev in enumerate(["critical", "high", "medium", "low", "informational"]):
        with cols[idx]:
            st.metric(
                sev.upper(),
                sev_counts.get(sev, 0),
                delta=None,
            )

    st.divider()

    det_df = pd.DataFrame([d.to_dict() for d in detections])
    det_df = det_df.sort_values("severity_id", ascending=False)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader(f"Detection Log ({len(det_df)} alerts)")
        display_cols = [
            c for c in [
                "timestamp", "severity", "rule_id", "rule_name",
                "description", "mitre_tactic", "mitre_technique_id",
                "event_message", "confidence",
            ]
            if c in det_df.columns
        ]
        st.dataframe(det_df[display_cols], hide_index=True, use_container_width=True)

    with col2:
        # Detections by rule
        rule_counts = det_df["rule_id"].value_counts().reset_index()
        rule_counts.columns = ["rule_id", "count"]
        fig = px.bar(rule_counts, x="count", y="rule_id", orientation="h",
                     title="Detections by Rule")
        st.plotly_chart(fig, use_container_width=True)

        # Detections by severity donut
        sev_df = det_df["severity"].value_counts().reset_index()
        sev_df.columns = ["severity", "count"]
        _SEV_COLOURS = {
            "informational": "#28a745", "low": "#17a2b8",
            "medium": "#ffc107", "high": "#fd7e14", "critical": "#dc3545",
        }
        fig2 = px.pie(
            sev_df, names="severity", values="count",
            title="Detections by Severity",
            color="severity", color_discrete_map=_SEV_COLOURS, hole=0.4,
        )
        st.plotly_chart(fig2, use_container_width=True)

    if st.button("⬇️ Export Detections CSV"):
        csv = det_df.to_csv(index=False)
        st.download_button(
            "Download detections.csv",
            data=csv,
            file_name="blackstar_detections.csv",
            mime="text/csv",
        )


# ---------------------------------------------------------------------------
# Tab: Spark / Iceberg Info
# ---------------------------------------------------------------------------

def _tab_spark_iceberg() -> None:
    st.header("⚡ Spark & Iceberg Integration")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Apache Iceberg – Open Table Format")
        st.markdown("""
Apache Iceberg is the storage foundation of the Open Security Lake.
Key properties used in BlackStarSIEM v2:

- **Immutable snapshots** – every pipeline run creates a new snapshot;
  historical data is never overwritten (perfect for forensics).
- **Schema evolution** – add new OCSF fields without breaking existing readers.
- **Partition pruning** – events are partitioned by `severity_id`, enabling
  sub-second queries on critical events.
- **Time travel** – `SELECT * FROM events FOR SYSTEM_TIME AS OF ...`

The warehouse can be stored on **local filesystem** (dev), **MinIO** (on-prem)
or **AWS S3 / GCS / Azure ADLS** (cloud).
        """)

        st.subheader("Catalog Options")
        catalog_df = pd.DataFrame([
            {"Catalog": "SQL (SQLite)", "Use Case": "Local development", "Config": "sqlite:///catalog.db"},
            {"Catalog": "SQL (PostgreSQL)", "Use Case": "Production on-prem", "Config": "postgresql://..."},
            {"Catalog": "AWS Glue", "Use Case": "AWS cloud", "Config": "glue catalog_id=..."},
            {"Catalog": "REST (Confluent)", "Use Case": "Confluent Cloud Tableflow", "Config": "https://..."},
            {"Catalog": "Hive Metastore", "Use Case": "Existing Hadoop/Hive", "Config": "thrift://..."},
        ])
        st.dataframe(catalog_df, hide_index=True, use_container_width=True)

    with col2:
        st.subheader("Apache Spark – Production Analytics")
        st.code("""
# Production Spark setup (requires Java + iceberg JAR)
from v2.processing.spark_analytics import SparkAnalytics

spark = SparkAnalytics(
    master="spark://spark:7077",     # Spark cluster
    catalog_uri="postgresql://...",  # Production catalog
    warehouse_path="s3://bucket/",
).start()

# SQL queries directly on Iceberg tables
top_ips = spark.top_source_ips(n=20).toPandas()
brute_force = spark.failed_auth_by_user(threshold=5).toPandas()
critical = spark.recent_critical_events(limit=100).toPandas()

spark.stop()
        """, language="python")

        st.subheader("DuckDB – Demo / Dev Mode")
        st.code("""
# DuckDB queries the same Iceberg warehouse without Java
from v2.processing.duckdb_analytics import DuckDBAnalytics

db = DuckDBAnalytics(iceberg_warehouse="./warehouse").connect()
# Or register a Pandas DataFrame directly:
db.register_dataframe(df, "events")
sev = db.severity_distribution()  # returns Pandas DataFrame
        """, language="python")

        writer: IcebergWriter = st.session_state["writer"]
        st.metric("Events in In-Memory Store", writer.event_count())
        df = writer.get_dataframe()
        if not df.empty:
            st.caption(f"Schema: {len(df.columns)} columns, {len(df)} rows")
            st.code(str(list(df.columns)), language="python")



# ---------------------------------------------------------------------------
# Tab: Correlation Rules Builder
# ---------------------------------------------------------------------------

_OPERATOR_LABELS = {
    "AND": "AND – both this and the previous step must fire",
    "OR": "OR – either this or the previous step must fire",
    "THEN": "THEN – this step must fire after the previous step (sequential)",
}

_SEV_COLOURS_CORR = {
    "informational": "#28a745",
    "low": "#17a2b8",
    "medium": "#ffc107",
    "high": "#fd7e14",
    "critical": "#dc3545",
}


def _tab_correlation() -> None:  # noqa: C901 – long but linear UI logic
    st.header("🔗 Correlation Rules Builder")

    st.markdown(
        """
Build **correlation rules** by stacking individual SIEM detection rules into a
sequential pipeline.  Each step references a predefined rule (e.g. `AUTH-001`)
or a custom field condition.  Steps are joined by a logical operator:

| Operator | Meaning |
|----------|---------|
| **AND** | Both rules must fire in the current detection window |
| **OR** | At least one rule must fire |
| **THEN** | The first rule must fire *before* the second (temporal order) |
        """
    )

    engine: RuleEngine = st.session_state["engine"]
    corr_engine: CorrelationEngine = st.session_state["corr_engine"]
    detections = st.session_state.get("detections", [])

    # ------------------------------------------------------------------
    # Layout: builder on the left, saved rules + results on the right
    # ------------------------------------------------------------------
    left, right = st.columns([1, 1], gap="large")

    # ==================== LEFT: Builder ====================
    with left:
        st.subheader("🛠️ Build a New Correlation Rule")

        with st.form("corr_rule_form", clear_on_submit=False):
            rule_name = st.text_input(
                "Rule Name",
                placeholder="e.g. Brute Force then Lateral Movement",
            )
            rule_desc = st.text_input(
                "Description (optional)",
                placeholder="Describe what this correlation detects",
            )
            st.form_submit_button("Set Rule Details ✏️", use_container_width=True)

        st.divider()

        # ---- Step builder ----
        st.markdown("#### 📋 Add Steps")

        # Collect available rule IDs from the SIEM engine
        rules_df = engine.rules_summary()
        predefined_ids = sorted(rules_df["rule_id"].tolist())
        step_choices = ["CUSTOM"] + predefined_ids

        # Step-choice labels for display
        id_to_name = dict(zip(rules_df["rule_id"], rules_df["name"]))

        col_a, col_b = st.columns([1, 1])
        with col_a:
            sel_rule_id = st.selectbox(
                "Rule ID",
                options=step_choices,
                format_func=lambda rid: (
                    f"{rid} – {id_to_name[rid]}" if rid in id_to_name else rid
                ),
                key="step_rule_id",
            )
        with col_b:
            draft_steps = st.session_state["corr_draft_steps"]
            op_options = ["AND", "OR", "THEN"]
            sel_op = st.selectbox(
                "Operator (join to previous step)",
                options=op_options,
                disabled=len(draft_steps) == 0,
                help="Ignored for the first step.",
                key="step_operator",
            )

        step_label = st.text_input(
            "Step Label (optional)",
            placeholder="Human-readable label",
            key="step_label",
        )

        custom_cond_str = ""
        if sel_rule_id == "CUSTOM":
            custom_cond_str = st.text_input(
                "Custom condition (field=value pairs, comma-separated)",
                placeholder='meta_action=login_failure, user_name=root',
                help='Example: meta_action=login_failure, severity=critical',
                key="step_custom",
            )

        col_add, col_clear = st.columns(2)
        with col_add:
            if st.button("➕ Add Step", use_container_width=True):
                custom_cond = None
                if sel_rule_id == "CUSTOM" and custom_cond_str.strip():
                    try:
                        custom_cond = dict(
                            pair.strip().split("=", 1)
                            for pair in custom_cond_str.split(",")
                            if "=" in pair
                        )
                    except Exception:
                        st.error("Invalid custom condition format. Use: key=value, key2=value2")
                        custom_cond = None

                operator = CorrelationOperator(sel_op) if draft_steps else CorrelationOperator.AND
                label = step_label.strip() or (
                    f"{sel_rule_id} – {id_to_name.get(sel_rule_id, '')}"
                    if sel_rule_id != "CUSTOM"
                    else "Custom condition"
                )
                step = CorrelationStep(
                    rule_id=sel_rule_id,
                    label=label,
                    operator=operator,
                    custom_condition=custom_cond,
                )
                st.session_state["corr_draft_steps"].append(step)
                st.rerun()

        with col_clear:
            if st.button("🗑️ Clear Steps", use_container_width=True):
                st.session_state["corr_draft_steps"] = []
                st.rerun()

        # ---- Preview current draft ----
        draft_steps = st.session_state["corr_draft_steps"]
        if draft_steps:
            st.markdown("#### 👁️ Rule Preview")
            for idx, step in enumerate(draft_steps):
                op_badge = (
                    f"**{step.operator.value}**" if idx > 0 else "*(start)*"
                )
                step_info = f"`{step.rule_id}`"
                if step.custom_condition:
                    pairs = ", ".join(f"`{k}={v}`" for k, v in step.custom_condition.items())
                    step_info += f" where {pairs}"
                st.markdown(
                    f"{op_badge} → **Step {idx + 1}**: {step.label} &nbsp; {step_info}"
                )

                # Per-step remove button
                if st.button(f"✖ Remove step {idx + 1}", key=f"rm_step_{idx}"):
                    st.session_state["corr_draft_steps"].pop(idx)
                    st.rerun()

        st.divider()

        # ---- Save rule ----
        col_save, col_enabled = st.columns([2, 1])
        with col_enabled:
            enabled_toggle = st.checkbox("Enabled", value=True, key="corr_enabled")
        with col_save:
            if st.button("💾 Save Correlation Rule", type="primary", use_container_width=True):
                if not rule_name.strip():
                    st.error("Please enter a rule name.")
                elif len(draft_steps) < 1:
                    st.error("Add at least one step before saving.")
                else:
                    cid = f"CORR-{st.session_state['corr_next_id']:03d}"
                    new_rule = CorrelationRule(
                        correlation_id=cid,
                        name=rule_name.strip(),
                        description=rule_desc.strip(),
                        steps=list(draft_steps),
                        enabled=enabled_toggle,
                    )
                    corr_engine.add_rule(new_rule)
                    st.session_state["corr_next_id"] += 1
                    st.session_state["corr_draft_steps"] = []
                    st.success(f"✅ Saved correlation rule **{cid}: {new_rule.name}**")
                    st.rerun()

    # ==================== RIGHT: Saved rules + results ====================
    with right:
        st.subheader(f"📂 Saved Correlation Rules ({len(corr_engine.rules)})")

        if not corr_engine.rules:
            st.info(
                "No correlation rules saved yet.  "
                "Use the builder on the left to create your first rule."
            )
        else:
            for rule in corr_engine.rules:
                exp_title = (
                    f"{'✅' if rule.enabled else '⏸️'} "
                    f"**{rule.correlation_id}** – {rule.name}"
                )
                with st.expander(exp_title, expanded=False):
                    if rule.description:
                        st.caption(rule.description)

                    # Step table
                    step_rows = []
                    for idx, step in enumerate(rule.steps):
                        op_str = step.operator.value if idx > 0 else "—"
                        cond = ""
                        if step.custom_condition:
                            cond = ", ".join(f"{k}={v}" for k, v in step.custom_condition.items())
                        step_rows.append({
                            "Step": idx + 1,
                            "Operator": op_str,
                            "Rule ID": step.rule_id,
                            "Label": step.label,
                            "Custom Condition": cond,
                        })
                    st.dataframe(pd.DataFrame(step_rows), hide_index=True, use_container_width=True)

                    col_en, col_del = st.columns(2)
                    with col_en:
                        if st.button(
                            "Disable" if rule.enabled else "Enable",
                            key=f"toggle_{rule.correlation_id}",
                        ):
                            rule.enabled = not rule.enabled
                            st.rerun()
                    with col_del:
                        if st.button("🗑 Delete", key=f"del_{rule.correlation_id}"):
                            corr_engine.remove_rule(rule.correlation_id)
                            st.rerun()

        st.divider()

        # ---- Run correlation against current detections ----
        st.subheader("▶ Run Correlation Engine")

        if not detections:
            st.info("Run the pipeline first to generate detections for correlation.")
        elif not corr_engine.rules:
            st.info("Create at least one correlation rule to run the engine.")
        else:
            det_count = len(detections)
            rule_count = len(corr_engine.rules)
            st.markdown(
                f"Evaluating **{rule_count}** correlation rule(s) against "
                f"**{det_count}** detection(s)."
            )

            if st.button("🔗 Run Correlation Rules", type="primary", use_container_width=True):
                matches = corr_engine.evaluate(detections)
                st.session_state["corr_matches"] = matches
                if matches:
                    st.success(f"⚡ {len(matches)} correlation rule(s) fired!")
                else:
                    st.info("No correlation rules matched the current detections.")
                st.rerun()

        # ---- Display matches ----
        matches = st.session_state.get("corr_matches", [])
        if matches:
            st.subheader(f"🚨 Correlation Matches ({len(matches)})")
            for match in matches:
                with st.expander(
                    f"🔗 **{match.correlation_id}** – {match.correlation_name}  "
                    f"({len(match.matched_rule_ids)} rule(s) matched)",
                    expanded=True,
                ):
                    st.markdown(
                        f"**Matched rules:** {', '.join(f'`{r}`' for r in match.matched_rule_ids)}"
                    )
                    st.caption(f"Evaluated at: {match.timestamp}")

                    if match.matched_detections:
                        det_rows = [d.to_dict() for d in match.matched_detections]
                        det_df = pd.DataFrame(det_rows)
                        display_cols = [
                            c for c in [
                                "timestamp", "rule_id", "rule_name", "severity",
                                "description", "mitre_tactic", "mitre_technique_id",
                            ]
                            if c in det_df.columns
                        ]
                        st.dataframe(
                            det_df[display_cols],
                            hide_index=True,
                            use_container_width=True,
                        )

            # Export matches
            if st.button("⬇️ Export Correlation Matches CSV"):
                rows = [m.to_dict() for m in matches]
                csv = pd.DataFrame(rows).to_csv(index=False)
                st.download_button(
                    "Download correlation_matches.csv",
                    data=csv,
                    file_name="correlation_matches.csv",
                    mime="text/csv",
                )


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------

def main() -> None:
    _render_sidebar()

    st.title("🛡️ BlackStarSIEM v2 – Open Security Lake")
    st.caption(
        "Data ingestion via Kafka → Apache Iceberg storage → "
        "Spark/DuckDB analytics → Python SIEM rules"
    )

    tab_arch, tab_events, tab_analytics, tab_rules, tab_detections, tab_spark, tab_corr = st.tabs([
        "🏗️ Architecture",
        "📋 Events",
        "📈 Analytics",
        "🔎 Detection Rules",
        "🚨 Alerts",
        "⚡ Spark & Iceberg",
        "🔗 Correlation Rules",
    ])

    with tab_arch:
        _tab_architecture()
    with tab_events:
        _tab_events()
    with tab_analytics:
        _tab_analytics()
    with tab_rules:
        _tab_rules()
    with tab_detections:
        _tab_detections()
    with tab_spark:
        _tab_spark_iceberg()
    with tab_corr:
        _tab_correlation()


if __name__ == "__main__":
    main()
