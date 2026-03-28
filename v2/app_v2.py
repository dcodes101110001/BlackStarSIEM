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
# Navigation pages (ordered list used by sidebar and main renderer)
# ---------------------------------------------------------------------------

_NAV_PAGES = [
    ("🏗️ Architecture", "Architecture"),
    ("📋 Events", "Events"),
    ("📈 Analytics", "Analytics"),
    ("🔎 Detection Rules", "Detection Rules"),
    ("🚨 Alerts", "Alerts"),
    ("🎯 MITRE ATT&CK", "MITRE ATT&CK"),
    ("⚡ Spark & Iceberg", "Spark & Iceberg"),
]


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_sidebar() -> str:
    """Render the sidebar and return the currently selected page key."""
    with st.sidebar:
        st.image(
            "https://img.shields.io/badge/BlackStarSIEM-v2-blue?style=for-the-badge",
            width=250,
        )
        st.markdown("## 🛡️ BlackStarSIEM v2")
        st.caption("Open Security Lake Architecture")

        st.divider()
        st.markdown("### 🗺️ Navigation")
        page_labels = [label for label, _ in _NAV_PAGES]
        selected_label = st.radio(
            "Go to",
            page_labels,
            label_visibility="collapsed",
        )
        # Map label → key
        selected_key = next(
            key for label, key in _NAV_PAGES if label == selected_label
        )

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

    return selected_key


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
# Tab: Detections / Alerts (with filtering + sorting)
# ---------------------------------------------------------------------------

_SEV_COLOURS: Dict[str, str] = {
    "informational": "#28a745",
    "low": "#17a2b8",
    "medium": "#ffc107",
    "high": "#fd7e14",
    "critical": "#dc3545",
}


def _tab_detections() -> None:
    st.header("🚨 Detections & Alerts")
    detections = st.session_state.get("detections", [])

    if not detections:
        if st.session_state.get("scan_run"):
            st.success("✅ No detections – all clear for this run!")
        else:
            st.info("Run the pipeline to generate detections.")
        return

    det_df = pd.DataFrame([d.to_dict() for d in detections])

    # ── Summary metrics ──────────────────────────────────────────────────────
    sev_counts = det_df["severity"].value_counts().to_dict()
    cols = st.columns(5)
    for idx, sev in enumerate(["critical", "high", "medium", "low", "informational"]):
        with cols[idx]:
            st.metric(sev.upper(), sev_counts.get(sev, 0))

    st.divider()

    # ── Filters ──────────────────────────────────────────────────────────────
    with st.expander("🔍 Filters & Sorting", expanded=True):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            all_sevs = ["All"] + sorted(det_df["severity"].dropna().unique().tolist())
            sel_sev = st.selectbox("Severity", all_sevs, key="alert_sev_filter")
        with f2:
            all_tactics = ["All"] + sorted(
                det_df["mitre_tactic"].dropna().unique().tolist()
            )
            sel_tactic = st.selectbox("MITRE Tactic", all_tactics, key="alert_tactic_filter")
        with f3:
            all_rules = ["All"] + sorted(det_df["rule_id"].dropna().unique().tolist())
            sel_rule = st.selectbox("Rule", all_rules, key="alert_rule_filter")
        with f4:
            min_conf = st.slider(
                "Min Confidence", 0.0, 1.0, 0.0, 0.05, key="alert_conf_filter"
            )

        s1, s2 = st.columns(2)
        with s1:
            sort_field = st.selectbox(
                "Sort by",
                ["severity_id", "timestamp", "rule_id", "mitre_tactic", "confidence"],
                key="alert_sort_field",
            )
        with s2:
            sort_asc = st.radio(
                "Order", ["Descending", "Ascending"],
                horizontal=True, key="alert_sort_order"
            ) == "Ascending"

    # Apply filters
    filtered = det_df.copy()
    if sel_sev != "All":
        filtered = filtered[filtered["severity"] == sel_sev]
    if sel_tactic != "All":
        filtered = filtered[filtered["mitre_tactic"] == sel_tactic]
    if sel_rule != "All":
        filtered = filtered[filtered["rule_id"] == sel_rule]
    filtered = filtered[filtered["confidence"] >= min_conf]

    # Apply sort
    filtered = filtered.sort_values(sort_field, ascending=sort_asc)

    st.caption(f"Showing **{len(filtered)}** of **{len(det_df)}** detections")

    # ── Table + charts ────────────────────────────────────────────────────────
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader(f"Detection Log ({len(filtered)} alerts)")
        display_cols = [
            c for c in [
                "timestamp", "severity", "rule_id", "rule_name",
                "description", "mitre_tactic", "mitre_technique_id",
                "event_message", "confidence",
            ]
            if c in filtered.columns
        ]
        st.dataframe(filtered[display_cols], hide_index=True, use_container_width=True)

        csv = filtered.to_csv(index=False)
        st.download_button(
            "⬇️ Export Filtered Detections CSV",
            data=csv,
            file_name="blackstar_detections.csv",
            mime="text/csv",
        )

    with col2:
        rule_counts = filtered["rule_id"].value_counts().reset_index()
        rule_counts.columns = ["rule_id", "count"]
        fig = px.bar(rule_counts, x="count", y="rule_id", orientation="h",
                     title="Detections by Rule")
        st.plotly_chart(fig, use_container_width=True)

        sev_df2 = filtered["severity"].value_counts().reset_index()
        sev_df2.columns = ["severity", "count"]
        fig2 = px.pie(
            sev_df2, names="severity", values="count",
            title="Detections by Severity",
            color="severity", color_discrete_map=_SEV_COLOURS, hole=0.4,
        )
        st.plotly_chart(fig2, use_container_width=True)


# ---------------------------------------------------------------------------
# Section: MITRE ATT&CK Detections Dashboard
# ---------------------------------------------------------------------------

# Enterprise ATT&CK tactics in canonical order (abridged for rules present)
_MITRE_TACTICS_ORDER: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _tab_mitre_attack() -> None:
    st.header("🎯 MITRE ATT&CK Detections Dashboard")
    st.caption(
        "Detections from the current pipeline run mapped onto the "
        "[MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)."
    )

    detections = st.session_state.get("detections", [])
    engine: RuleEngine = st.session_state["engine"]

    if not detections and not st.session_state.get("scan_run"):
        st.info("Run the pipeline first to populate the MITRE ATT&CK coverage map.")

    # ── Build coverage tables ─────────────────────────────────────────────────
    # All rules → coverage (what the engine *can* detect)
    rules_df = engine.rules_summary()
    all_techniques: Dict[str, Dict] = {}  # technique_id → {tactic, name, rule_ids}
    for row in rules_df.itertuples(index=False):
        tid = str(getattr(row, "mitre_technique_id", "") or "").strip()
        tactic = str(getattr(row, "mitre_tactic", "") or "").strip()
        tname = str(getattr(row, "name", "") or "").strip()
        rid = str(getattr(row, "rule_id", "") or "").strip()
        if tid and rid:
            if tid not in all_techniques:
                all_techniques[tid] = {
                    "tactic": tactic, "technique": tname, "rule_ids": []
                }
            all_techniques[tid]["rule_ids"].append(rid)

    # Active detections → which technique IDs fired
    det_df: pd.DataFrame = (
        pd.DataFrame([d.to_dict() for d in detections])
        if detections else pd.DataFrame()
    )
    fired_techniques: Dict[str, int] = {}  # technique_id → count
    if not det_df.empty and "mitre_technique_id" in det_df.columns:
        for tid, cnt in det_df["mitre_technique_id"].value_counts().items():
            if str(tid).strip():
                fired_techniques[str(tid).strip()] = int(cnt)

    # ── Summary coverage strip ────────────────────────────────────────────────
    tactics_with_coverage = {
        info["tactic"] for info in all_techniques.values() if info["tactic"]
    }
    tactics_with_detections = {
        all_techniques[tid]["tactic"]
        for tid in fired_techniques
        if tid in all_techniques and all_techniques[tid]["tactic"]
    }

    st.subheader("📊 Coverage Summary")
    sm1, sm2, sm3 = st.columns(3)
    sm1.metric("Tactics Covered by Rules", len(tactics_with_coverage))
    sm2.metric("Techniques Covered by Rules", len(all_techniques))
    sm3.metric("Techniques with Active Detections", len(fired_techniques))

    st.divider()

    # ── ATT&CK Matrix heat-map ────────────────────────────────────────────────
    st.subheader("🗺️ ATT&CK Matrix")
    st.caption(
        "🟦 Rule exists (covered)  │  🟥 Active detection(s)  │  ⬜ Not covered"
    )

    # Group techniques by tactic (preserve canonical tactic order)
    tactic_techniques: Dict[str, List[Dict]] = {t: [] for t in _MITRE_TACTICS_ORDER}
    for tid, info in all_techniques.items():
        tactic = info["tactic"]
        if tactic in tactic_techniques:
            tactic_techniques[tactic].append(
                {
                    "tid": tid,
                    "technique": info["technique"],
                    "rule_ids": info["rule_ids"],
                    "fired": fired_techniques.get(tid, 0),
                }
            )
        else:
            # Tactic not in our ordered list → add at end
            if tactic not in tactic_techniques:
                tactic_techniques[tactic] = []
            tactic_techniques[tactic].append(
                {
                    "tid": tid,
                    "technique": info["technique"],
                    "rule_ids": info["rule_ids"],
                    "fired": fired_techniques.get(tid, 0),
                }
            )

    # Only show tactics that have at least one covered technique
    active_tactics = [
        t for t in _MITRE_TACTICS_ORDER if tactic_techniques.get(t)
    ]

    # Render as a Plotly heatmap grid
    if active_tactics:
        max_rows = max(len(tactic_techniques[t]) for t in active_tactics)
        z_vals: List[List[float]] = []
        hover_text: List[List[str]] = []
        annotations_list = []

        for row_idx in range(max_rows):
            z_row: List[float] = []
            hover_row: List[str] = []
            for col_idx, tactic in enumerate(active_tactics):
                techs = tactic_techniques[tactic]
                if row_idx < len(techs):
                    tech = techs[row_idx]
                    if tech["fired"] > 0:
                        z_val = 2.0  # active detection
                        cell_text = f"{tech['tid']}\n({tech['fired']} hit)"
                    else:
                        z_val = 1.0  # covered, no detection
                        cell_text = tech["tid"]
                    hover_row.append(
                        f"<b>{tech['technique']}</b><br>"
                        f"Technique: {tech['tid']}<br>"
                        f"Rules: {', '.join(tech['rule_ids'])}<br>"
                        f"Detections: {tech['fired']}"
                    )
                    annotations_list.append(
                        dict(
                            x=col_idx,
                            y=row_idx,
                            text=cell_text,
                            showarrow=False,
                            font=dict(color="white", size=9),
                            xanchor="center",
                            yanchor="middle",
                        )
                    )
                else:
                    z_val = 0.0  # empty cell
                    hover_row.append("")
                z_row.append(z_val)
            z_vals.append(z_row)
            hover_text.append(hover_row)

        colorscale = [
            [0.0, "#1a1a2e"],   # empty
            [0.5, "#1565c0"],   # covered (blue)
            [1.0, "#c62828"],   # active detection (red)
        ]

        fig_matrix = go.Figure(
            data=go.Heatmap(
                z=z_vals,
                x=active_tactics,
                colorscale=colorscale,
                showscale=False,
                hovertext=hover_text,
                hovertemplate="%{hovertext}<extra></extra>",
                xgap=2,
                ygap=2,
            )
        )
        fig_matrix.update_layout(
            height=max(300, max_rows * 36 + 80),
            margin=dict(l=10, r=10, t=40, b=80),
            xaxis=dict(
                tickangle=-30,
                tickfont=dict(size=11),
                side="top",
            ),
            yaxis=dict(visible=False),
            annotations=annotations_list,
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            font=dict(color="white"),
        )
        st.plotly_chart(fig_matrix, use_container_width=True)

    st.divider()

    # ── Technique-level detail table ──────────────────────────────────────────
    st.subheader("📋 Technique Coverage Detail")
    detail_rows = []
    for tid, info in all_techniques.items():
        fired = fired_techniques.get(tid, 0)
        detail_rows.append(
            {
                "Technique ID": tid,
                "Technique": info["technique"],
                "Tactic": info["tactic"],
                "Rules": ", ".join(info["rule_ids"]),
                "Detections": fired,
                "Status": "🔴 Active" if fired > 0 else "🔵 Covered",
            }
        )
    detail_df = pd.DataFrame(detail_rows).sort_values(
        ["Detections", "Tactic"], ascending=[False, True]
    )
    st.dataframe(detail_df, hide_index=True, use_container_width=True)

    # ── Tactic-level bar chart ────────────────────────────────────────────────
    if not det_df.empty and "mitre_tactic" in det_df.columns:
        st.subheader("📊 Detections by Tactic")
        tactic_counts = (
            det_df["mitre_tactic"]
            .value_counts()
            .reset_index()
        )
        tactic_counts.columns = ["tactic", "count"]
        fig_tac = px.bar(
            tactic_counts,
            x="tactic",
            y="count",
            color="tactic",
            title="Detection Count by MITRE ATT&CK Tactic",
        )
        fig_tac.update_layout(showlegend=False)
        st.plotly_chart(fig_tac, use_container_width=True)


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
# Main layout
# ---------------------------------------------------------------------------

def main() -> None:
    selected_page = _render_sidebar()

    st.title("🛡️ BlackStarSIEM v2 – Open Security Lake")
    st.caption(
        "Data ingestion via Kafka → Apache Iceberg storage → "
        "Spark/DuckDB analytics → Python SIEM rules"
    )

    if selected_page == "Architecture":
        _tab_architecture()
    elif selected_page == "Events":
        _tab_events()
    elif selected_page == "Analytics":
        _tab_analytics()
    elif selected_page == "Detection Rules":
        _tab_rules()
    elif selected_page == "Alerts":
        _tab_detections()
    elif selected_page == "MITRE ATT&CK":
        _tab_mitre_attack()
    elif selected_page == "Spark & Iceberg":
        _tab_spark_iceberg()


if __name__ == "__main__":
    main()
