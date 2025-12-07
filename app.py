"""
BlackStar SIEM - Elastic SIEM Lab in Streamlit
A comprehensive SIEM lab interface built with Streamlit for learning and experimenting with Elastic SIEM.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from elasticsearch import Elasticsearch
import random
import json
from typing import Dict, List, Any
import tempfile
import os

# Import YARAL engine
from yaral_engine import YARALEngine, YARALRule, get_sample_yaral_rules, validate_yaral_rule

# Page configuration
st.set_page_config(
    page_title="BlackStar SIEM Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 20px;
        background: linear-gradient(90deg, #1f77b4 0%, #ff7f0e 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .alert-box {
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .alert-critical {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
    }
    .alert-warning {
        background-color: #fff3e0;
        border-left: 5px solid #ff9800;
    }
    .alert-info {
        background-color: #e3f2fd;
        border-left: 5px solid #2196f3;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'es_connected' not in st.session_state:
    st.session_state.es_connected = False
if 'es_client' not in st.session_state:
    st.session_state.es_client = None
if 'simulated_events' not in st.session_state:
    st.session_state.simulated_events = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'yaral_engine' not in st.session_state:
    st.session_state.yaral_engine = YARALEngine()
if 'yaral_matches' not in st.session_state:
    st.session_state.yaral_matches = []

def get_udm_event_mapping():
    """Get UDM/ECS mapping for event types"""
    return {
        'nmap_scan': {'category': 'network', 'type': 'info', 'kind': 'event', 'outcome': None},
        'ssh_login': {'category': 'authentication', 'type': 'start', 'kind': 'event', 'outcome': None},
        'failed_login': {'category': 'authentication', 'type': 'start', 'kind': 'event', 'outcome': 'failure'},
        'port_scan': {'category': 'network', 'type': 'connection', 'kind': 'event', 'outcome': None},
        'file_access': {'category': 'file', 'type': 'access', 'kind': 'event', 'outcome': None},
        'process_creation': {'category': 'process', 'type': 'start', 'kind': 'event', 'outcome': 'success'}
    }

def connect_to_elastic(cloud_id, api_key):
    """Connect to Elastic Cloud with comprehensive error handling"""
    try:
        es = Elasticsearch(
            cloud_id=cloud_id,
            api_key=api_key,
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3,
            verify_certs=True  # Enable SSL certificate verification
        )
        # Test connection with info() call instead of ping()
        # ping() may not work with API keys in some configurations
        info = es.info()
        if info:
            st.session_state.es_client = es
            st.session_state.es_connected = True
            return True, f"Successfully connected to Elastic Cloud! (Cluster: {info.get('cluster_name', 'N/A')})"
        else:
            return False, "Failed to connect to Elastic Cloud"
    except Exception as e:
        # Provide detailed, actionable error messages
        error_message = str(e).lower()
        
        # Authentication errors
        if 'unauthorized' in error_message or 'authentication' in error_message or '401' in error_message:
            return False, (
                "❌ Authentication Failed\n\n"
                "Your API key or Cloud ID is invalid.\n\n"
                "✅ Steps to fix:\n"
                "1. Verify your API key is active in Elastic Cloud\n"
                "2. Ensure the API key has proper permissions\n"
                "3. Check that the Cloud ID matches your deployment\n"
                "4. Try generating a new API key"
            )
        
        # SSL/Certificate errors
        elif 'ssl' in error_message or 'certificate' in error_message or 'verify' in error_message:
            return False, (
                "❌ SSL Certificate Verification Failed\n\n"
                "SSL certificate verification is enabled for security. The connection failed because the certificate could not be verified.\n\n"
                "✅ Steps to fix:\n"
                "1. Check your internet connection\n"
                "2. Verify system certificates are up to date\n"
                "3. If behind a corporate proxy, contact your network administrator\n"
                "4. Ensure the Cloud ID is correct and the deployment is accessible\n\n"
                f"Technical details: {str(e)}"
            )
        
        # Connection/Network errors
        elif 'timeout' in error_message or 'connection' in error_message or 'network' in error_message:
            return False, (
                "❌ Connection Timeout\n\n"
                "Cannot reach your Elastic Cloud deployment.\n\n"
                "✅ Steps to fix:\n"
                "1. Check your internet connection\n"
                "2. Verify the Cloud ID is correct\n"
                "3. Ensure Elastic Cloud is not experiencing outages\n"
                "4. Check if you're behind a firewall blocking the connection\n"
                "5. Try again in a few moments\n\n"
                f"Technical details: {str(e)}"
            )
        
        # Cloud ID format errors
        elif 'cloud_id' in error_message or 'base64' in error_message:
            return False, (
                "❌ Invalid Cloud ID Format\n\n"
                "The Cloud ID you provided appears to be malformed.\n\n"
                "✅ Steps to fix:\n"
                "1. Copy the Cloud ID directly from Elastic Cloud console\n"
                "2. Ensure there are no extra spaces or characters\n"
                "3. Cloud ID should look like: 'deployment-name:base64string'\n\n"
                f"Technical details: {str(e)}"
            )
        
        # Generic error with helpful context
        else:
            return False, (
                f"❌ Connection Error\n\n"
                f"An unexpected error occurred while connecting to Elastic Cloud.\n\n"
                f"Error details: {str(e)}\n\n"
                "✅ General troubleshooting:\n"
                "1. Verify your Cloud ID and API key are correct\n"
                "2. Check your network connection\n"
                "3. Ensure Elastic Cloud deployment is running\n"
                "4. Try using Demo Mode to test the application\n"
                "5. Check Elastic Cloud status page for outages"
            )

def convert_to_udm(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert security event to Unified Data Model (UDM) format.
    UDM provides a standardized way to represent security data.
    """
    udm_event = {
        "metadata": {
            "event_timestamp": event.get('timestamp', datetime.now()).isoformat() if isinstance(event.get('timestamp'), datetime) else event.get('timestamp'),
            "event_type": map_event_type_to_udm(event.get('event.action', 'GENERIC_EVENT')),
            "product_name": "BlackStar SIEM",
            "vendor_name": "BlackStar",
            "product_event_type": event.get('event.action', ''),
            "severity": map_severity_to_udm(event.get('event.severity', 'low'))
        },
        "principal": {
            "ip": [event.get('source.ip', '')],
            "user": {
                "userid": event.get('user.name', '')
            }
        },
        "target": {
            "ip": [event.get('destination.ip', '')],
            "port": event.get('destination.port', 0)
        },
        "network": {
            "session_id": f"{event.get('source.ip', '')}_{event.get('destination.ip', '')}_{event.get('timestamp', '')}",
            "direction": "OUTBOUND"
        },
        "security_result": [{
            "action": event.get('event.outcome', 'UNKNOWN'),
            "description": event.get('message', ''),
            "severity": map_severity_to_udm(event.get('event.severity', 'low'))
        }],
        "extensions": {
            "auth": {
                "type": "LOGIN" if 'login' in event.get('event.action', '').lower() else "UNKNOWN"
            }
        }
    }
    
    return udm_event

def map_event_type_to_udm(event_action: str) -> str:
    """Map event action to UDM event type"""
    event_type_mapping = {
        'nmap_scan': 'SCAN_NETWORK',
        'ssh_login': 'USER_LOGIN',
        'failed_login': 'USER_LOGIN',
        'port_scan': 'SCAN_PORT',
        'file_access': 'FILE_READ',
        'process_creation': 'PROCESS_LAUNCH'
    }
    return event_type_mapping.get(event_action, 'GENERIC_EVENT')

def map_severity_to_udm(severity: str) -> str:
    """Map severity to UDM severity"""
    severity_mapping = {
        'low': 'LOW',
        'medium': 'MEDIUM',
        'high': 'HIGH',
        'critical': 'CRITICAL'
    }
    return severity_mapping.get(severity.lower(), 'INFORMATIONAL')

def generate_sample_events(count=100):
    """Generate sample security events in UDM/ECS format for demonstration"""
    events = []
    event_types = ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access', 'process_creation']
    severities = ['low', 'medium', 'high', 'critical']
    source_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.10', '203.0.113.5']
    
    # Get UDM/ECS mapping
    event_mapping = get_udm_event_mapping()
    
    for i in range(count):
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        event_type = random.choice(event_types)
        event_meta = event_mapping[event_type]
        # Use predetermined outcome if specified, otherwise random
        outcome = event_meta['outcome'] if event_meta['outcome'] else random.choice(['success', 'failure'])
        severity = random.choice(severities)
        src_ip = random.choice(source_ips)
        
        # UDM/ECS compliant event structure
        event = {
            # Core timestamp
            '@timestamp': timestamp.isoformat(),
            'timestamp': timestamp,
            
            # Event categorization (UDM/ECS)
            'event.kind': event_meta['kind'],
            'event.category': event_meta['category'],
            'event.type': event_meta['type'],
            'event.action': event_type,
            'event.outcome': outcome,
            'event.severity': severity,
            'event.dataset': 'blackstar.siem',
            'event.module': 'blackstar',
            
            # Source information
            'source.ip': src_ip,
            'source.address': src_ip,
            
            # Destination information
            'destination.ip': '192.168.1.50',
            'destination.address': '192.168.1.50',
            'destination.port': random.choice([22, 80, 443, 3389, 8080]),
            
            # User information
            'user.name': random.choice(['admin', 'user1', 'root', 'service_account']),
            
            # Additional metadata
            'message': f'Security event detected: {event_type}',
            'host.name': 'blackstar-siem-host',
            'agent.type': 'blackstar-agent',
            'agent.version': '1.0.0'
        }
        # Add UDM version
        event['udm'] = convert_to_udm(event)
        events.append(event)
    
    return events

def create_event_timeline(events_df):
    """Create timeline visualization of events"""
    timeline_data = events_df.groupby([pd.Grouper(key='timestamp', freq='1H'), 'event.severity']).size().reset_index(name='count')
    
    fig = px.area(
        timeline_data,
        x='timestamp',
        y='count',
        color='event.severity',
        title='Security Events Timeline',
        labels={'count': 'Event Count', 'timestamp': 'Time'},
        color_discrete_map={
            'low': '#4caf50',
            'medium': '#ff9800',
            'high': '#ff5722',
            'critical': '#f44336'
        }
    )
    fig.update_layout(height=400)
    return fig

def create_event_distribution(events_df):
    """Create event type distribution chart"""
    event_counts = events_df['event.action'].value_counts()
    
    fig = px.pie(
        values=event_counts.values,
        names=event_counts.index,
        title='Event Type Distribution',
        hole=0.4
    )
    fig.update_layout(height=400)
    return fig

def create_severity_chart(events_df):
    """Create severity distribution chart"""
    severity_counts = events_df['event.severity'].value_counts()
    
    fig = go.Figure(data=[
        go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            marker_color=['#4caf50', '#ff9800', '#ff5722', '#f44336']
        )
    ])
    fig.update_layout(
        title='Events by Severity',
        xaxis_title='Severity',
        yaxis_title='Count',
        height=400
    )
    return fig

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ BlackStar SIEM Lab</h1>', unsafe_allow_html=True)
    st.markdown("### Elastic SIEM Learning Environment")
    
    # Sidebar - Configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        with st.expander("🔌 Elastic Cloud Connection", expanded=not st.session_state.es_connected):
            st.markdown("Connect to your Elastic Cloud deployment")
            
            cloud_id = st.text_input(
                "Cloud ID",
                type="password",
                help="Your Elastic Cloud deployment ID"
            )
            api_key = st.text_input(
                "API Key",
                type="password",
                help="Your Elastic API key"
            )
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Connect", type="primary"):
                    if cloud_id and api_key:
                        success, message = connect_to_elastic(cloud_id, api_key)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                    else:
                        st.warning("Please provide both Cloud ID and API Key")
            
            with col2:
                if st.button("Use Demo Mode"):
                    st.session_state.es_connected = True
                    st.session_state.simulated_events = generate_sample_events()
                    st.success("Demo mode activated!")
                    st.rerun()
        
        # Connection status
        if st.session_state.es_connected:
            st.success("✅ Connected")
        else:
            st.info("ℹ️ Not connected - Use Demo Mode to explore")
        
        st.divider()
        
        # Simulation controls
        if st.session_state.es_connected:
            st.header("🎯 Event Simulation")
            
            event_type = st.selectbox(
                "Event Type",
                ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access', 'process_creation']
            )
            
            if st.button("Simulate Event"):
                # Get UDM/ECS mapping
                event_mapping = get_udm_event_mapping()
                event_meta = event_mapping.get(event_type, {'category': 'network', 'type': 'info', 'kind': 'event', 'outcome': None})
                timestamp = datetime.now()
                severity = random.choice(['low', 'medium', 'high', 'critical'])
                # Use predetermined outcome if specified, otherwise use 'success'
                outcome = event_meta['outcome'] if event_meta['outcome'] else 'success'
                
                # UDM/ECS compliant simulated event
                new_event = {
                    '@timestamp': timestamp.isoformat(),
                    'timestamp': timestamp,
                    'event.kind': event_meta['kind'],
                    'event.category': event_meta['category'],
                    'event.type': event_meta['type'],
                    'event.action': event_type,
                    'event.severity': severity,
                    'event.outcome': outcome,
                    'event.dataset': 'blackstar.siem',
                    'event.module': 'blackstar',
                    'source.ip': '192.168.1.100',
                    'source.address': '192.168.1.100',
                    'destination.ip': '192.168.1.50',
                    'destination.address': '192.168.1.50',
                    'destination.port': 22 if 'ssh' in event_type else 80,
                    'user.name': 'simulated_user',
                    'message': f'Simulated {event_type} event',
                    'host.name': 'blackstar-siem-host',
                    'agent.type': 'blackstar-agent',
                    'agent.version': '1.0.0'
                }
                # Add UDM version
                new_event['udm'] = convert_to_udm(new_event)
                st.session_state.simulated_events.append(new_event)
                st.success(f"Simulated {event_type} event!")
                st.rerun()
    
    # Main content
    if not st.session_state.es_connected:
        # Welcome screen
        st.info("👋 Welcome to BlackStar SIEM Lab! Connect to Elastic Cloud or use Demo Mode to get started.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            ### 🎓 What is this?
            BlackStar SIEM Lab is an interactive learning environment for:
            - Understanding SIEM concepts
            - Analyzing security events
            - Creating visualizations
            - Setting up alerts
            - Simulating security scenarios
            """)
        
        with col2:
            st.markdown("""
            ### 🚀 Getting Started
            1. Connect to your Elastic Cloud deployment, OR
            2. Click "Use Demo Mode" in the sidebar
            3. Explore security events and analytics
            4. Create custom alerts
            5. Simulate security events
            """)
        
        st.markdown("---")
        st.markdown("""
        ### 📚 Features
        - **Real-time Event Monitoring**: View and filter security events
        - **Visual Analytics**: Interactive charts and dashboards
        - **Alert Management**: Create and manage custom alert rules
        - **Event Simulation**: Generate test events for learning
        """)
        
    else:
        # Main dashboard tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Dashboard", "🔍 Events", "📈 Analytics", "🚨 Alerts", "🔬 YARAL"])
        
        # Get events (from Elastic or simulated)
        if st.session_state.simulated_events:
            events_df = pd.DataFrame(st.session_state.simulated_events)
        else:
            # In a real implementation, query Elastic here
            events_df = pd.DataFrame(generate_sample_events())
        
        with tab1:
            # Dashboard overview
            st.header("Security Overview")
            
            # Metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_events = len(events_df)
                st.metric("Total Events", f"{total_events:,}")
            
            with col2:
                critical_events = len(events_df[events_df['event.severity'] == 'critical'])
                st.metric("Critical Events", critical_events, delta=f"{critical_events}")
            
            with col3:
                unique_ips = events_df['source.ip'].nunique()
                st.metric("Unique Source IPs", unique_ips)
            
            with col4:
                failed_events = len(events_df[events_df['event.outcome'] == 'failure'])
                st.metric("Failed Events", failed_events)
            
            st.divider()
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(create_event_timeline(events_df), use_container_width=True)
            
            with col2:
                st.plotly_chart(create_event_distribution(events_df), use_container_width=True)
            
            # Severity chart
            st.plotly_chart(create_severity_chart(events_df), use_container_width=True)
        
        with tab2:
            # Events viewer
            st.header("Security Events Log")
            
            # Filters
            col1, col2, col3 = st.columns(3)
            
            with col1:
                severity_filter = st.multiselect(
                    "Severity",
                    options=events_df['event.severity'].unique(),
                    default=events_df['event.severity'].unique()
                )
            
            with col2:
                event_type_filter = st.multiselect(
                    "Event Type",
                    options=events_df['event.action'].unique(),
                    default=events_df['event.action'].unique()
                )
            
            with col3:
                outcome_filter = st.multiselect(
                    "Outcome",
                    options=events_df['event.outcome'].unique(),
                    default=events_df['event.outcome'].unique()
                )
            
            # Apply filters
            filtered_df = events_df[
                (events_df['event.severity'].isin(severity_filter)) &
                (events_df['event.action'].isin(event_type_filter)) &
                (events_df['event.outcome'].isin(outcome_filter))
            ]
            
            st.info(f"Showing {len(filtered_df)} of {len(events_df)} events")
            
            # Display events
            st.dataframe(
                filtered_df.sort_values('timestamp', ascending=False),
                use_container_width=True,
                height=500
            )
            
            # Export option
            col_exp1, col_exp2 = st.columns(2)
            with col_exp1:
                if st.button("📥 Export to CSV"):
                    csv = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            
            with col_exp2:
                if st.button("📋 Export UDM Format"):
                    # Convert filtered events to UDM format
                    udm_events = []
                    for _, event in filtered_df.iterrows():
                        if 'udm' in event and event['udm']:
                            udm_events.append(event['udm'])
                        else:
                            udm_events.append(convert_to_udm(event.to_dict()))
                    
                    udm_json = json.dumps(udm_events, indent=2, default=str)
                    st.download_button(
                        label="Download UDM JSON",
                        data=udm_json,
                        file_name=f"siem_events_udm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            # UDM Viewer
            st.divider()
            st.subheader("🔍 UDM Format Viewer")
            if len(filtered_df) > 0:
                selected_event_idx = st.selectbox(
                    "Select event to view in UDM format:",
                    range(len(filtered_df)),
                    format_func=lambda x: f"Event {x+1}: {filtered_df.iloc[x]['event.action']} at {filtered_df.iloc[x]['timestamp']}"
                )
                
                if selected_event_idx is not None:
                    selected_event = filtered_df.iloc[selected_event_idx]
                    if 'udm' in selected_event and selected_event['udm']:
                        udm_data = selected_event['udm']
                    else:
                        udm_data = convert_to_udm(selected_event.to_dict())
                    
                    st.json(udm_data)
        
        with tab3:
            # Analytics
            st.header("Security Analytics")
            
            # Top source IPs
            st.subheader("Top Source IPs")
            top_ips = events_df['source.ip'].value_counts().head(10)
            fig_ips = px.bar(
                x=top_ips.values,
                y=top_ips.index,
                orientation='h',
                labels={'x': 'Event Count', 'y': 'Source IP'},
                title='Most Active Source IPs'
            )
            st.plotly_chart(fig_ips, use_container_width=True)
            
            # Event outcome analysis
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Event Outcomes")
                outcome_counts = events_df['event.outcome'].value_counts()
                fig_outcome = px.pie(
                    values=outcome_counts.values,
                    names=outcome_counts.index,
                    title='Success vs Failure'
                )
                st.plotly_chart(fig_outcome, use_container_width=True)
            
            with col2:
                st.subheader("Top Users")
                user_counts = events_df['user.name'].value_counts().head(5)
                st.dataframe(
                    user_counts.reset_index().rename(columns={'index': 'User', 'user.name': 'Events'}),
                    use_container_width=True
                )
            
            # Time-based analysis
            st.subheader("Events by Hour")
            events_df['hour'] = pd.to_datetime(events_df['timestamp']).dt.hour
            hourly_events = events_df.groupby('hour').size()
            fig_hourly = px.line(
                x=hourly_events.index,
                y=hourly_events.values,
                labels={'x': 'Hour of Day', 'y': 'Event Count'},
                title='Event Distribution by Hour'
            )
            st.plotly_chart(fig_hourly, use_container_width=True)
        
        with tab4:
            # Alerts management
            st.header("Alert Rules")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("Create New Alert Rule")
                
                alert_name = st.text_input("Alert Name", placeholder="e.g., Nmap Scan Detected")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    alert_event_type = st.selectbox(
                        "Event Type to Monitor",
                        ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access', 'process_creation']
                    )
                
                with col_b:
                    alert_severity = st.selectbox(
                        "Minimum Severity",
                        ['low', 'medium', 'high', 'critical']
                    )
                
                alert_threshold = st.number_input("Trigger after X events", min_value=1, value=5)
                alert_description = st.text_area("Description", placeholder="Describe what this alert detects...")
                
                if st.button("Create Alert Rule", type="primary"):
                    new_alert = {
                        'name': alert_name,
                        'event_type': alert_event_type,
                        'severity': alert_severity,
                        'threshold': alert_threshold,
                        'description': alert_description,
                        'created_at': datetime.now(),
                        'enabled': True
                    }
                    st.session_state.alerts.append(new_alert)
                    st.success(f"Alert rule '{alert_name}' created!")
            
            with col2:
                st.subheader("Active Alerts")
                st.metric("Total Rules", len(st.session_state.alerts))
                
                # Check for triggered alerts
                triggered = 0
                for alert in st.session_state.alerts:
                    matching_events = events_df[
                        events_df['event.action'] == alert['event_type']
                    ]
                    if len(matching_events) >= alert['threshold']:
                        triggered += 1
                
                st.metric("Triggered", triggered, delta=f"+{triggered}")
            
            st.divider()
            
            # Display existing alerts
            if st.session_state.alerts:
                st.subheader("Configured Alert Rules")
                
                for idx, alert in enumerate(st.session_state.alerts):
                    with st.expander(f"📋 {alert['name']}", expanded=False):
                        col_x, col_y = st.columns([3, 1])
                        
                        with col_x:
                            st.write(f"**Event Type:** {alert['event_type']}")
                            st.write(f"**Severity:** {alert['severity']}")
                            st.write(f"**Threshold:** {alert['threshold']} events")
                            st.write(f"**Description:** {alert['description']}")
                            st.write(f"**Created:** {alert['created_at'].strftime('%Y-%m-%d %H:%M')}")
                            
                            # Check if triggered
                            matching_events = events_df[
                                events_df['event.action'] == alert['event_type']
                            ]
                            if len(matching_events) >= alert['threshold']:
                                st.error(f"⚠️ TRIGGERED: {len(matching_events)} matching events found!")
                            else:
                                st.info(f"ℹ️ {len(matching_events)} matching events (threshold: {alert['threshold']})")
                        
                        with col_y:
                            if st.button("🗑️ Delete", key=f"delete_{idx}"):
                                # Create new list without this item to avoid index issues
                                st.session_state.alerts = [a for i, a in enumerate(st.session_state.alerts) if i != idx]
                                st.rerun()
            else:
                st.info("No alert rules configured yet. Create your first rule above!")
        
        with tab5:
            # YARAL Rules Management
            st.header("🔬 YARAL Rule Manager")
            st.info("YARAL (Yet Another Rule Alert Language) - A flexible, JSON-based rule engine for security event detection")
            
            # Create subtabs for better organization
            yaral_tab1, yaral_tab2, yaral_tab3, yaral_tab4 = st.tabs(["📝 Rules", "🔍 Scanner", "📥 Import/Export", "🧪 Simulator"])
            
            with yaral_tab1:
                # Rule Management
                st.subheader("Manage YARAL Rules")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    # Load sample rules
                    if st.button("📥 Load Sample Rules"):
                        sample_rules = get_sample_yaral_rules()
                        count = 0
                        for rule in sample_rules:
                            # Check if rule already exists
                            existing = st.session_state.yaral_engine.get_rule(rule['name'])
                            if not existing:
                                if st.session_state.yaral_engine.add_rule(rule):
                                    count += 1
                        st.success(f"Loaded {count} sample rules!")
                        st.rerun()
                    
                    st.divider()
                    
                    # Add custom rule
                    st.subheader("Add Custom YARAL Rule")
                    
                    with st.form("add_yaral_rule"):
                        rule_name = st.text_input("Rule Name*", placeholder="e.g., Suspicious_Login_Activity")
                        rule_description = st.text_area("Description", placeholder="Describe what this rule detects")
                        
                        col_a, col_b = st.columns(2)
                        with col_a:
                            rule_severity = st.selectbox("Severity", ['low', 'medium', 'high', 'critical'])
                        with col_b:
                            rule_enabled = st.checkbox("Enabled", value=True)
                        
                        st.markdown("**Conditions** (JSON format)")
                        st.markdown("""
                        Example conditions:
                        ```json
                        {
                          "event.action": "ssh_login",
                          "event.outcome": "failure",
                          "user.name": {"in": ["root", "admin"]}
                        }
                        ```
                        Supported operators: `eq`, `ne`, `in`, `contains`, `regex`, `gt`, `lt`
                        """)
                        
                        rule_conditions = st.text_area(
                            "Conditions (JSON)*",
                            height=150,
                            placeholder='{"event.action": "failed_login", "event.severity": "high"}'
                        )
                        
                        submit_button = st.form_submit_button("➕ Add Rule", type="primary")
                        
                        if submit_button:
                            if rule_name and rule_conditions:
                                try:
                                    # Parse conditions with better error reporting
                                    conditions = json.loads(rule_conditions)
                                    
                                    # Create rule dict
                                    new_rule = {
                                        'name': rule_name,
                                        'description': rule_description,
                                        'severity': rule_severity,
                                        'enabled': rule_enabled,
                                        'conditions': conditions,
                                        'metadata': {
                                            'author': 'User',
                                            'created': datetime.now().isoformat()
                                        }
                                    }
                                    
                                    # Validate
                                    is_valid, errors = validate_yaral_rule(new_rule)
                                    if not is_valid:
                                        st.error(f"Validation errors: {', '.join(errors)}")
                                    else:
                                        # Check if exists
                                        if st.session_state.yaral_engine.get_rule(rule_name):
                                            st.error(f"Rule '{rule_name}' already exists!")
                                        else:
                                            if st.session_state.yaral_engine.add_rule(new_rule):
                                                st.success(f"Rule '{rule_name}' added successfully!")
                                                st.rerun()
                                            else:
                                                st.error("Failed to add rule")
                                
                                except json.JSONDecodeError as e:
                                    # Provide detailed error information
                                    error_msg = f"Invalid JSON in conditions:\n"
                                    error_msg += f"- Error: {e.msg}\n"
                                    if hasattr(e, 'lineno') and hasattr(e, 'colno'):
                                        error_msg += f"- Location: Line {e.lineno}, Column {e.colno}\n"
                                    error_msg += f"\nPlease check your JSON syntax. Common issues:\n"
                                    error_msg += f"- Missing quotes around strings\n"
                                    error_msg += f"- Missing commas between fields\n"
                                    error_msg += f"- Unbalanced brackets or braces"
                                    st.error(error_msg)
                                except Exception as e:
                                    st.error(f"Error adding rule: {str(e)}")
                            else:
                                st.warning("Please provide rule name and conditions")
                
                with col2:
                    st.subheader("Rule Statistics")
                    all_rules = st.session_state.yaral_engine.get_all_rules()
                    enabled_rules = [r for r in all_rules if r.get('enabled', True)]
                    st.metric("Total Rules", len(all_rules))
                    st.metric("Enabled Rules", len(enabled_rules))
                    st.metric("Matches Found", len(st.session_state.yaral_matches))
                
                st.divider()
                
                # Display existing rules
                all_rules = st.session_state.yaral_engine.get_all_rules()
                if all_rules:
                    st.subheader("Configured YARAL Rules")
                    
                    for idx, rule in enumerate(all_rules):
                        status_icon = "✅" if rule.get('enabled', True) else "❌"
                        severity_emoji = {
                            'low': '🟢',
                            'medium': '🟡',
                            'high': '🟠',
                            'critical': '🔴'
                        }.get(rule.get('severity', 'medium'), '⚪')
                        
                        with st.expander(f"{status_icon} {severity_emoji} {rule['name']}", expanded=False):
                            col_x, col_y = st.columns([3, 1])
                            
                            with col_x:
                                st.write(f"**Description:** {rule.get('description', 'N/A')}")
                                st.write(f"**Severity:** {rule.get('severity', 'medium')}")
                                st.write(f"**Status:** {'Enabled' if rule.get('enabled', True) else 'Disabled'}")
                                
                                st.markdown("**Conditions:**")
                                st.json(rule.get('conditions', {}))
                                
                                if rule.get('metadata'):
                                    with st.expander("Metadata"):
                                        st.json(rule['metadata'])
                            
                            with col_y:
                                if st.button("🗑️ Delete", key=f"delete_yaral_{idx}"):
                                    st.session_state.yaral_engine.remove_rule(rule['name'])
                                    st.rerun()
                                
                                current_rule = st.session_state.yaral_engine.get_rule(rule['name'])
                                if current_rule and current_rule.enabled:
                                    if st.button("⏸️ Disable", key=f"disable_yaral_{idx}"):
                                        current_rule.enabled = False
                                        st.rerun()
                                else:
                                    if st.button("▶️ Enable", key=f"enable_yaral_{idx}"):
                                        if current_rule:
                                            current_rule.enabled = True
                                        st.rerun()
                else:
                    st.info("No YARAL rules configured. Load sample rules or add your own!")
            
            with yaral_tab2:
                # Scanner
                st.subheader("🔍 Event Scanner")
                st.markdown("Scan security events against YARAL rules to detect threats and anomalies")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    all_rules = st.session_state.yaral_engine.get_all_rules()
                    enabled_count = len([r for r in all_rules if r.get('enabled', True)])
                    st.metric("Rules Ready", enabled_count)
                
                with col2:
                    st.metric("Events to Scan", len(events_df))
                
                with col3:
                    st.metric("Previous Matches", len(st.session_state.yaral_matches))
                
                st.divider()
                
                if st.button("🔍 Scan All Events", type="primary", use_container_width=True):
                    if enabled_count > 0:
                        st.session_state.yaral_matches = []
                        
                        with st.spinner(f"Scanning {len(events_df)} events with {enabled_count} rules..."):
                            for _, event in events_df.iterrows():
                                matches = st.session_state.yaral_engine.scan_event(event.to_dict())
                                st.session_state.yaral_matches.extend(matches)
                        
                        st.success(f"✅ Scan complete! Found {len(st.session_state.yaral_matches)} matches.")
                        st.rerun()
                    else:
                        st.warning("No enabled YARAL rules. Please enable some rules first!")
                
                # Display matches
                if st.session_state.yaral_matches:
                    st.divider()
                    st.subheader("🎯 Detection Results")
                    
                    # Summary by severity
                    severity_counts = {}
                    for match in st.session_state.yaral_matches:
                        sev = match.get('severity', 'unknown')
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("🔴 Critical", severity_counts.get('critical', 0))
                    with col2:
                        st.metric("🟠 High", severity_counts.get('high', 0))
                    with col3:
                        st.metric("🟡 Medium", severity_counts.get('medium', 0))
                    with col4:
                        st.metric("🟢 Low", severity_counts.get('low', 0))
                    
                    st.divider()
                    
                    # Display matches table
                    matches_data = []
                    for match in st.session_state.yaral_matches:
                        matches_data.append({
                            'Timestamp': match.get('timestamp', datetime.now()),
                            'Rule': match.get('rule_name', 'N/A'),
                            'Severity': match.get('severity', 'N/A'),
                            'Description': match.get('description', 'N/A'),
                            'Event Type': match.get('event', {}).get('event.action', 'N/A'),
                            'Source IP': match.get('event', {}).get('source.ip', 'N/A')
                        })
                    
                    matches_df = pd.DataFrame(matches_data)
                    st.dataframe(matches_df, use_container_width=True, height=400)
                    
                    # Export matches
                    col_exp1, col_exp2 = st.columns(2)
                    with col_exp1:
                        if st.button("📥 Export Matches (CSV)"):
                            csv = matches_df.to_csv(index=False)
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name=f"yaral_matches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    with col_exp2:
                        if st.button("📥 Export Matches (JSON)"):
                            matches_json = json.dumps(st.session_state.yaral_matches, indent=2, default=str)
                            st.download_button(
                                label="Download JSON",
                                data=matches_json,
                                file_name=f"yaral_matches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                    
                    # Show detailed match info
                    st.divider()
                    st.subheader("Match Details")
                    
                    for idx, match in enumerate(st.session_state.yaral_matches[:10]):  # Show first 10
                        with st.expander(f"Match {idx+1}: {match.get('rule_name')} - {match.get('severity')}"):
                            st.write(f"**Rule:** {match.get('rule_name')}")
                            st.write(f"**Description:** {match.get('description')}")
                            st.write(f"**Severity:** {match.get('severity')}")
                            st.write(f"**Timestamp:** {match.get('timestamp')}")
                            
                            if match.get('reasons'):
                                st.markdown("**Match Reasons:**")
                                for reason in match.get('reasons', []):
                                    st.write(f"- {reason}")
                            
                            st.markdown("**Event Data:**")
                            st.json(match.get('event', {}))
                    
                    if len(st.session_state.yaral_matches) > 10:
                        st.info(f"Showing first 10 of {len(st.session_state.yaral_matches)} matches. Export to see all.")
            
            with yaral_tab3:
                # Import/Export
                st.subheader("📥 Import/Export Rules")
                
                # Export section
                st.markdown("### Export Rules")
                st.markdown("Export your YARAL rules to share or backup")
                
                all_rules = st.session_state.yaral_engine.get_all_rules()
                
                if all_rules:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.metric("Rules to Export", len(all_rules))
                    
                    with col2:
                        export_format = st.selectbox("Format", [".yaral (JSON)", ".json"])
                    
                    if st.button("📤 Export Rules", type="primary"):
                        rules_json = st.session_state.yaral_engine.export_rules()
                        file_extension = "yaral" if ".yaral" in export_format else "json"
                        
                        st.download_button(
                            label=f"Download Rules (.{file_extension})",
                            data=rules_json,
                            file_name=f"yaral_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}",
                            mime="application/json"
                        )
                else:
                    st.info("No rules to export. Create some rules first!")
                
                st.divider()
                
                # Import from file
                st.markdown("### Import from File")
                st.markdown("Import YARAL rules from a JSON or .yaral file")
                
                uploaded_file = st.file_uploader("Choose a file", type=['json', 'yaral'])
                
                if uploaded_file is not None:
                    try:
                        content = uploaded_file.read().decode('utf-8')
                        
                        if st.button("📥 Import from File"):
                            count, errors = st.session_state.yaral_engine.import_rules(content)
                            
                            if count > 0:
                                st.success(f"Successfully imported {count} rules!")
                            
                            if errors:
                                st.error("Errors during import:")
                                for error in errors:
                                    st.write(f"- {error}")
                            
                            if count > 0:
                                st.rerun()
                    
                    except Exception as e:
                        st.error(f"Error reading file: {str(e)}")
                
                st.divider()
                
                # Import from Git
                st.markdown("### Import from Git Repository")
                st.markdown("Clone a Git repository and import all .yaral files")
                
                with st.form("git_import"):
                    git_url = st.text_input(
                        "Git Repository URL*",
                        placeholder="https://github.com/username/yaral-rules.git"
                    )
                    
                    git_branch = st.text_input(
                        "Branch",
                        value="main",
                        placeholder="main"
                    )
                    
                    st.markdown("""
                    **Note:** The repository will be cloned and all `.yaral` files will be imported.
                    Make sure the repository contains valid YARAL rule files.
                    """)
                    
                    submit_git = st.form_submit_button("🔗 Import from Git", type="primary")
                    
                    if submit_git:
                        if git_url:
                            with st.spinner(f"Cloning repository and importing rules..."):
                                count, errors = st.session_state.yaral_engine.import_from_git(git_url, git_branch)
                            
                            if count > 0:
                                st.success(f"✅ Successfully imported {count} rules from Git repository!")
                                st.rerun()
                            else:
                                st.warning("No rules were imported")
                            
                            if errors:
                                st.error("Errors during import:")
                                for error in errors:
                                    st.write(f"- {error}")
                        else:
                            st.warning("Please provide a Git repository URL")
            
            with yaral_tab4:
                # Simulator
                st.subheader("🧪 Rule Simulator")
                st.markdown("Test YARAL rules against custom or sample events to verify they work correctly")
                
                # Select rule to test
                all_rules = st.session_state.yaral_engine.get_all_rules()
                
                if all_rules:
                    rule_names = [r['name'] for r in all_rules]
                    selected_rule_name = st.selectbox(
                        "Select Rule to Test",
                        options=rule_names,
                        help="Choose a rule to test against events"
                    )
                    
                    selected_rule = st.session_state.yaral_engine.get_rule(selected_rule_name)
                    
                    if selected_rule:
                        # Show rule info
                        with st.expander("Rule Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Name:** {selected_rule.name}")
                                st.write(f"**Description:** {selected_rule.description}")
                            with col2:
                                st.write(f"**Severity:** {selected_rule.severity}")
                                st.write(f"**Enabled:** {selected_rule.enabled}")
                            
                            st.markdown("**Conditions:**")
                            st.json(selected_rule.conditions)
                        
                        st.divider()
                        
                        # Test options
                        test_option = st.radio(
                            "Test Against:",
                            ["Custom Event (JSON)", "Sample Events", "All Current Events"],
                            horizontal=True
                        )
                        
                        test_results = []
                        
                        if test_option == "Custom Event (JSON)":
                            st.markdown("**Provide Event Data (JSON)**")
                            st.markdown("Example event structure:")
                            example_event = {
                                "event.action": "ssh_login",
                                "event.outcome": "failure",
                                "event.severity": "high",
                                "event.category": "authentication",
                                "source.ip": "192.168.1.100",
                                "user.name": "root"
                            }
                            st.code(json.dumps(example_event, indent=2), language='json')
                            
                            custom_event_json = st.text_area(
                                "Event JSON",
                                height=200,
                                placeholder=json.dumps(example_event, indent=2)
                            )
                            
                            if st.button("🧪 Test Rule", type="primary"):
                                try:
                                    event = json.loads(custom_event_json)
                                    matched, reasons = selected_rule.match_event(event)
                                    
                                    if matched:
                                        st.success("✅ Rule MATCHED the event!")
                                        st.markdown("**Match Reasons:**")
                                        for reason in reasons:
                                            st.write(f"- {reason}")
                                    else:
                                        st.warning("❌ Rule did NOT match the event")
                                        st.info("The event did not satisfy all conditions of this rule")
                                    
                                    # Show what was checked
                                    with st.expander("Detailed Analysis"):
                                        st.markdown("**Conditions Checked:**")
                                        for field, condition in selected_rule.conditions.items():
                                            field_value = selected_rule._get_nested_value(event, field)
                                            st.write(f"- Field: `{field}`")
                                            st.write(f"  - Expected: `{condition}`")
                                            st.write(f"  - Found: `{field_value}`")
                                            st.write(f"  - Match: {selected_rule._check_condition(event, field, condition)}")
                                
                                except json.JSONDecodeError as e:
                                    st.error(f"Invalid JSON: {str(e)}")
                                except Exception as e:
                                    st.error(f"Error testing rule: {str(e)}")
                        
                        elif test_option == "Sample Events":
                            # Generate a few sample events
                            sample_events = generate_sample_events(10)
                            
                            if st.button("🧪 Test Against Samples", type="primary"):
                                matches = 0
                                for event in sample_events:
                                    matched, reasons = selected_rule.match_event(event)
                                    if matched:
                                        matches += 1
                                        test_results.append({
                                            'event': event,
                                            'reasons': reasons
                                        })
                                
                                st.info(f"Tested against {len(sample_events)} sample events")
                                
                                if matches > 0:
                                    st.success(f"✅ Rule matched {matches} out of {len(sample_events)} events")
                                    
                                    # Show matches
                                    for idx, result in enumerate(test_results[:5]):  # Show first 5
                                        with st.expander(f"Match {idx+1}"):
                                            st.markdown("**Reasons:**")
                                            for reason in result['reasons']:
                                                st.write(f"- {reason}")
                                            st.markdown("**Event:**")
                                            st.json(result['event'])
                                    
                                    if len(test_results) > 5:
                                        st.info(f"Showing first 5 of {len(test_results)} matches")
                                else:
                                    st.warning("❌ Rule did not match any sample events")
                        
                        elif test_option == "All Current Events":
                            if st.button("🧪 Test Against All Events", type="primary"):
                                matches = 0
                                for _, event in events_df.iterrows():
                                    matched, reasons = selected_rule.match_event(event.to_dict())
                                    if matched:
                                        matches += 1
                                        test_results.append({
                                            'event': event.to_dict(),
                                            'reasons': reasons
                                        })
                                
                                st.info(f"Tested against {len(events_df)} current events")
                                
                                if matches > 0:
                                    st.success(f"✅ Rule matched {matches} out of {len(events_df)} events")
                                    
                                    # Show matches
                                    for idx, result in enumerate(test_results[:5]):  # Show first 5
                                        with st.expander(f"Match {idx+1}"):
                                            st.markdown("**Reasons:**")
                                            for reason in result['reasons']:
                                                st.write(f"- {reason}")
                                            st.markdown("**Event:**")
                                            st.json(result['event'])
                                    
                                    if len(test_results) > 5:
                                        st.info(f"Showing first 5 of {len(test_results)} matches")
                                else:
                                    st.warning("❌ Rule did not match any current events")
                
                else:
                    st.info("No rules available to test. Create some rules first!")
                    
                    if st.button("Load Sample Rules"):
                        sample_rules = get_sample_yaral_rules()
                        for rule in sample_rules:
                            st.session_state.yaral_engine.add_rule(rule)
                        st.success(f"Loaded {len(sample_rules)} sample rules!")
                        st.rerun()

if __name__ == "__main__":
    main()
