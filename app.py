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

def get_udm_event_mapping():
    """Get UDM/ECS mapping for event types"""
    return {
        'nmap_scan': {'category': 'network', 'type': 'info', 'kind': 'event', 'outcome': None},
        'ssh_login': {'category': 'authentication', 'type': 'start', 'kind': 'event', 'outcome': None},
        'failed_login': {'category': 'authentication', 'type': 'end', 'kind': 'event', 'outcome': 'failure'},
        'port_scan': {'category': 'network', 'type': 'connection', 'kind': 'event', 'outcome': None},
        'file_access': {'category': 'file', 'type': 'access', 'kind': 'event', 'outcome': None},
        'process_creation': {'category': 'process', 'type': 'start', 'kind': 'event', 'outcome': 'success'}
    }

def connect_to_elastic(cloud_id, api_key):
    """Connect to Elastic Cloud"""
    try:
        es = Elasticsearch(
            cloud_id=cloud_id,
            api_key=api_key,
            request_timeout=30
        )
        if es.ping():
            st.session_state.es_client = es
            st.session_state.es_connected = True
            return True, "Successfully connected to Elastic Cloud!"
        else:
            return False, "Failed to ping Elastic Cloud"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

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
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔍 Events", "📈 Analytics", "🚨 Alerts"])
        
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
            if st.button("📥 Export to CSV"):
                csv = filtered_df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
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

if __name__ == "__main__":
    main()
