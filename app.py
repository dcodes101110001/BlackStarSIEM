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
import re

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
if 'yaral_rules' not in st.session_state:
    st.session_state.yaral_rules = []

def load_yaral_rules():
    """
    Load YARAL (YARA-Like) rules for security event detection
    YARAL rules are simplified pattern-matching rules for SIEM events
    """
    default_rules = [
        {
            'name': 'Suspicious_Nmap_Scan',
            'description': 'Detects potential Nmap scanning activity',
            'conditions': {
                'event.action': 'nmap_scan',
                'event.severity': ['medium', 'high', 'critical']
            },
            'severity': 'high',
            'enabled': True
        },
        {
            'name': 'Multiple_Failed_Logins',
            'description': 'Detects multiple failed login attempts',
            'conditions': {
                'event.action': 'failed_login',
                'event.outcome': 'failure'
            },
            'severity': 'medium',
            'enabled': True
        },
        {
            'name': 'Port_Scan_Detection',
            'description': 'Detects port scanning activity',
            'conditions': {
                'event.action': 'port_scan'
            },
            'severity': 'high',
            'enabled': True
        },
        {
            'name': 'Unauthorized_File_Access',
            'description': 'Detects unauthorized file access attempts',
            'conditions': {
                'event.action': 'file_access',
                'event.outcome': 'failure'
            },
            'severity': 'medium',
            'enabled': True
        }
    ]
    return default_rules

def match_yaral_rule(event, rule):
    """
    Check if an event matches a YARAL rule
    """
    if not rule.get('enabled', True):
        return False
    
    conditions = rule.get('conditions', {})
    
    for key, value in conditions.items():
        event_value = event.get(key)
        
        # Handle list of acceptable values
        if isinstance(value, list):
            if event_value not in value:
                return False
        # Handle single value
        else:
            if event_value != value:
                return False
    
    return True

def apply_yaral_rules(events, rules):
    """
    Apply YARAL rules to events and return matches
    """
    matches = []
    
    for event in events:
        for rule in rules:
            if match_yaral_rule(event, rule):
                match = {
                    'event': event,
                    'rule_name': rule['name'],
                    'rule_description': rule['description'],
                    'rule_severity': rule['severity'],
                    'timestamp': event.get('timestamp', datetime.now())
                }
                matches.append(match)
    
    return matches


def connect_to_elastic(cloud_id, api_key):
    """Connect to Elastic Cloud"""
    try:
        es = Elasticsearch(
            cloud_id=cloud_id,
            api_key=api_key,
            request_timeout=30,
            verify_certs=True
        )
        # Test connection with ping
        if not es.ping():
            return False, "Unable to connect to Elastic Cloud. Please verify your Cloud ID and API Key are correct."
        
        st.session_state.es_client = es
        st.session_state.es_connected = True
        return True, "Successfully connected to Elastic Cloud!"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

def parse_to_udm(event):
    """
    Parse event data into UDM (Unified Data Model) format
    UDM is Google Chronicle's standardized format for security events
    """
    udm_event = {
        'metadata': {
            'event_timestamp': event.get('timestamp', datetime.now()).isoformat() if isinstance(event.get('timestamp'), datetime) else str(event.get('timestamp', '')),
            'event_type': 'NETWORK_CONNECTION' if 'scan' in event.get('event.action', '') or 'port' in event.get('event.action', '') else 'USER_LOGIN',
            'product_name': 'BlackStar SIEM',
            'vendor_name': 'BlackStar',
            'product_version': '1.0',
        },
        'principal': {
            'ip': event.get('source.ip', ''),
            'user': {
                'userid': event.get('user.name', ''),
            },
        },
        'target': {
            'ip': event.get('destination.ip', ''),
            'port': event.get('destination.port', 0),
        },
        'security_result': {
            'action': event.get('event.action', ''),
            'severity': event.get('event.severity', 'UNKNOWN_SEVERITY').upper(),
            'description': event.get('message', ''),
        },
        'network': {
            'direction': 'OUTBOUND',
        }
    }
    
    # Map severity to UDM severity levels
    severity_mapping = {
        'low': 'LOW',
        'medium': 'MEDIUM', 
        'high': 'HIGH',
        'critical': 'CRITICAL'
    }
    udm_event['security_result']['severity'] = severity_mapping.get(
        event.get('event.severity', '').lower(), 'UNKNOWN_SEVERITY'
    )
    
    return udm_event

def generate_sample_events(count=100):
    """Generate sample security events for demonstration"""
    events = []
    event_types = ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access', 'process_creation']
    severities = ['low', 'medium', 'high', 'critical']
    source_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.10', '203.0.113.5']
    
    for i in range(count):
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        event = {
            'timestamp': timestamp,
            'event.action': random.choice(event_types),
            'event.severity': random.choice(severities),
            'source.ip': random.choice(source_ips),
            'destination.ip': '192.168.1.50',
            'destination.port': random.choice([22, 80, 443, 3389, 8080]),
            'user.name': random.choice(['admin', 'user1', 'root', 'service_account']),
            'event.outcome': random.choice(['success', 'failure']),
            'message': f'Security event detected: {random.choice(event_types)}'
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
                ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access']
            )
            
            if st.button("Simulate Event"):
                new_event = {
                    'timestamp': datetime.now(),
                    'event.action': event_type,
                    'event.severity': random.choice(['low', 'medium', 'high', 'critical']),
                    'source.ip': '192.168.1.100',
                    'destination.ip': '192.168.1.50',
                    'destination.port': 22 if 'ssh' in event_type else 80,
                    'user.name': 'simulated_user',
                    'event.outcome': 'success',
                    'message': f'Simulated {event_type} event'
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
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Dashboard", "🔍 Events", "📈 Analytics", "🚨 Alerts", "🔍 YARAL Rules"])
        
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
            
            # Export options
            col_export1, col_export2 = st.columns(2)
            
            with col_export1:
                if st.button("📥 Export to CSV"):
                    csv = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            
            with col_export2:
                if st.button("📥 Export to UDM JSON"):
                    # Convert events to UDM format
                    udm_events = [parse_to_udm(event) for event in filtered_df.to_dict('records')]
                    udm_json = json.dumps(udm_events, indent=2, default=str)
                    st.download_button(
                        label="Download UDM JSON",
                        data=udm_json,
                        file_name=f"siem_events_udm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
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
                        ['nmap_scan', 'ssh_login', 'failed_login', 'port_scan', 'file_access']
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
            # YARAL Rules management
            st.header("YARAL Detection Rules")
            st.markdown("**YARAL (YARA-Like)** rules provide pattern-based detection for security events")
            
            # Load default rules if not loaded
            if not st.session_state.yaral_rules:
                st.session_state.yaral_rules = load_yaral_rules()
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("Active YARAL Rules")
                
                if st.session_state.yaral_rules:
                    for idx, rule in enumerate(st.session_state.yaral_rules):
                        with st.expander(f"🔍 {rule['name']}", expanded=False):
                            col_a, col_b = st.columns([3, 1])
                            
                            with col_a:
                                st.write(f"**Description:** {rule['description']}")
                                st.write(f"**Severity:** {rule['severity']}")
                                st.write(f"**Status:** {'✅ Enabled' if rule.get('enabled', True) else '❌ Disabled'}")
                                
                                # Display conditions
                                st.write("**Conditions:**")
                                conditions_str = json.dumps(rule.get('conditions', {}), indent=2)
                                st.code(conditions_str, language='json')
                                
                                # Apply rule to current events
                                matching_events = [e for e in events_df.to_dict('records') if match_yaral_rule(e, rule)]
                                
                                if matching_events:
                                    st.warning(f"⚠️ {len(matching_events)} events match this rule")
                                else:
                                    st.success("✅ No matching events")
                            
                            with col_b:
                                # Toggle enable/disable
                                current_state = rule.get('enabled', True)
                                new_state = st.checkbox("Enabled", value=current_state, key=f"yaral_enable_{idx}")
                                if new_state != current_state:
                                    st.session_state.yaral_rules[idx]['enabled'] = new_state
                                    st.rerun()
                else:
                    st.info("No YARAL rules loaded. Click 'Load Default Rules' to get started.")
            
            with col2:
                st.subheader("Rule Statistics")
                
                total_rules = len(st.session_state.yaral_rules)
                enabled_rules = sum(1 for r in st.session_state.yaral_rules if r.get('enabled', True))
                
                st.metric("Total Rules", total_rules)
                st.metric("Enabled Rules", enabled_rules)
                
                # Apply all rules and show matches
                if st.session_state.yaral_rules and not events_df.empty:
                    all_matches = apply_yaral_rules(events_df.to_dict('records'), st.session_state.yaral_rules)
                    st.metric("Total Matches", len(all_matches))
                
                st.divider()
                
                if st.button("🔄 Load Default Rules"):
                    st.session_state.yaral_rules = load_yaral_rules()
                    st.success("Default YARAL rules loaded!")
                    st.rerun()
                
                if st.button("🗑️ Clear All Rules"):
                    st.session_state.yaral_rules = []
                    st.success("All rules cleared!")
                    st.rerun()
            
            # Show recent matches
            if st.session_state.yaral_rules and not events_df.empty:
                st.divider()
                st.subheader("Recent YARAL Matches")
                
                all_matches = apply_yaral_rules(events_df.to_dict('records'), st.session_state.yaral_rules)
                
                if all_matches:
                    # Convert to DataFrame for display
                    matches_data = []
                    for match in all_matches[:50]:  # Show last 50 matches
                        matches_data.append({
                            'Timestamp': match['timestamp'],
                            'Rule': match['rule_name'],
                            'Severity': match['rule_severity'],
                            'Source IP': match['event'].get('source.ip', 'N/A'),
                            'Event Action': match['event'].get('event.action', 'N/A'),
                            'Description': match['rule_description']
                        })
                    
                    matches_df = pd.DataFrame(matches_data)
                    st.dataframe(matches_df.sort_values('Timestamp', ascending=False), use_container_width=True, height=400)
                    
                    # Export matches
                    if st.button("📥 Export YARAL Matches"):
                        matches_json = json.dumps(all_matches, indent=2, default=str)
                        st.download_button(
                            label="Download Matches JSON",
                            data=matches_json,
                            file_name=f"yaral_matches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                else:
                    st.info("No events match the current YARAL rules.")

if __name__ == "__main__":
    main()
