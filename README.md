# BlackStarSIEM 🛡️

A comprehensive Elastic SIEM Lab built with Streamlit for learning and experimenting with Security Information and Event Management (SIEM) concepts.

## 🎯 Overview

BlackStar SIEM is an interactive learning environment inspired by [this LinkedIn article](https://www.linkedin.com/pulse/your-first-elastic-siem-lab-simple-steps-powerful-results-pathania-slwqc/). It provides a user-friendly interface to:

- Monitor and analyze security events in real-time
- Create interactive visualizations and dashboards
- Set up custom alert rules
- Simulate security events for learning purposes
- Connect to Elastic Cloud or use demo mode

## ✨ Features

### 📊 Dashboard
- Real-time security metrics overview
- Event timeline visualization
- Event type distribution charts
- Severity-based analytics
- Source IP tracking

### 🔍 Event Viewer
- Comprehensive event log display
- Advanced filtering capabilities (severity, type, outcome)
- Export events to CSV
- **Export events to UDM (Unified Data Model) JSON format**
- Real-time event updates
- Detailed event information

### 📈 Analytics
- Top source IP analysis
- Event outcome statistics
- User activity tracking
- Time-based event distribution
- Interactive visualizations

### 🚨 Alert Management
- Custom alert rule creation
- Event-based triggering
- Threshold configuration
- Alert monitoring and notifications
- Rule management interface

### 🔍 YARAL Detection Rules
- **YARAL (YARA-Like) pattern-based detection**
- Pre-configured security detection rules
- Real-time event matching
- Rule enable/disable toggle
- Export detection matches
- Custom rule conditions

### 🎯 Event Simulation
- Generate test security events
- Multiple event types:
  - Nmap scans
  - SSH login attempts
  - Failed authentication
  - Port scans
  - File access events
  - Process creation

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- (Optional) Elastic Cloud account for production use

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dcodes101110001/BlackStarSIEM.git
   cd BlackStarSIEM
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   streamlit run app.py
   ```

4. **Access the application:**
   Open your browser and navigate to `http://localhost:8501`

## 💡 Usage

### Demo Mode (No Elastic Cloud Required)

1. Launch the application
2. Click **"Use Demo Mode"** in the sidebar
3. Explore pre-generated sample events
4. Create visualizations and alerts
5. Simulate security events

### Connecting to Elastic Cloud

1. Create a free [Elastic Cloud account](https://cloud.elastic.co/)
2. Set up a new deployment
3. Generate an API key
4. In the application sidebar:
   - Enter your **Cloud ID**
   - Enter your **API Key**
   - Click **Connect**

### Creating Alerts

1. Navigate to the **Alerts** tab
2. Fill in the alert details:
   - Alert name
   - Event type to monitor
   - Minimum severity level
   - Trigger threshold
   - Description
3. Click **Create Alert Rule**
4. Monitor triggered alerts in real-time

### Simulating Events

1. Ensure you're connected (Demo Mode or Elastic Cloud)
2. In the sidebar under **Event Simulation**:
   - Select an event type
   - Click **Simulate Event**
3. View the new event in the dashboard and logs

## 📁 Project Structure

```
BlackStarSIEM/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## 🛠️ Technologies Used

- **Streamlit** - Web application framework
- **Pandas** - Data manipulation and analysis
- **Plotly** - Interactive visualizations
- **Elasticsearch** - Search and analytics engine
- **Python** - Programming language
- **UDM (Unified Data Model)** - Google Chronicle's standardized security event format
- **YARAL** - YARA-like pattern matching for security event detection

## 📚 Learning Resources

This project is designed to help you learn:

1. **SIEM Fundamentals**
   - Event collection and analysis
   - Security monitoring
   - Incident detection

2. **Elastic Stack**
   - Elasticsearch queries
   - Data visualization
   - Alert configuration

3. **Security Analysis**
   - Event correlation
   - Pattern recognition
   - Threat detection

## 🎓 Use Cases

- **SOC Analyst Training** - Practice analyzing security events
- **Cybersecurity Education** - Learn SIEM concepts hands-on
- **Lab Environment** - Test detection rules safely
- **Demonstration** - Showcase SIEM capabilities
- **Research** - Experiment with security analytics

## 🔒 Security Notes

- Demo mode uses simulated data only
- API keys are stored in session state (not persistent)
- Use strong authentication for production deployments
- Regularly update dependencies for security patches
- Follow security best practices when connecting to Elastic Cloud

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is open source and available for educational purposes.

## 🙏 Acknowledgments

- Inspired by Satyam Pathania's LinkedIn article on Elastic SIEM labs
- Built with the amazing Streamlit framework
- Powered by Elasticsearch

## 📞 Support

For questions, issues, or suggestions:
- Open an issue on GitHub
- Check the [Elastic documentation](https://www.elastic.co/guide/index.html)
- Review [Streamlit documentation](https://docs.streamlit.io/)

## 🌟 Features Roadmap

- [ ] Advanced query builder
- [ ] Custom dashboard creation
- [ ] Multi-user support
- [ ] Integration with other SIEM tools
- [ ] Machine learning-based anomaly detection
- [ ] Threat intelligence integration
- [ ] Automated response actions
- [ ] Report generation

---

**Made with ❤️ for the cybersecurity community**