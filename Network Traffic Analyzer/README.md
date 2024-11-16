# CyberYaw Network Traffic Analyzer Tool

Welcome to CyberYaw's Network Traffic Analyzer, a terminal-based cybersecurity tool designed for real-time packet analysis, anomaly detection, and alerting. This tool helps identify suspicious network activity and provides insights into HTTP, DNS, and other packet-level data.

---

## Features
- Dynamic Network Interface Selection: Select the network interface to monitor.
- Real-Time Packet Capture: View live network traffic summaries.
- Anomaly Detection: Detect unusual traffic patterns using Z-score analysis.
- Alerts: Send email and Slack notifications for detected anomalies.
- Packet Analysis:
  - HTTP Requests and Responses
  - DNS Queries and Responses
- Data Logging: Store packet summaries in an SQLite database.

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yoadjei/Network-Traffic-Analyzer.git
cd Network-Traffic-Analyzer

### 2. Install Dependencies

Make sure you have Python 3.9 or higher installed. Install the required packages:

pip install -r requirements.txt

### 3. Configure .env File

Create a .env file in the project root directory with the following:

EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password
SLACK_WEBHOOK=https://hooks.slack.com/services/your/slack/webhook

### 4. Run the Tool

Start the tool using:

sudo python network_analyzer.py

Note: Root privileges are required to sniff network packets.
