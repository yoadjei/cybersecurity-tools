# **Network Traffic Analyzer**

Network Traffic Analyzer, an advanced tool designed for real-time network packet analysis, anomaly detection, and automated alerting. This tool helps cybersecurity professionals and enthusiasts monitor network traffic, identify suspicious behavior, and ensure the integrity of their network environment.

# **Features**

 • Dynamic Network Interface Selection: Automatically detects available network interfaces for packet sniffing.
 • Real-Time Packet Capture: Provides live insights into the network traffic flowing through your system, including HTTP and DNS activity.
 • Anomaly Detection: Utilizes statistical methods (Z-score analysis) to detect unusual patterns in network traffic, triggering alerts when anomalies are found.
 • Alert System: Sends notifications via email and Slack when an anomaly or suspicious traffic pattern is detected.
 • Detailed Packet Analysis:
 • HTTP Requests and Responses: Analyze the HTTP methods, hosts, and response codes.
 • DNS Queries and Responses: Capture DNS queries and responses for domain name resolution insights.
 • Data Logging: Store packet summaries in a local SQLite database for later analysis and historical record-keeping.
 • Comprehensive User Interface: Interactive ASCII art banner and easy-to-follow interface prompts for selecting network interfaces.

Installation & Setup

To get started with the CyberYaw Network Traffic Analyzer, follow the steps below.

1. Clone the Repository

Clone the project repository to your local machine:

git clone https://github.com/yoadjei/Network-Traffic-Analyzer.git
cd Network-Traffic-Analyzer

2. Install Dependencies

Ensure you have Python 3.9+ installed, and then install the required dependencies by running:

pip install -r requirements.txt

The dependencies are listed in requirements.txt and include:
 • scapy: For packet sniffing and analysis.
 • pyfiglet: For generating ASCII art banners.
 • requests: For sending Slack notifications.
 • python-dotenv: For managing environment variables securely.

3. Configure the .env File

Create a .env file in the root directory to store sensitive credentials like your email and Slack webhook URL. Here’s a sample .env file:

# .env file
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password
SLACK_WEBHOOK=https://hooks.slack.com/services/your/slack/webhook

Make sure to replace your_email@gmail.com and the Slack webhook URL with your actual credentials.

4. Set Up Email Account

 • Ensure the email account you’re using allows access to less secure apps (if using Gmail, you might need to enable “Allow less secure apps”).
 • For added security, you can create an App Password if two-factor authentication (2FA) is enabled for your Gmail account.

5. Run the Tool

To start capturing network traffic and monitor for anomalies, run the tool with the following command:

sudo python network_analyzer.py

Note: You need to run the script with elevated privileges (sudo on Linux/macOS) to access network interfaces for packet sniffing.

How It Works

1. Network Interface Selection

When you start the tool, it will list all available network interfaces on your machine. You’ll be prompted to select one to begin monitoring network traffic.

2. Real-Time Packet Capture and Analysis

Once a network interface is selected, the tool will start capturing packets in real-time. It will analyze incoming packets and detect potential anomalies, including:
 • HTTP Requests/Responses: The tool inspects HTTP headers, methods, and response codes to provide insights into web traffic.
 • DNS Queries/Responses: It identifies DNS queries and responses, displaying the queried domain and resolved IP address.

3. Anomaly Detection

The tool uses a simple statistical model (Z-score) to detect anomalies in network traffic. If the traffic deviates significantly from the average, an alert is triggered.The threshold for anomaly detection can be adjusted based on your requirements.

4. Alerts

When an anomaly is detected, the tool automatically sends out notifications to:
 • Email: An email will be sent to your designated email address (configured in .env).
 • Slack: A message will be posted to your Slack channel via the provided webhook URL.

5. Data Logging

All captured packets are logged into a local SQLite database. You can review the database for historical data or further analysis. The database stores the timestamp and summary of each captured packet.

Customizing the Tool

Anomaly Detection Sensitivity

The current anomaly detection algorithm uses the Z-score for traffic volume. A higher Z-score threshold will make the tool more sensitive to anomalies. You can adjust the threshold or add additional metrics for anomaly detection in the packet_utils.py file.

# Example of adjusting the anomaly detection sensitivity
PACKET_WINDOW_SIZE = 100  # Number of packets to analyze before detecting an anomaly
Z_SCORE_THRESHOLD = 2  # Adjust the Z-score threshold for anomaly detection

Alert Settings

You can modify the email and Slack notification settings in the alert_utils.py file to match your preferred alerting format, such as adding custom text or HTML formatting.

Example Output

When the tool is running, you’ll see real-time output of the captured packets and their analysis. Here’s an example of the output:

[2024-11-16 10:30:45] Packet captured: IP 192.168.0.1 > 192.168.0.2: ICMP Echo Request
[2024-11-16 10:30:45] DNS Query - Name: www.example.com
[2024-11-16 10:30:46] HTTP Request - Method: GET, Host: www.example.com
Anomaly detected in traffic!
Email alert sent.
Slack alert sent.

Advanced Features

Traffic Pattern Analysis

This tool can also be extended to analyze traffic patterns using machine learning or other statistical models. You can modify the packet_utils.py file to implement your custom analysis methods.

Security Enhancements

 • SSL/TLS Inspection: For advanced users, you can integrate SSL/TLS decryption for HTTPS traffic by configuring a proxy or modifying the packet capture method.
 • Deep Packet Inspection: Further inspect payload data for advanced threat detection (requires parsing more protocols).

Contributing

We welcome contributions to enhance the tool! If you find any issues or would like to add features, feel free to fork the repository and submit a pull request.

License

This project is licensed under the MIT License - see the LICENSE file for details.

Contact

For questions, feature requests, or bug reports, please contact me via email at adjeiyawosei@gmail.com.
