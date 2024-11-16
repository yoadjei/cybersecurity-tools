import smtplib
import requests
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Retrieve sensitive credentials from .env
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

# Send Email Alert
def send_email_alert(subject, body):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(EMAIL_USER, "adjeiyawosei@gmail.com", message)
        server.quit()
        print("Email alert sent.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Send Slack Alert
def send_slack_alert(message):
    try:
        payload = {'text': message}
        response = requests.post(SLACK_WEBHOOK, json=payload)
        if response.status_code == 200:
            print("Slack alert sent.")
        else:
            print(f"Failed to send Slack alert: {response.status_code}")
    except Exception as e:
        print(f"Failed to send Slack message: {e}")

# Trigger all alerts (Email and Slack only)
def trigger_alert(alert_message):
    send_email_alert("Network Traffic Anomaly Alert", alert_message)
    send_slack_alert(alert_message)