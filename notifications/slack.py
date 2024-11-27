import requests
from typing import List, Dict

def send_slack_notifications(webhook_url: str, findings: List[Dict]):
    if not webhook_url:
        return

    message = {"text": "🚨 Critical Security Findings Detected", "attachments": []}
    for finding in findings:
        attachment = {
            "color": "FF0000",
            "title": f"Critical Finding: {finding['template']}",
            "text": f"Details: {finding}"
        }
        message['attachments'].append(attachment)

    requests.post(webhook_url, json=message)
