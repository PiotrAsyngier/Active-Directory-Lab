#!/usr/bin/env python3
import sys
import json
import requests
import traceback

LOG_FILE = "/tmp/slack_debug.log"


def log_debug(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def send_alert(alert_file, hook_url):
    log_debug(f"Odczytywanie alertu: {alert_file}")
    with open(alert_file, "r", encoding="utf-8") as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    mitre_ids = rule.get("mitre", {}).get("id", ["N/A"])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    mitre_id = mitre_ids[0] if mitre_ids else "N/A"

    win_data = alert.get("data", {}).get("win", {})
    event_id = win_data.get("system", {}).get("eventID", "N/A")
    event_data = win_data.get("eventdata", {})
    source_ip = event_data.get("ipAddress", "N/A")
    subject_user = event_data.get("subjectUserName", "N/A")
    target = (
        event_data.get("targetUserName")
        or event_data.get("serviceName")
        or event_data.get("objectName", "N/A")
    )

    slack_msg = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Wazuh SOC Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Reguła:* {rule.get('description', 'Brak opisu')}\n"
                        f"*Poziom:* {rule.get('level', '0')}\n"
                        f"*MITRE ATT&CK:* {mitre_id}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event ID:*\n{event_id}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{source_ip}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Attacker (Subject):*\n{subject_user}",
                    },
                    {"type": "mrkdwn", "text": f"*Target/Service:*\n{target}"},
                ],
            },
        ]
    }

    log_debug("Wysylanie alertu do skonfigurowanego webhooka")
    response = requests.post(hook_url, json=slack_msg, timeout=5)
    response.raise_for_status()
    log_debug(f"Status HTTP: {response.status_code}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        log_debug("Za malo argumentow: oczekiwano alert_file, api_key i hook_url")
        sys.exit(2)

    try:
        send_alert(sys.argv[1], sys.argv[3])
    except (OSError, ValueError, json.JSONDecodeError, requests.RequestException) as error:
        log_debug(f"CRITICAL ERROR: {error}")
        log_debug(traceback.format_exc())
        sys.exit(1)
