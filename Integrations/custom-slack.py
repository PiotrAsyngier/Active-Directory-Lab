#!/usr/bin/env python3
import sys
import json
import requests
import traceback

LOG_FILE = "/tmp/slack_debug.log"

def log_debug(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def send_alert(alert_file, hook_url):
    try:
        log_debug(f"Odczytywanie alertu: {alert_file}")
        with open(alert_file, 'r') as f:
            alert = json.load(f)

        # 1. Podstawowe metadane reguły
        rule_desc = alert.get('rule', {}).get('description', 'Brak opisu')
        level = alert.get('rule', {}).get('level', '0')
        mitre_id = alert.get('rule', {}).get('mitre', {}).get('id', ['N/A'])[0]
        
        # 2. Głęboki kontekst z logów Windows (Event Data)
        win_data = alert.get('data', {}).get('win', {})
        event_id = win_data.get('system', {}).get('eventID', 'N/A')
        
        event_data = win_data.get('eventdata', {})
        source_ip = event_data.get('ipAddress', 'N/A')
        subject_user = event_data.get('subjectUserName', 'N/A')
        
        # Cel różni się w zależności od typu logu (np. 4769 to serviceName, 4662 to objectName/targetUserName)
        target = event_data.get('targetUserName') or event_data.get('serviceName') or event_data.get('objectName', 'N/A')

        # 3. Formatowanie ładunku w standardzie Slack Block Kit
        slack_msg = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 Wazuh SOC Alert",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Reguła:* {rule_desc}\n*Poziom:* {level}\n*MITRE ATT&CK:* {mitre_id}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Event ID:*\n{event_id}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Source IP:*\n{source_ip}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Attacker (Subject):*\n{subject_user}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Target/Service:*\n{target}"
                        }
                    ]
                }
            ]
        }

        log_debug(f"Wysylanie POST na URL: {hook_url}")
        r = requests.post(hook_url, json=slack_msg, timeout=5)
        log_debug(f"Status HTTP: {r.status_code}")
        
    except Exception as e:
        log_debug(f"CRITICAL ERROR: {str(e)}")
        log_debug(traceback.format_exc())

if __name__ == "__main__":
    log_debug("--- START SKRYPTU ---")
    log_debug(f"Argumenty od Wazuha: {sys.argv}")
    if len(sys.argv) >= 4:
        hook_url = sys.argv[3]
        send_alert(sys.argv[1], hook_url)
    else:
        log_debug("Za mało argumentów!")
