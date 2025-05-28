from collections import Counter, defaultdict
import requests
from requests.auth import HTTPBasicAuth
import json


def sort_by_host(data):
    authLogs, dnsLogs, firewallLogs = [], [], []
    for errLog in data:
        errLog = errLog['message']
        service = errLog.get('service')
        if service == 'auth-service':
            authLogs.append(errLog)
        elif service == 'dns-service':
            dnsLogs.append(errLog)
        else:
            firewallLogs.append(errLog)
    return authLogs, dnsLogs, firewallLogs



def load_user_services(username, conn):
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT services FROM user_services WHERE username = %s", (username,))
        row = cursor.fetchone()
        if row and row['services']:
            return json.loads(row['services'])
        return []
    except Exception as e:
        raise e

def save_user_services(username, services, conn):
    try:
        cursor = conn.cursor()
        services_json = json.dumps(services)
        cursor.execute("""
            INSERT INTO user_services (username, services)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE services = VALUES(services)
        """, (username, services_json))
        conn.commit()
    except Exception as e:
        raise e
    
# ----------------- Analysis Config (Central Dictionary) ----------------- #
ANALYSIS_HANDLERS = {
    "failed_logins": {
        "label": "Failed Logins (Auth)",
        "services": ["auth-service"],
        "alertable": True,
        "func": analyze_auth_service_logs
    },
    "high_threat_protocol": {
        "label": "High Threat Protocols (Firewall)",
        "services": ["firewall-service"],
        "alertable": True,
        "func": analyze_firewall_logs
    },
    "dns_alerts": {
        "label": "Domain and Reason Alerts (DNS)",
        "services": ["dns-service"],
        "alertable": True,
        "func": lambda logs: {
            "domain_alerts": alert_by_domain(logs),
            "reason_alerts": alert_by_reason(logs)
        }
    },
    "generic_log_search": {
        "label": "Generic Log Pattern Count",
        "services": ["*"],  # Wildcard: all services
        "func": generic_log_count_analysis,
        "alertable": False,
        "configurable": True  # custom keyword supported
    }
}