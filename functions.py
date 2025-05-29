from collections import Counter, defaultdict
import requests
from requests.auth import HTTPBasicAuth
import json

def analyze_firewall_logs(logs):
    low_threat_count = 0
    medium_threat_count = 0
    high_threat_protocols = []
    low_threat_logs, med_threat_logs, high_threat_logs = [], [], []

    for log in logs:
        threat_level = log.get("threat_level", "").lower()
        protocol = log.get("protocol", "").upper()
        if threat_level == "low":
            low_threat_count += 1
            low_threat_logs.append(log)
        elif threat_level == "medium":
            medium_threat_count += 1
            med_threat_logs.append(log)
        elif threat_level == "high":
            high_threat_protocols.append(protocol)
            high_threat_logs.append(log)

    most_common_protocol = None
    if high_threat_protocols:
        protocol_counts = Counter(high_threat_protocols)
        most_common_protocol = protocol_counts.most_common(1)[0][0]

    return {
        "low_threat_logs": low_threat_logs,
        "med_threat_logs": med_threat_logs,
        "high_threat_logs": high_threat_logs,
        "Low Threat Logs Count": low_threat_count,
        "Medium Threat Logs Count": medium_threat_count,
        "Most Common High Threat Protocol": most_common_protocol
    }

def analyze_auth_service_logs(logs, threshold=3):
    failed_logins = defaultdict(int)
    failure_reasons = []
    user_error_logs = defaultdict(list)
    reason_error_logs = defaultdict(list)

    for msg in logs:
        if msg.get("status") == "ERROR" and msg.get("event_type") == "authentication_attempt":
            user = msg.get("username")
            reason = msg.get("failure_reason")
            if user:
                failed_logins[user] += 1
                user_error_logs[user].append(msg)
            if reason:
                failure_reasons.append(reason)
                reason_error_logs[reason].append(msg)

    result = {
        "Users with Excessive Failures": [
            (user, count) for user, count in failed_logins.items() if count > threshold
        ],
        "Common Failure Reasons": Counter(failure_reasons).most_common(),
        "Error Logs By User": {
            user: logs for user, logs in user_error_logs.items() if failed_logins[user] > threshold
        },
        "Error Logs By Reason": dict(reason_error_logs)
    }

    return result

def alert_by_reason(logs):
    reason_count = defaultdict(int)
    reason_logs = defaultdict(list)
    alerts = []

    for log in logs:
        reason = log.get("reason")
        if reason:
            reason_count[reason] += 1
            reason_logs[reason].append(log)
            if reason_count[reason] == 6:
                alerts.append({
                    "message": f"ALERT: Reason '{reason}' has occurred more than 5 times.",
                    "reason": reason,
                    "logs": reason_logs[reason]
                })
    return alerts

def alert_by_domain(logs):
    domain_count = defaultdict(int)
    domain_logs = defaultdict(list)
    alerts = []

    for log in logs:
        domain = log.get("queried_domain")
        if domain:
            domain_count[domain] += 1
            domain_logs[domain].append(log)
            if domain_count[domain] == 6:
                alerts.append({
                    "message": f"ALERT: Domain '{domain}' failed more than 5 times.",
                    "domain": domain,
                    "logs": domain_logs[domain]
                })
    return alerts

def fetch_logs_for_service(service_name, range_seconds=360, query="status:ERROR"):
    graylog_url = "http://localhost:9000/api/search/universal/relative"
    auth = HTTPBasicAuth("admin", "1q2w3e4r5t6y7u8i9o0p")
    headers = {
        "Accept": "application/json",
        "X-Requested-By": "fastapi-service"
    }
    params = {
        "query": query,
        "range": range_seconds,
        "decorate": "true"
    }
    response = requests.get(graylog_url, auth=auth, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json().get("messages", [])
        return [msg.get("message", {}) for msg in data if msg.get("message", {}).get("service") == service_name]
    else:
        raise Exception(f"Graylog API error {response.status_code}: {response.text}")

def generic_log_count_analysis(service_name="", field="", keyword="", range_seconds=360):
    graylog_url = "http://localhost:9000/api/search/universal/relative"
    query = f"{field}:{keyword}"
    auth = HTTPBasicAuth("admin", "1q2w3e4r5t6y7u8i9o0p")
    headers = {
        "Accept": "application/json",
        "X-Requested-By": "fastapi-service"
    }
    params = {
        "query": query,
        "range": range_seconds,
        "decorate": "true"
    }  
    response = requests.get(graylog_url, auth=auth, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json().get("messages", [])
        filtered_logs = [msg.get("message", {}) for msg in data if msg.get("message", {}).get("service") == service_name]
        return {
            "Matched Logs Count": len(filtered_logs),
            "Filtered Logs": filtered_logs,
            "Query Used": query
        }
    else:
        raise Exception(f"Graylog API error {response.status_code}: {response.text}")


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
