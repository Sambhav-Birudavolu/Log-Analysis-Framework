from collections import Counter, defaultdict

def analyze_firewall_logs(logs):
    low_threat_count = 0
    medium_threat_count = 0
    high_threat_protocols = []

    for log in logs:
        threat_level = log.get("threat_level", "").lower()
        protocol = log.get("protocol", "").upper()

        if threat_level == "low":
            low_threat_count += 1
        elif threat_level == "medium":
            medium_threat_count += 1
        elif threat_level == "high":
            high_threat_protocols.append(protocol)

    most_common_protocol = None
    if high_threat_protocols:
        protocol_counts = Counter(high_threat_protocols)
        most_common_protocol = protocol_counts.most_common(1)[0][0]

    return {
        "Low Threat Logs": low_threat_count,
        "Medium Threat Logs": medium_threat_count,
        "Most Common High Threat Protocol": most_common_protocol
    }

def analyze_auth_service_logs(logs, threshold=3):
    failed_logins = defaultdict(int)
    failure_reasons = []

    for msg in logs:
        if msg.get("status") == "ERROR" and msg.get("event_type") == "authentication_attempt":
            user = msg.get("username")
            reason = msg.get("failure_reason")

            if user:
                failed_logins[user] += 1
            if reason:
                failure_reasons.append(reason)

    result = {
        "Users with Excessive Failures": [
            (user, count) for user, count in failed_logins.items() if count > threshold
        ],
        "Common Failure Reasons": Counter(failure_reasons).most_common()
    }

    return result

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

def alert_by_reason(logs):
    reason_count = defaultdict(int)
    alerts = []
    for log in logs:
        reason = log.get("reason")
        reason_count[reason] += 1
        if reason_count[reason] >= 6:
            alerts.append(f"ALERT: Reason '{reason}' has occurred more than 5 times.")
    return alerts

def alert_by_domain(logs):
    domain_count = defaultdict(int)
    alerts = []
    for log in logs:
        domain = log.get("queried_domain")
        domain_count[domain] += 1
        if domain_count[domain] >= 6:
            alerts.append(f"ALERT: Domain '{domain}' failed more than 5 times.")
    return alerts
