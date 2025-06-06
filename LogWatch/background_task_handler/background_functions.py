from collections import Counter, defaultdict
from datetime import datetime
import redis
import requests
from requests.auth import HTTPBasicAuth
import smtplib
from email.mime.text import MIMEText
import json
import os
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join("..", "config", ".env"))

rdb = redis.Redis(host='localhost', port=6379, decode_responses=True)

def send_alert(alert_channel, alert_target, subject, message):
    try:
        if alert_channel == "email":
            from_email = os.getenv("EMAIL_USER")
            app_password = os.getenv("EMAIL_PASS")

            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = alert_target

            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(from_email, app_password)
                server.send_message(msg)

            print(f"📧 Email alert sent to {alert_target}")

        elif alert_channel == "slack":
            payload = {"text": f"*{subject}*\n{message}"}
            response = requests.post(alert_target, json=payload)
            response.raise_for_status()
            print(f"💬 Slack alert sent to {alert_target}")

        else:
            print(f"⚠️ Unsupported alert channel: {alert_channel}")
            return False

        return True

    except Exception as e:
        print(f"❌ Failed to send alert via {alert_channel}: {e}")
        return False

def fetch_logs_for_service_absolute(service_name, from_timestamp, to_timestamp, query="status:ERROR"):
    graylog_url = "http://localhost:9000/api/search/universal/absolute"
    auth = HTTPBasicAuth(
        os.getenv("GRAYLOG_USER", "admin"),
        os.getenv("GRAYLOG_PASSWORD", "admin")
    )
    headers = {
        "Accept": "application/json",
        "X-Requested-By": "consumer"
    }

    from_str = from_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    to_str = to_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    params = {
        "from": from_str,
        "to": to_str,
        "query": query,
        "decorate": "true"
    }

    response = requests.get(graylog_url, auth=auth, headers=headers, params=params)
    if response.status_code == 200:
        messages = response.json().get("messages", [])
        return [m.get("message", {}) for m in messages if m.get("message", {}).get("service") == service_name]
    else:
        raise Exception(f"Graylog API error {response.status_code}: {response.text}")

def update_failed_login_aggregates(logs, job_id, threshold=3):
    failed_logins = defaultdict(int)
    failure_reasons = Counter()

    for msg in logs:
        if msg.get("event_type") == "authentication_attempt":
            user = msg.get("username")
            reason = msg.get("failure_reason")
            if user:
                failed_logins[user] += 1
            if reason:
                failure_reasons[reason] += 1

    data_key = f"job:{job_id}:data"

    for user, count in failed_logins.items():
        key = f"user:{user}"
        current = int(rdb.hget(data_key, key) or 0)
        rdb.hset(data_key, key, current + count)

    for reason, count in failure_reasons.items():
        key = f"reason:{reason}"
        current = int(rdb.hget(data_key, key) or 0)
        rdb.hset(data_key, key, current + count)

    return dict(failed_logins), dict(failure_reasons)

def update_generic_log_aggregates(match_count, job_id, field, keyword):
    data_key = f"job:{job_id}:data"
    
    total_key = "total_match_count"
    current_total = int(rdb.hget(data_key, total_key) or 0)
    rdb.hset(data_key, total_key, current_total + match_count)

    field_key = f"{field}:{keyword}"
    current_field_count = int(rdb.hget(data_key, field_key) or 0)
    rdb.hset(data_key, field_key, current_field_count + match_count)

def update_log_pattern_timeseries(logs, job_id):
    data_key = f"job:{job_id}:data"
    bucket_counts = defaultdict(int)

    for log in logs:
        ts_str = log.get("timestamp")
        if ts_str:
            try:
                if ts_str.endswith("Z"):
                    ts_str = ts_str[:-1]
                dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
                bucket = dt.strftime("%Y-%m-%d %H:%M")
                bucket_counts[bucket] += 1
            except Exception as e:
                print(f"⚠️ Invalid timestamp in log: {ts_str} ({e})")

    for bucket, count in bucket_counts.items():
        key = f"bucket:{bucket}"
        current = int(rdb.hget(data_key, key) or 0)
        rdb.hset(data_key, key, current + count)

    total_key = "total_match_count"
    total = int(rdb.hget(data_key, total_key) or 0)
    rdb.hset(data_key, total_key, total + sum(bucket_counts.values()))

    return dict(bucket_counts)

def update_high_threat_protocol_stats(logs, job_id):
    data_key = f"job:{job_id}:data"
    low = med = 0
    high_protocols = []

    for log in logs:
        level = log.get("threat_level", "").lower()
        proto = log.get("protocol", "").upper()
        if level == "low":
            low += 1
        elif level == "medium":
            med += 1
        elif level == "high" and proto:
            high_protocols.append(proto)

    rdb.hincrby(data_key, "low_threat_count", low)
    rdb.hincrby(data_key, "medium_threat_count", med)
    rdb.hincrby(data_key, "high_threat_count", len(high_protocols))

    for proto, count in Counter(high_protocols).items():
        key = f"protocol:{proto}"
        rdb.hincrby(data_key, key, count)

    return {
        "low": low,
        "medium": med,
        "high": len(high_protocols),
        "protocol_freq": dict(Counter(high_protocols))
    }

def update_dns_alert_stats(logs, job_id, reason_threshold=5, domain_threshold=5):
    data_key = f"job:{job_id}:data"
    reason_count = defaultdict(int)
    domain_count = defaultdict(int)
    alerts = []

    for log in logs:
        reason = log.get("reason")
        domain = log.get("queried_domain")

        if reason:
            reason_count[reason] += 1
            if reason_count[reason] == reason_threshold + 1:
                alerts.append({
                    "type": "reason",
                    "value": reason,
                    "message": f"Reason '{reason}' occurred more than {reason_threshold} times."
                })

        if domain:
            domain_count[domain] += 1
            if domain_count[domain] == domain_threshold + 1:
                alerts.append({
                    "type": "domain",
                    "value": domain,
                    "message": f"Domain '{domain}' failed more than {domain_threshold} times."
                })

    for reason, count in reason_count.items():
        rdb.hincrby(data_key, f"reason:{reason}", count)

    for domain, count in domain_count.items():
        rdb.hincrby(data_key, f"domain:{domain}", count)

    return {
        "reason_counts": dict(reason_count),
        "domain_counts": dict(domain_count),
        "alerts": alerts
    }