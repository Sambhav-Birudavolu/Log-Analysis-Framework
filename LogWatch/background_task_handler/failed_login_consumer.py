import sys
import signal
import json
from datetime import datetime, timedelta
from confluent_kafka import Consumer, KafkaException, KafkaError

from background_functions import (
    fetch_logs_for_service_absolute,
    update_failed_login_aggregates,
    send_alert
)

running = True

def shutdown_handler(sig, frame):
    global running
    print("\n🛑 Shutdown requested... exiting.")
    running = False

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'log-analysis-group',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False
})

def process_failed_login(msg):
    try:
        job = json.loads(msg.value().decode('utf-8'))
        print(f"📥 Received failed login job: {job}")

        job_id = job["job_id"]
        service = job["service_name"]
        interval_seconds = job["interval"]
        alert_enabled = job["alert_enabled"]
        alert_channel = job["alert_channel"]
        alert_target = job["alert_target"]

        from_ts = datetime.strptime(job["from_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        to_ts = datetime.strptime(job["to_timestamp"], "%Y-%m-%d %H:%M:%S.%f")

        logs = fetch_logs_for_service_absolute(service, from_ts, to_ts)
        print(f"🔍 Fetched {len(logs)} logs for {service} from {from_ts} to {to_ts}")

        failed_logins, failure_reasons = update_failed_login_aggregates(logs, job_id)
        print(f"📊 Aggregates for job {job_id}:")
        print(f"    Failed logins: {failed_logins}")
        print(f"    Failure reasons: {failure_reasons}")

        if alert_enabled:
            threshold = 3  # Replace with job["threshold"] if dynamic
            triggered = [user for user, count in failed_logins.items() if count >= threshold]
            if triggered:
                subject = f"[ALERT] Failed login threshold crossed for Job {job_id}"
                body = [
                    f"Service: {service}",
                    f"Interval: {interval_seconds} seconds",
                    f"Triggered Users (≥{threshold} failed logins):"
                ]
                body += [f"- {u}: {failed_logins[u]}" for u in triggered]
                body += ["", "Failure Reasons:"]
                body += [f"- {r}: {c}" for r, c in failure_reasons.items()]
                send_alert(alert_channel, alert_target, subject, "\n".join(body))

    except Exception as e:
        print(f"❌ Error processing job: {e}")

def main():
    print("🚀 Starting Kafka consumer for topic: failed_logins")
    consumer.subscribe(['failed_logins'])

    try:
        while running:
            msg = consumer.poll(1.0)
            if not msg:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    raise KafkaException(msg.error())
            else:
                process_failed_login(msg)
                consumer.commit(msg)

    except KafkaException as e:
        print(f"⚠️ Kafka error: {e}")
    finally:
        print("🧹 Shutting down consumer...")
        consumer.close()

if __name__ == "__main__":
    main()