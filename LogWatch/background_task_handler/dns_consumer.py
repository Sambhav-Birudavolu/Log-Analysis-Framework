import sys
import signal
import json
from datetime import datetime
from confluent_kafka import Consumer, KafkaException, KafkaError

from background_functions import (
    fetch_logs_for_service_absolute,
    update_dns_alert_stats,
    send_alert
)

# Graceful shutdown handling
running = True
def shutdown_handler(sig, frame):
    global running
    print("\n🛑 Shutdown requested... exiting.")
    running = False

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Kafka consumer configuration
consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'dns-alert-group',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False
})

def process_dns_alert_job(msg):
    try:
        job = json.loads(msg.value().decode('utf-8'))
        print(f"📥 Received DNS alert job: {job}")

        job_id = job["job_id"]
        service = job["service_name"]
        from_ts = datetime.strptime(job["from_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        to_ts = datetime.strptime(job["to_timestamp"], "%Y-%m-%d %H:%M:%S.%f")

        alert_enabled = job.get("alert_enabled", False)
        alert_channel = job.get("alert_channel", "")
        alert_target = job.get("alert_target", "")
        reason_threshold = job.get("reason_threshold", 5)
        domain_threshold = job.get("domain_threshold", 5)

        logs = fetch_logs_for_service_absolute(service, from_ts, to_ts)
        print(f"🔍 Retrieved {len(logs)} logs for service `{service}`.")

        stats = update_dns_alert_stats(logs, job_id, reason_threshold, domain_threshold)
        print(f"📊 DNS alert stats for job {job_id}:")
        print(f"    Reasons: {stats['reason_counts']}")
        print(f"    Domains: {stats['domain_counts']}")

        if alert_enabled and stats["alerts"]:
            for alert in stats["alerts"]:
                subject = f"[DNS ALERT] 🚨 {alert['type'].capitalize()} Alert - {alert['value']}"
                message = (
                    f"Job ID: {job_id}\n"
                    f"Service: {service}\n"
                    f"Window: {from_ts} to {to_ts}\n"
                    f"Alert Type: {alert['type']}\n"
                    f"Value: {alert['value']}\n"
                    f"Message: {alert['message']}"
                )
                send_alert(alert_channel, alert_target, subject, message)

    except Exception as e:
        print(f"❌ Error processing DNS alert job: {e}")

def main():
    print("🚀 Starting Kafka consumer for topic: dns_alerts")
    consumer.subscribe(['dns_alerts'])

    try:
        while running:
            msg = consumer.poll(1.0)
            if not msg:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    raise KafkaException(msg.error())
            else:
                process_dns_alert_job(msg)
                consumer.commit(msg)

    except KafkaException as e:
        print(f"⚠️ Kafka error: {e}")
    finally:
        print("🧹 Closing Kafka consumer...")
        consumer.close()

if __name__ == "__main__":
    main()