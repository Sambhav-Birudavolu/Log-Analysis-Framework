import sys
import signal
import json
from datetime import datetime
from confluent_kafka import Consumer, KafkaException, KafkaError
from background_functions import (
    fetch_logs_for_service_absolute,
    update_high_threat_protocol_stats,
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
    'group.id': 'firewall-analysis-group',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False
})

def process_high_threat_protocol(msg):
    try:
        job = json.loads(msg.value().decode('utf-8'))
        print(f"📥 Received job: {job}")

        job_id = job["job_id"]
        service = job["service_name"]
        from_ts = datetime.strptime(job["from_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        to_ts = datetime.strptime(job["to_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        threshold = job.get("threshold", 10)
        alert_enabled = job.get("alert_enabled", False)
        alert_channel = job.get("alert_channel", "")
        alert_target = job.get("alert_target", "")

        logs = fetch_logs_for_service_absolute(service, from_ts, to_ts)
        print(f"🔍 Retrieved {len(logs)} logs for `{service}`")

        stats = update_high_threat_protocol_stats(logs, job_id)
        print(f"📊 Threat stats for job {job_id}: {stats}")

        if alert_enabled and stats.get("high", 0) >= threshold:
            protocol_freq = stats.get("protocol_freq", {})
            most_common_protocol = max(protocol_freq.items(), key=lambda x: x[1])[0] if protocol_freq else "N/A"

            subject = f"[ALERT] 🚨 High Threat Activity Detected in `{service}`"
            message = (
                f"Job ID: {job_id}\n"
                f"Service: {service}\n"
                f"Window: {from_ts} to {to_ts}\n"
                f"Total High Threat Logs: {stats.get('high', 0)}\n"
                f"Most Common Protocol: {most_common_protocol}\n"
                f"\nLow Threat Logs: {stats.get('low', 0)}\n"
                f"Medium Threat Logs: {stats.get('medium', 0)}"
            )
            send_alert(alert_channel, alert_target, subject, message)

    except Exception as e:
        print(f"❌ Error processing job: {e}")

def main():
    print("🚀 Starting consumer for topic: high_threat_protocol")
    consumer.subscribe(['high_threat_protocol'])

    try:
        while running:
            msg = consumer.poll(1.0)
            if not msg:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    raise KafkaException(msg.error())
            else:
                process_high_threat_protocol(msg)
                consumer.commit(msg)
    except KafkaException as e:
        print(f"⚠️ Kafka error: {e}")
    finally:
        print("🧹 Closing consumer...")
        consumer.close()

if __name__ == "__main__":
    main()