import sys
import signal
import json
from datetime import datetime, timedelta
from confluent_kafka import Consumer, KafkaException, KafkaError

from background_functions import (
    send_alert,
    fetch_logs_for_service_absolute,
    update_generic_log_aggregates
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

def process_generic_log_search(msg):
    try:
        job = json.loads(msg.value().decode('utf-8'))
        print(f"📥 Received job: {job}")

        job_id = job["job_id"]
        service = job["service_name"]
        interval_seconds = job["interval"]
        alert_enabled = job["alert_enabled"]
        alert_channel = job["alert_channel"]
        alert_target = job["alert_target"]
        query = job.get("query", "")
        threshold = job.get("threshold", 10)

        if ":" in query:
            field, keyword = query.split(":", 1)
        else:
            field, keyword = "generic", query or "match"

        from_ts = datetime.strptime(job["from_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        to_ts = datetime.strptime(job["to_timestamp"], "%Y-%m-%d %H:%M:%S.%f")

        logs = fetch_logs_for_service_absolute(service, from_ts, to_ts, query)
        match_count = len(logs)
        print(f"🔍 {match_count} logs matched for job {job_id} with query `{query}`")

        update_generic_log_aggregates(match_count, job_id, field, keyword)
        print(f"📦 Redis updated: {match_count} matches under {field}:{keyword}")

        if alert_enabled and match_count >= threshold:
            subject = f"[ALERT] {match_count} matches for `{query}` in {service}"
            lines = [
                f"Job ID: {job_id}",
                f"Service: {service}",
                f"Query: {query}",
                f"Matches: {match_count}",
                f"Threshold: {threshold}",
                f"Interval: {interval_seconds} seconds",
                f"Time Window: {from_ts} → {to_ts}",
                "\n🔎 Sample Logs:"
            ]
            sample_logs = logs[:5]
            lines += [json.dumps(log, indent=2)[:300] for log in sample_logs]
            send_alert(alert_channel, alert_target, subject, "\n".join(lines))

    except Exception as e:
        print(f"❌ Error processing job: {e}")

def main():
    print("🚀 Starting Kafka consumer for topic: generic_log_search")
    consumer.subscribe(['generic_log_search'])

    try:
        while running:
            msg = consumer.poll(1.0)
            if not msg:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    raise KafkaException(msg.error())
            else:
                process_generic_log_search(msg)
                consumer.commit(msg)

    except KafkaException as e:
        print(f"⚠️ Kafka error: {e}")
    finally:
        print("🧹 Shutting down consumer...")
        consumer.close()

if __name__ == "__main__":
    main()