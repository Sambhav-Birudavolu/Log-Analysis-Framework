import sys
import signal
import json
from datetime import datetime
from confluent_kafka import Consumer, KafkaException, KafkaError
from background_functions import (
    fetch_logs_for_service_absolute,
    update_log_pattern_timeseries,
)

running = True

def shutdown_handler(sig, frame):
    global running
    print("\n🛑 Shutdown requested...")
    running = False

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'log-timeseries-group',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': False
})

def process_log_pattern_timeseries(msg):
    try:
        job = json.loads(msg.value().decode('utf-8'))
        print(f"📥 Received job: {job}")

        job_id = job["job_id"]
        service = job["service_name"]
        query = job.get("query", "")
        from_ts = datetime.strptime(job["from_timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        to_ts = datetime.strptime(job["to_timestamp"], "%Y-%m-%d %H:%M:%S.%f")

        logs = fetch_logs_for_service_absolute(service, from_ts, to_ts, query)
        series = update_log_pattern_timeseries(logs, job_id)

        print(f"📊 Timeseries updated in Redis for job {job_id}: {len(series)} buckets")

    except Exception as e:
        print(f"❌ Error processing job: {e}")

def main():
    print("🚀 Starting Kafka consumer for topic: log_pattern_timeseries")
    consumer.subscribe(['log_pattern_timeseries'])

    try:
        while running:
            msg = consumer.poll(1.0)
            if not msg:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    raise KafkaException(msg.error())
            else:
                process_log_pattern_timeseries(msg)
                consumer.commit(msg)

    except KafkaException as e:
        print(f"⚠️ Kafka error: {e}")
    finally:
        print("🧹 Closing consumer...")
        consumer.close()

if __name__ == "__main__":
    main()