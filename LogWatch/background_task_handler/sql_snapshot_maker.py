import time
import json
import redis
from datetime import datetime
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv(dotenv_path=os.path.join("config", ".env"))
rdb = redis.Redis(host='localhost', port=6379, decode_responses=True)

def create_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

def sync_last_runs_and_results():
    print("🔄 Syncing Redis to SQL...")
    conn = None
    try:
        conn = create_connection()
        cursor = conn.cursor()

        for key in rdb.scan_iter("job:*:last_run"):
            try:
                job_id = int(key.split(":")[1])
                last_run_str = rdb.get(key)
                if last_run_str:
                    cursor.execute(
                        "UPDATE background_jobs SET last_run = %s WHERE id = %s",
                        (last_run_str, job_id)
                    )
            except Exception as e:
                print(f"⚠️ Error syncing last_run for {key}: {e}")

        for key in rdb.scan_iter("job:*:data"):
            try:
                job_id = int(key.split(":")[1])
                result_hash = rdb.hgetall(key)
                if result_hash:
                    result_json = json.dumps(result_hash)
                    timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

                    cursor.execute("""
                        INSERT INTO job_results (job_id, timestamp, result_json)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            timestamp = VALUES(timestamp),
                            result_json = VALUES(result_json)
                    """, (job_id, timestamp_now, result_json))
            except Exception as e:
                print(f"⚠️ Error syncing data for {key}: {e}")

        conn.commit()
        cursor.close()
        print("✅ Redis sync to SQL complete.")

    except Error as e:
        print(f"❌ SQL error: {e}")
    finally:
        if conn.is_connected():
            conn.close()

if __name__ == "__main__":
    while True:
        sync_last_runs_and_results()
        time.sleep(30)
