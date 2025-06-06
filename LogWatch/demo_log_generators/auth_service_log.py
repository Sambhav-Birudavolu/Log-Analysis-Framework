import requests, random, time, json

GRAYLOG_URL = 'http://localhost:12201/gelf'

users = ['admin', 'jdoe', 'guest', 'user123']
ips = [
    '192.168.1.100', '10.0.0.5',  # internal/private
    '8.8.8.8', '91.198.174.192', '203.0.113.45'  # public
]
reasons = ['Invalid password', 'User not found', 'Account locked']
statuses = ['INFO', 'WARN', 'ERROR']

while True:
    log = {
        "version": "1.1",
        "host": "auth-service",
        "short_message": "Login event",
        "full_message": f"Login attempt by user '{(u := random.choice(users))}' from IP {(ip := random.choice(ips))}",
        "timestamp": time.time(),
        "status": random.choice(statuses),
        "_service": "auth-service",
        "_event_type": "authentication_attempt",
        "_username": u,
        "_source_ip": ip,
        "_user_agent": "Mozilla/5.0",
        "_failure_reason": random.choice(reasons),
        "_event_id": f"AUTH{random.randint(400,499)}"
    }

    requests.post(GRAYLOG_URL, json=log)
    print("Sent auth log:", json.dumps(log))
    time.sleep(random.randint(1, 3))
