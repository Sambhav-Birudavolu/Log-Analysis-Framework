import requests, random, time, json

GRAYLOG_URL = 'http://localhost:12201/gelf'

ips = ['10.0.0.8', '172.16.1.4', '192.168.1.99']
protocols = ['TCP', 'UDP']
threats = ['low', 'medium', 'high']
statuses = ['INFO', 'WARN', 'ERROR']

while True:
    ip = random.choice(ips)
    log = {
        "version": "1.1",
        "host": "firewall-service",
        "short_message": "Firewall alert",
        "full_message": f"Port scan activity detected from {ip}",
        "timestamp": time.time(),
        "status": random.choice(statuses),
        "_service": "firewall-service",
        "_event_type": "port_scan",
        "_source_ip": ip,
        "_destination_port_range": f"{random.randint(20, 100)}-{random.randint(1000, 2000)}",
        "_protocol": random.choice(protocols),
        "_threat_level": random.choice(threats),
        "_action_taken": "IP blocked",
        "_event_id": f"FW{random.randint(1, 999):03d}"
    }

    requests.post(GRAYLOG_URL, json=log)
    print("Sent firewall log:", json.dumps(log))
    time.sleep(random.randint(2, 4))

