import requests, random, time, json

GRAYLOG_URL = 'http://localhost:12201/gelf'

domains = ['example.fake', 'test.invalid', 'site.unknown']
clients = ['172.16.0.10', '10.10.10.20', '192.168.1.77']
reasons = ['NXDOMAIN', 'Timeout', 'Server failure']
statuses = ['INFO', 'WARN', 'ERROR']

while True:
    domain = random.choice(domains)
    client_ip = random.choice(clients)

    log = {
        "version": "1.1",
        "host": "dns-service",
        "short_message": "DNS query event",
        "full_message": f"Domain '{domain}' could not be resolved for client {client_ip}",
        "timestamp": time.time(),
        "status": random.choice(statuses),
        "_service": "dns-service",
        "_event_type": "dns_lookup_failure",
        "_queried_domain": domain,
        "_client_ip": client_ip,
        "_dns_server": "8.8.8.8",
        "_reason": random.choice(reasons),
        "_event_id": f"DNS{random.randint(100, 999)}"
    }

    requests.post(GRAYLOG_URL, json=log)
    print("Sent DNS log:", json.dumps(log))
    time.sleep(random.randint(2, 5))

