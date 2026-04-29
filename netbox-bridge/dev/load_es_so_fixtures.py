"""Load Security Onion-shaped Zeek + Suricata documents into Elasticsearch.

Field paths verified against Security-Onion-Solutions/securityonion ingest pipelines:
- zeek.common: id.orig_h -> source.ip, id.resp_h -> destination.ip, etc.
- zeek.conn: proto -> network.transport, service -> network.protocol
- alert.signature_id -> rule.id (via Filebeat Suricata module convention)

Uses ES datastream-equivalent: a backing index with an alias 'logs-zeek-so' so the bridge's
literal DEFAULT_INDEX_PATTERN routes correctly.
"""
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

ES_URL = "http://localhost:9201"


def http(method, path, body=None):
    req = urllib.request.Request(
        ES_URL + path,
        data=json.dumps(body).encode() if body else None,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode(), "status": e.code}


# Wipe-and-recreate idempotent setup
INDEX = "logs-zeek-so-2026.04.28"
ALIAS = "logs-zeek-so"

http("DELETE", f"/{INDEX}")

# Create the backing index with explicit ECS-aligned mapping (SO ingest pipelines normalize
# everything into ECS field paths regardless of source log type)
http("PUT", f"/{INDEX}", {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {
                "kind": {"type": "keyword"},
                "dataset": {"type": "keyword"},
                "module": {"type": "keyword"},
                "severity": {"type": "long"},
            }},
            "source": {"properties": {
                "ip": {"type": "ip"},
                "port": {"type": "long"},
                "mac": {"type": "keyword"},
            }},
            "destination": {"properties": {
                "ip": {"type": "ip"},
                "port": {"type": "long"},
                "mac": {"type": "keyword"},
            }},
            "network": {"properties": {
                "transport": {"type": "keyword"},
                "protocol": {"type": "keyword"},
            }},
            "rule": {"properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "category": {"type": "keyword"},
            }},
        }
    }
})

# Mount alias 'logs-zeek-so' so the bridge's DEFAULT_INDEX_PATTERN routes correctly.
http("POST", "/_aliases", {
    "actions": [{"add": {"index": INDEX, "alias": ALIAS}}]
})

print(f"Created index {INDEX} with alias {ALIAS}")


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def conn(*, src, dst, dst_port, transport, protocol, dst_mac=None):
    return {
        "@timestamp": now_iso(),
        "event": {"kind": "event", "dataset": "conn", "module": "zeek"},
        "source": {"ip": src, "port": 53124},
        "destination": {"ip": dst, "port": dst_port, **({"mac": dst_mac} if dst_mac else {})},
        "network": {"transport": transport, "protocol": protocol},
    }


def alert(*, src, dst, severity, sid, signature, category):
    return {
        "@timestamp": now_iso(),
        # Filebeat module sets event.kind=alert and event.module=suricata
        "event": {"kind": "alert", "dataset": "alert", "module": "suricata", "severity": severity},
        "source": {"ip": src},
        "destination": {"ip": dst},
        "rule": {"id": str(sid), "name": signature, "category": category},
    }


# Same data shape as the Malcolm/OS test for parity
n = 0
for j in range(5):
    http("POST", f"/{INDEX}/_doc",
         conn(src="10.0.0.99", dst="10.0.0.5", dst_port=502,
              transport="tcp", protocol="modbus",
              dst_mac="00:0e:8c:11:22:33"))
    n += 1
for j in range(5):
    http("POST", f"/{INDEX}/_doc",
         conn(src="10.0.0.99", dst="10.0.0.5", dst_port=80,
              transport="tcp", protocol="http",
              dst_mac="00:0e:8c:11:22:33"))
    n += 1
for j in range(3):
    http("POST", f"/{INDEX}/_doc",
         conn(src="10.0.0.99", dst="10.0.0.6", dst_port=34962,
              transport="tcp", protocol="profinet",
              dst_mac="08:61:95:aa:bb:cc"))
    n += 1
for j in range(3):
    http("POST", f"/{INDEX}/_doc",
         conn(src="10.0.0.99", dst="10.0.0.6", dst_port=102,
              transport="tcp", protocol="s7comm",
              dst_mac="08:61:95:aa:bb:cc"))
    n += 1
for j in range(20):
    http("POST", f"/{INDEX}/_doc",
         alert(src="10.0.0.99", dst="10.0.0.5", severity=1,
               sid=2027865, signature="ET POLICY HTTP traffic on port 443",
               category="Potentially Bad Traffic"))
    n += 1
for j in range(80):
    http("POST", f"/{INDEX}/_doc",
         alert(src="10.0.0.99", dst="10.0.0.5", severity=2,
               sid=2024900, signature="ET INFO Generic POST to dotted-quad host",
               category="Misc activity"))
    n += 1
for j in range(50):
    http("POST", f"/{INDEX}/_doc",
         alert(src="10.0.0.99", dst="10.0.0.6", severity=3,
               sid=2018959, signature="ET INFO TLS Handshake Foo",
               category="Misc activity"))
    n += 1

http("POST", f"/{INDEX}/_refresh")
r = http("GET", f"/{ALIAS}/_count")
print(f"alias logs-zeek-so: {r.get('count', r)} docs ({n} indexed)")
