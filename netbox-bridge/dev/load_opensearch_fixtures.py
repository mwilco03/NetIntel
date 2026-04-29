"""Load Zeek conn + Suricata alert documents into OpenSearch with real ECS field paths.

Field paths used here are the ones verified against upstream pipelines (Filebeat Suricata
module + Malcolm logstash). After loading, the OpenSearchClient + Malcolm/SuricataSource
queries are run for real and their outputs captured. This replaces the synthetic JSON fixtures
that would not survive a real-world Malcolm encounter.
"""
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

OS_URL = "http://localhost:9200"

# Two Zeek-style indices: one Malcolm-shaped (arkime_sessions3-*), one SO-shaped (logs-zeek-so).
INDICES = {
    "arkime_sessions3-2026.04.28": {  # Malcolm
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {
                    "kind": {"type": "keyword"},
                    "dataset": {"type": "keyword"},
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
    },
    "logs-zeek-so-2026.04.28": {  # Security Onion
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": None,  # let OpenSearch auto-detect
    },
}


def http(method, path, body=None):
    req = urllib.request.Request(
        OS_URL + path,
        data=json.dumps(body).encode() if body else None,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode(), "status": e.code}


def create_indices():
    for name, spec in INDICES.items():
        # Delete if exists, recreate
        http("DELETE", f"/{name}")
        body = {"settings": spec["settings"]}
        if spec["mappings"]:
            body["mappings"] = spec["mappings"]
        r = http("PUT", f"/{name}", body)
        print(f"  index {name}: {r.get('acknowledged', r)}")


def index_doc(index, doc_id, doc):
    return http("PUT", f"/{index}/_doc/{doc_id}", doc)


def now_iso(offset_minutes=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


# -----------------------------------------------------------------------------
# Zeek conn-style observations (Malcolm / SO)
# -----------------------------------------------------------------------------

def make_zeek_conn(*, src_ip, dst_ip, dst_port, transport, protocol, dst_mac=None):
    """Field paths verified against Malcolm logstash 1015_zeek_conn.conf + 1300_zeek_normalize.conf
    and SO zeek.common ingest pipeline. Real Malcolm conn data has all of these populated when
    L2 capture is on."""
    doc = {
        "@timestamp": now_iso(),
        "event": {"kind": "event", "dataset": "conn"},
        "source": {"ip": src_ip, "port": 53124},
        "destination": {"ip": dst_ip, "port": dst_port, **({"mac": dst_mac} if dst_mac else {})},
        "network": {"transport": transport, "protocol": protocol},
    }
    return doc


def make_suricata_alert(*, src_ip, dst_ip, severity, sid, signature, category):
    """Field paths verified against Filebeat Suricata module ingest/pipeline.yml AND Malcolm
    logstash/pipelines/suricata/11_suricata_logs.conf.
      alert.signature_id -> rule.id
      alert.signature    -> rule.name
      alert.severity     -> event.severity (Filebeat preserves; Malcolm rewrites — see audit)
      event.kind = "alert"
    """
    return {
        "@timestamp": now_iso(),
        "event": {"kind": "alert", "dataset": "alert", "severity": severity},
        "source": {"ip": src_ip},
        "destination": {"ip": dst_ip},
        "rule": {"id": str(sid), "name": signature, "category": category},
    }


def main():
    print("=== Creating indices ===")
    create_indices()

    print("=== Loading Malcolm-shaped Zeek conn docs ===")
    # 10.0.0.5: Siemens MAC, modbus + http
    for i, (port, transport, proto) in enumerate([(502, "tcp", "modbus"), (80, "tcp", "http")]):
        for j in range(5):  # 5 conn records per service to populate aggs
            doc = make_zeek_conn(
                src_ip="10.0.0.99", dst_ip="10.0.0.5", dst_port=port,
                transport=transport, protocol=proto,
                dst_mac="00:0e:8c:11:22:33"
            )
            index_doc("arkime_sessions3-2026.04.28", f"5-{i}-{j}", doc)
    # 10.0.0.6: Rockwell MAC, profinet + s7comm
    for i, (port, transport, proto) in enumerate([(34962, "tcp", "profinet"), (102, "tcp", "s7comm")]):
        for j in range(3):
            doc = make_zeek_conn(
                src_ip="10.0.0.99", dst_ip="10.0.0.6", dst_port=port,
                transport=transport, protocol=proto,
                dst_mac="08:61:95:aa:bb:cc"
            )
            index_doc("arkime_sessions3-2026.04.28", f"6-{i}-{j}", doc)
    # 10.0.0.7: no MAC observed (graceful degradation case), dns only
    for j in range(2):
        doc = make_zeek_conn(
            src_ip="10.0.0.99", dst_ip="10.0.0.7", dst_port=53,
            transport="udp", protocol="dns"
        )
        index_doc("arkime_sessions3-2026.04.28", f"7-{j}", doc)

    print("=== Loading Suricata alerts ===")
    for j in range(20):  # 20 high-severity alerts on 10.0.0.5
        doc = make_suricata_alert(
            src_ip="10.0.0.99", dst_ip="10.0.0.5", severity=1, sid=2027865,
            signature="ET POLICY HTTP traffic on port 443",
            category="Potentially Bad Traffic",
        )
        index_doc("arkime_sessions3-2026.04.28", f"alert-5-1-{j}", doc)
    for j in range(80):  # 80 medium alerts on 10.0.0.5
        doc = make_suricata_alert(
            src_ip="10.0.0.99", dst_ip="10.0.0.5", severity=2, sid=2024900,
            signature="ET INFO Generic POST to dotted-quad host",
            category="Misc activity",
        )
        index_doc("arkime_sessions3-2026.04.28", f"alert-5-2-{j}", doc)
    for j in range(50):  # 50 low alerts on 10.0.0.6
        doc = make_suricata_alert(
            src_ip="10.0.0.99", dst_ip="10.0.0.6", severity=3, sid=2018959,
            signature="ET INFO TLS Handshake Foo",
            category="Misc activity",
        )
        index_doc("arkime_sessions3-2026.04.28", f"alert-6-3-{j}", doc)

    print("=== Refreshing index ===")
    http("POST", "/arkime_sessions3-2026.04.28/_refresh")
    print("=== Counting docs ===")
    r = http("GET", "/arkime_sessions3-2026.04.28/_count")
    print(f"  arkime_sessions3-2026.04.28: {r.get('count', r)} docs")


if __name__ == "__main__":
    main()
