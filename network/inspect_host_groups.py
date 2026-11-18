
import json
import sqlite3
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent

DB_FILE = ROOT / "data/threat_intel.db"
DNS_FILE = ROOT / "data/network/dns_queries.json"
CONN_FILE = ROOT / "data/network/connections.json"

WINDOW_MINUTES = 5


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def normalize_domain(value):
    return str(value or "").strip().lower().rstrip(".")


def extract_ipv4_addresses(answers):
    ips = set()

    if not isinstance(answers, list):
        return ips

    for answer in answers:
        if not isinstance(answer, str):
            continue

        value = answer.strip()

        try:
            parsed = ipaddress.ip_address(value)
            if parsed.version == 4:
                ips.add(value)
        except ValueError:
            continue

    return ips


def load_url_iocs():
    hosts = defaultdict(set)

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            """
            SELECT ioc
            FROM iocs
            WHERE LOWER(ioc_type) = 'url'
            """
        ).fetchall()

    for (ioc,) in rows:
        try:
            host = normalize_domain(urlsplit(ioc).hostname)
        except ValueError:
            continue

        if host:
            hosts[host].add(ioc)

    return hosts


def main():
    print("Loading data...")

    url_hosts = load_url_iocs()
    dns_records = load_json(DNS_FILE)
    conn_records = load_json(CONN_FILE)

    dns_by_host = defaultdict(list)
    connections_by_dst_ip = defaultdict(list)

    for record in dns_records:
        host = normalize_domain(record.get("domain"))
        timestamp = parse_timestamp(record.get("timestamp"))

        if host and timestamp:
            dns_by_host[host].append((timestamp, record))

    for connection in conn_records:
        timestamp = parse_timestamp(connection.get("timestamp"))
        dst_ip = connection.get("dst_ip")

        if timestamp and dst_ip:
            connections_by_dst_ip[dst_ip].append(
                (timestamp, connection)
            )

    # Sort connections by timestamp for consistent analysis.
    for ip in connections_by_dst_ip:
        connections_by_dst_ip[ip].sort(key=lambda item: item[0])

    window = timedelta(minutes=WINDOW_MINUTES)

    total_correlated_connections = 0
    hosts_with_dns = 0
    hosts_with_correlations = 0

    print("\n========== FINAL NETWORK CORRELATION ==========")
    print("Correlation window:", WINDOW_MINUTES, "minutes")
    print("Connection direction: destination IP only")

    for host, iocs in sorted(url_hosts.items()):
        host_dns = dns_by_host.get(host, [])

        if not host_dns:
            continue

        hosts_with_dns += 1
        correlated = {}

        for dns_time, dns_event in host_dns:
            answer_ips = extract_ipv4_addresses(
                dns_event.get("answers")
            )

            for ip in answer_ips:
                for conn_time, connection in connections_by_dst_ip.get(ip, []):
                    if conn_time < dns_time:
                        continue

                    if conn_time > dns_time + window:
                        break

                    uid = connection.get("uid")

                    if not uid:
                        continue

                    # Keep each connection only once per host.
                    if uid not in correlated:
                        correlated[uid] = {
                            "connection_timestamp": connection.get("timestamp"),
                            "connection_uid": uid,
                            "dst_ip": ip,
                            "dst_port": connection.get("dst_port"),
                            "protocol": connection.get("protocol"),
                            "src_ip": connection.get("src_ip"),
                            "dns_timestamp": dns_event.get("timestamp"),
                            "dns_uid": dns_event.get("uid")
                        }

        if correlated:
            hosts_with_correlations += 1

        total_correlated_connections += len(correlated)

        dns_uids = {
            event.get("uid")
            for _, event in host_dns
            if event.get("uid")
        }

        print(f"\nHost: {host}")
        print("Unique URL IOCs:", len(iocs))
        print("DNS Events:", len(host_dns))
        print("Unique DNS UIDs:", len(dns_uids))
        print("Destination-IP Correlated Connections:", len(correlated))

        print("URL IOC Samples:")
        for ioc in sorted(iocs)[:3]:
            print(" ", ioc)

        print("Connection Evidence Samples:")
        for evidence in list(correlated.values())[:5]:
            print(" ", evidence)

    print("\n================================================")
    print("Hosts with DNS overlap:", hosts_with_dns)
    print("Hosts with destination-IP correlations:",
          hosts_with_correlations)
    print("Total unique connections across host groups:",
          total_correlated_connections)


if __name__ == "__main__":
    main()
