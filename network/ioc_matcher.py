
import json
import sqlite3
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter


# ==========================================
# PROJECT PATHS
# ==========================================

ROOT = Path(__file__).resolve().parent.parent

DB_FILE = ROOT / "data" / "threat_intel.db"
DNS_FILE = ROOT / "data" / "network" / "dns_queries.json"
CONN_FILE = ROOT / "data" / "network" / "connections.json"
OUTPUT_FILE = ROOT / "data" / "network" / "ioc_matches.json"


# ==========================================
# NORMALIZATION FUNCTIONS
# ==========================================

def normalize_domain(value):
    if not value:
        return None

    value = value.strip().lower().rstrip(".")

    if not value or value == "-":
        return None

    return value


def normalize_ip(value):
    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def parse_url(value):
    try:
        parsed = urlsplit(value.strip())

        host = parsed.hostname

        if not host:
            return None

        try:
            port = parsed.port
        except ValueError:
            return None

        ip = normalize_ip(host)

        return {
            "host": ip if ip else normalize_domain(host),
            "is_ip": ip is not None,
            "port": port
        }

    except ValueError:
        return None


def parse_ip_port(value):
    try:
        ip, port = value.rsplit(":", 1)

        normalized_ip = normalize_ip(ip)
        port = int(port)

        if normalized_ip and 0 <= port <= 65535:
            return normalized_ip, port

    except (ValueError, AttributeError):
        pass

    return None


# ==========================================
# DATA LOADING
# ==========================================

def load_iocs():
    connection = sqlite3.connect(
        f"file:{DB_FILE.as_posix()}?mode=ro",
        uri=True
    )

    connection.row_factory = sqlite3.Row

    rows = connection.execute("""
        SELECT id, ioc, ioc_type, source, threat_type,
               malware, confidence, first_seen, last_seen,
               reporter, tags
        FROM iocs
    """).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ==========================================
# IOC INDEXING
# ==========================================

def build_indexes(iocs):

    domains = {}
    ips = {}
    ip_ports = {}
    url_ip_ports = {}
    url_hosts = {}

    for ioc in iocs:

        value = ioc["ioc"].strip()
        ioc_type = ioc["ioc_type"].lower()

        # Domain and hostname IOCs
        if ioc_type in ("domain", "hostname"):

            key = normalize_domain(value)

            if key:
                domains.setdefault(key, []).append(ioc)

        # Standalone IPv4 IOCs
        elif ioc_type == "ipv4":

            key = normalize_ip(value)

            if key:
                ips.setdefault(key, []).append(ioc)

        # IP:Port IOCs
        elif ioc_type == "ip:port":

            parsed = parse_ip_port(value)

            if parsed:
                ip_ports.setdefault(parsed, []).append(ioc)

        # URL IOCs
        elif ioc_type == "url":

            parsed = parse_url(value)

            if not parsed:
                continue

            # URL containing an IP address and explicit port
            if parsed["is_ip"] and parsed["port"] is not None:

                key = (parsed["host"], parsed["port"])

                url_ip_ports.setdefault(key, []).append(ioc)

            # Keep URL hosts separate from actual domain IOCs
            else:

                url_hosts.setdefault(
                    parsed["host"], []
                ).append(ioc)

    return domains, ips, ip_ports, url_ip_ports, url_hosts


# ==========================================
# MATCH RECORD CREATION
# ==========================================

def add_match(
    results,
    seen,
    ioc,
    event_type,
    record,
    matched_value,
    matched_field,
    match_type
):

    key = (
        ioc.get("ioc"),
        ioc.get("ioc_type"),
        ioc.get("source"),
        event_type,
        record.get("uid"),
        record.get("timestamp"),
        record.get("domain"),
        record.get("src_ip"),
        record.get("src_port"),
        record.get("dst_ip"),
        record.get("dst_port"),
        matched_field,
        matched_value,
        match_type
    )

    if key in seen:
        return

    seen.add(key)

    results.append({
        "ioc": ioc,
        "match_type": match_type,
        "matched_value": matched_value,
        "matched_field": matched_field,
        "event_type": event_type,
        "event": record
    })


# ==========================================
# DNS MATCHING
# ==========================================

def match_dns(dns_records, domains, ips, results, seen):

    for record in dns_records:

        domain = normalize_domain(record.get("domain"))

        # Match actual Domain and Hostname IOCs only
        if domain and domain in domains:

            for ioc in domains[domain]:

                add_match(
                    results,
                    seen,
                    ioc,
                    "dns",
                    record,
                    domain,
                    "domain",
                    "EXACT_DOMAIN"
                )

        # Match standalone IPv4 IOCs against DNS answers
        for answer in record.get("answers") or []:

            answer_ip = normalize_ip(answer)

            if answer_ip and answer_ip in ips:

                for ioc in ips[answer_ip]:

                    add_match(
                        results,
                        seen,
                        ioc,
                        "dns",
                        record,
                        answer_ip,
                        "answer",
                        "EXACT_IP"
                    )


# ==========================================
# CONNECTION MATCHING
# ==========================================

def match_connections(
    conn_records,
    ips,
    ip_ports,
    url_ip_ports,
    results,
    seen
):

    for record in conn_records:

        dst_ip = normalize_ip(record.get("dst_ip"))
        src_ip = normalize_ip(record.get("src_ip"))

        dst_port = record.get("dst_port")
        src_port = record.get("src_port")

        # --------------------------------------
        # Standalone IPv4 IOC matching
        # --------------------------------------

        for field, ip in (
            ("dst_ip", dst_ip),
            ("src_ip", src_ip)
        ):

            if ip and ip in ips:

                for ioc in ips[ip]:

                    add_match(
                        results,
                        seen,
                        ioc,
                        "connection",
                        record,
                        ip,
                        field,
                        "EXACT_IP"
                    )

        # --------------------------------------
        # IP:Port and URL IP:Port matching
        # --------------------------------------

        for field, ip, port in (
            ("dst_ip:dst_port", dst_ip, dst_port),
            ("src_ip:src_port", src_ip, src_port)
        ):

            if not ip or port is None:
                continue

            try:
                normalized_port = int(port)

                if not 0 <= normalized_port <= 65535:
                    continue

            except (ValueError, TypeError):
                continue

            key = (ip, normalized_port)

            # Actual IP:Port IOC
            if key in ip_ports:

                for ioc in ip_ports[key]:

                    add_match(
                        results,
                        seen,
                        ioc,
                        "connection",
                        record,
                        f"{ip}:{normalized_port}",
                        field,
                        "EXACT_IP_PORT"
                    )

            # URL IOC whose host is an IP and has a port.
            # This confirms only the IP:Port endpoint,
            # not the complete URL or its path.

            if key in url_ip_ports:

                for ioc in url_ip_ports[key]:

                    add_match(
                        results,
                        seen,
                        ioc,
                        "connection",
                        record,
                        f"{ip}:{normalized_port}",
                        field,
                        "URL_IP_PORT_MATCH"
                    )


# ==========================================
# MATCH ANALYSIS SUMMARY
# ==========================================

def print_summary(iocs, dns_records, conn_records, results):

    match_types = Counter(
        match["match_type"] for match in results
    )

    matched_iocs = {
        (
            match["ioc"]["ioc"],
            match["ioc"]["ioc_type"],
            match["ioc"]["source"]
        )
        for match in results
    }

    print("\n========== MATCH SUMMARY ==========")

    print("Total IOCs:", len(iocs))
    print("DNS records:", len(dns_records))
    print("Connection records:", len(conn_records))

    print("Total match records:", len(results))
    print("Unique matched IOCs:", len(matched_iocs))

    print("\nMatches by type:")

    for name, count in match_types.most_common():
        print(f"{name}: {count}")

    print("===================================\n")


# ==========================================
# MAIN
# ==========================================

def main():

    print("Loading IOC database...")
    iocs = load_iocs()

    print("Loading network data...")
    dns_records = load_json(DNS_FILE)
    conn_records = load_json(CONN_FILE)

    print("Building IOC indexes...")

    (
        domains,
        ips,
        ip_ports,
        url_ip_ports,
        url_hosts
    ) = build_indexes(iocs)

    print("\nIOC Index Statistics:")
    print("Domain IOCs:", sum(len(v) for v in domains.values()))
    print("IPv4 IOCs:", sum(len(v) for v in ips.values()))
    print("IP:Port IOCs:", sum(len(v) for v in ip_ports.values()))
    print("URL IP:Port IOCs:", sum(len(v) for v in url_ip_ports.values()))
    print("URL Host indicators:", sum(len(v) for v in url_hosts.values()))

    results = []
    seen = set()

    print("\nMatching DNS records...")
    match_dns(
        dns_records,
        domains,
        ips,
        results,
        seen
    )

    print("Matching connection records...")
    match_connections(
        conn_records,
        ips,
        ip_ports,
        url_ip_ports,
        results,
        seen
    )

    # Save results
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\nMatching completed!")

    print_summary(
        iocs,
        dns_records,
        conn_records,
        results
    )

    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
