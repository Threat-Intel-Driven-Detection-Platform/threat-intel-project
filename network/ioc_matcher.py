
import argparse
import hashlib
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
OUTPUT_FILE = ROOT / "data" / "network" / "ioc_matches.json"      # legacy nested format (kept for old scripts)
DETECTIONS_FILE = ROOT / "results" / "detections.json"            # official Week 2 flat format (for Week 3)
SAMPLE_IOC_FILE = ROOT / "data" / "iocs" / "sample_iocs.json"     # lab sample indicators (spec: "known sample indicators")
SAMPLE_OUTPUT_FILE = ROOT / "results" / "sample_validation.json"


DEFAULT_PORTS = {"http": 80, "https": 443}


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
            "port": port,
            "scheme": (parsed.scheme or "").lower()
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

            # URL containing an IP address. If no explicit port is given,
            # the scheme implies it (http -> 80, https -> 443).
            # (Previously these URLs were silently dropped into url_hosts
            #  and could never match a connection.)
            port = parsed["port"]

            if parsed["is_ip"] and port is None:
                port = DEFAULT_PORTS.get(parsed["scheme"])

            if parsed["is_ip"] and port is not None:

                key = (parsed["host"], port)

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

        # Subdomain of an IOC domain: query "a.b.evil.com" hits IOC "evil.com"
        # (parent labels only, never a bare TLD, exact match handled above)
        if domain:
            labels = domain.split(".")

            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])

                for ioc in domains.get(parent, []):

                    add_match(
                        results,
                        seen,
                        ioc,
                        "dns",
                        record,
                        domain,
                        "domain",
                        "SUBDOMAIN_OF_IOC_DOMAIN"
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
# OFFICIAL DETECTION RECORD (Week 2 -> Week 3 contract)
# ==========================================

DOMAIN_MATCH_TYPES = ("EXACT_DOMAIN", "SUBDOMAIN_OF_IOC_DOMAIN")


def to_detection_record(match):
    """Flatten an internal match into the agreed Week 2 detection record."""

    ioc = match["ioc"]
    event = match["event"]
    match_type = match["match_type"]
    is_dns = match["event_type"] == "dns"

    if match_type in DOMAIN_MATCH_TYPES:
        indicator = normalize_domain(ioc["ioc"])
        indicator_type = "domain"
    else:
        # matched_value is "ip" or "ip:port" -> indicator is always the IP
        indicator = match["matched_value"].rsplit(":", 1)[0] \
            if match_type.endswith("_PORT_MATCH") or match_type == "EXACT_IP_PORT" \
            else match["matched_value"]
        indicator_type = "ip"

    port = event.get("src_port") if match["matched_field"].startswith("src") \
        else event.get("dst_port")

    fingerprint = "|".join(str(x) for x in (
        ioc.get("ioc"), ioc.get("ioc_type"), ioc.get("source"),
        match["event_type"], event.get("uid"), event.get("timestamp"),
        match["matched_field"], match["matched_value"], match_type
    ))

    return {
        "match_id": "M-" + hashlib.sha1(fingerprint.encode()).hexdigest()[:16],
        "timestamp": event.get("timestamp"),
        "indicator": indicator,
        "indicator_type": indicator_type,
        "source": ioc.get("source"),
        "evidence_source": "dns.log" if is_dns else "conn.log",
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "domain": event.get("domain") if is_dns else None,
        "port": port,
        # extra context (additive - Week 3/4 may ignore or use)
        "match_type": match_type,
        "matched_field": match["matched_field"],
        "ioc_value": ioc.get("ioc"),
        "ioc_type": ioc.get("ioc_type"),
        "threat_type": ioc.get("threat_type"),
        "malware": ioc.get("malware"),
        "confidence": ioc.get("confidence"),
        "ioc_first_seen": ioc.get("first_seen"),
        "uid": event.get("uid"),
        "protocol": event.get("protocol"),
    }


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


# ==========================================
# MAIN
# ==========================================

def run_matching(iocs, dns_records, conn_records, verbose=True):

    (
        domains,
        ips,
        ip_ports,
        url_ip_ports,
        url_hosts
    ) = build_indexes(iocs)

    if verbose:
        print("IOC Index Statistics:")
        print("  Domain IOCs:", sum(len(v) for v in domains.values()))
        print("  IPv4 IOCs:", sum(len(v) for v in ips.values()))
        print("  IP:Port IOCs:", sum(len(v) for v in ip_ports.values()))
        print("  URL IP:Port IOCs:", sum(len(v) for v in url_ip_ports.values()))
        print("  URL Host indicators (context only):",
              sum(len(v) for v in url_hosts.values()))

    results = []
    seen = set()

    match_dns(dns_records, domains, ips, results, seen)
    match_connections(conn_records, ips, ip_ports, url_ip_ports, results, seen)

    results.sort(key=lambda m: m["event"].get("timestamp_unix") or 0)

    return results


def main():

    parser = argparse.ArgumentParser(description="Match Zeek-derived network data against the IOC database.")
    parser.add_argument("--sample-iocs", action="store_true",
                        help="Match ONLY the lab sample IOCs (data/iocs/sample_iocs.json) "
                             "and write results/sample_validation.json")
    args = parser.parse_args()

    print("Loading IOCs...")

    if args.sample_iocs:
        iocs = load_json(SAMPLE_IOC_FILE)
        out_file = SAMPLE_OUTPUT_FILE
    else:
        iocs = load_iocs()
        out_file = DETECTIONS_FILE

    print("Loading network data...")
    dns_records = load_json(DNS_FILE)
    conn_records = load_json(CONN_FILE)

    print("Matching...")
    results = run_matching(iocs, dns_records, conn_records)

    detections = [to_detection_record(m) for m in results]

    write_json(out_file, detections)

    if not args.sample_iocs:
        # legacy nested output, kept so older scripts keep working
        write_json(OUTPUT_FILE, results)

    print_summary(iocs, dns_records, conn_records, results)

    print("Output:", out_file)


if __name__ == "__main__":
    main()
