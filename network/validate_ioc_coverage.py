
from pathlib import Path

from ioc_matcher import (
    load_iocs,
    load_json,
    build_indexes,
    normalize_domain,
    normalize_ip,
)


ROOT = Path(__file__).resolve().parent.parent

DNS_FILE = ROOT / "data" / "network" / "dns_queries.json"
CONN_FILE = ROOT / "data" / "network" / "connections.json"


def collect_dns_domains(dns_records):
    """Collect normalized domains observed in DNS queries."""
    domains = set()

    for record in dns_records:
        domain = normalize_domain(record.get("domain"))

        if domain:
            domains.add(domain)

    return domains


def collect_dns_answer_ips(dns_records):
    """Collect normalized IP addresses found in DNS answers."""
    ips = set()

    for record in dns_records:
        for answer in record.get("answers") or []:
            ip = normalize_ip(answer)

            if ip:
                ips.add(ip)

    return ips


def collect_connection_endpoints(conn_records):
    """Collect connection IPs and their corresponding IP:Port tuples."""
    connection_ips = set()
    connection_ip_ports = set()

    for record in conn_records:
        for ip_field, port_field in (
            ("src_ip", "src_port"),
            ("dst_ip", "dst_port"),
        ):
            ip = normalize_ip(record.get(ip_field))

            if not ip:
                continue

            connection_ips.add(ip)

            port = record.get(port_field)

            if port is None:
                continue

            try:
                port = int(port)

                if 0 <= port <= 65535:
                    connection_ip_ports.add((ip, port))

            except (ValueError, TypeError):
                continue

    return connection_ips, connection_ip_ports


def print_section(title):
    print(f"\n{'=' * 55}")
    print(title)
    print("=" * 55)


def print_overlap(label, ioc_count, observed_count, hits):
    print(f"\n{label}:")
    print("IOC values:", ioc_count)
    print("Observed values:", observed_count)
    print("Overlaps:", len(hits))
    print("Examples:", sorted(hits)[:20])


def main():

    print("Loading IOC database and Zeek data...")

    iocs = load_iocs()
    dns_records = load_json(DNS_FILE)
    conn_records = load_json(CONN_FILE)

    print("Total IOCs:", len(iocs))
    print("DNS records:", len(dns_records))
    print("Connection records:", len(conn_records))

    print("\nBuilding IOC indexes...")

    (
        domains,
        ips,
        ip_ports,
        url_ip_ports,
        url_hosts,
    ) = build_indexes(iocs)

    print("\nCollecting observed network indicators...")

    dns_domains = collect_dns_domains(dns_records)
    dns_answer_ips = collect_dns_answer_ips(dns_records)

    connection_ips, connection_ip_ports = (
        collect_connection_endpoints(conn_records)
    )

    # --------------------------------------------------
    # 1. Exact Domain / Hostname Matching
    # --------------------------------------------------

    domain_hits = set(domains) & dns_domains

    # --------------------------------------------------
    # 2. URL Host Contextual Analysis
    # --------------------------------------------------

    url_host_hits = set(url_hosts) & dns_domains

    # --------------------------------------------------
    # 3. Standalone IPv4 Matching
    # --------------------------------------------------

    ip_hits_dns = set(ips) & dns_answer_ips
    ip_hits_conn = set(ips) & connection_ips

    # --------------------------------------------------
    # 4. IP:Port Matching
    # --------------------------------------------------

    ip_port_hits = set(ip_ports) & connection_ip_ports

    # --------------------------------------------------
    # 5. URL IP:Port Contextual Matching
    # --------------------------------------------------

    url_ip_port_hits = (
        set(url_ip_ports) & connection_ip_ports
    )

    # --------------------------------------------------
    # REPORT
    # --------------------------------------------------

    print_section("IOC COVERAGE VALIDATION")

    print("\nNetwork Data Statistics:")
    print("Unique observed DNS domains:", len(dns_domains))
    print("Unique DNS answer IPs:", len(dns_answer_ips))
    print("Unique connection IPs:", len(connection_ips))
    print("Unique connection IP:Port pairs:", len(connection_ip_ports))

    print_section("1. DOMAIN / HOSTNAME MATCHING")

    print_overlap(
        "Exact Domain Matching",
        len(domains),
        len(dns_domains),
        domain_hits,
    )

    print_section("2. URL HOST CONTEXTUAL ANALYSIS")

    print_overlap(
        "URL Host vs Observed DNS Domain",
        len(url_hosts),
        len(dns_domains),
        url_host_hits,
    )

    print(
        "\nIMPORTANT: URL Host overlap is contextual evidence only."
    )
    print(
        "It does NOT confirm that the complete URL or URI path was accessed."
    )

    print_section("3. STANDALONE IPv4 MATCHING")

    print_overlap(
        "IPv4 vs DNS Answers",
        len(ips),
        len(dns_answer_ips),
        ip_hits_dns,
    )

    print_overlap(
        "IPv4 vs Connection Endpoints",
        len(ips),
        len(connection_ips),
        ip_hits_conn,
    )

    print_section("4. IP:PORT MATCHING")

    print_overlap(
        "IP:Port vs Connection Endpoints",
        len(ip_ports),
        len(connection_ip_ports),
        ip_port_hits,
    )

    print_section("5. URL IP:PORT CONTEXTUAL MATCHING")

    print_overlap(
        "URL IP:Port vs Connection Endpoints",
        len(url_ip_ports),
        len(connection_ip_ports),
        url_ip_port_hits,
    )

    print(
        "\nIMPORTANT: URL IP:Port overlap confirms only the endpoint."
    )
    print(
        "It does NOT confirm that the URL path or resource was requested."
    )

    # --------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------

    print_section("FINAL COVERAGE SUMMARY")

    print("Exact Domain overlaps:", len(domain_hits))
    print("URL Host contextual overlaps:", len(url_host_hits))
    print("IPv4 DNS overlaps:", len(ip_hits_dns))
    print("IPv4 Connection overlaps:", len(ip_hits_conn))
    print("IP:Port overlaps:", len(ip_port_hits))
    print("URL IP:Port contextual overlaps:", len(url_ip_port_hits))

    total_exact_overlaps = (
        len(domain_hits)
        + len(ip_hits_dns)
        + len(ip_hits_conn)
        + len(ip_port_hits)
        + len(url_ip_port_hits)
    )

    print("\nTotal overlap categories counted:", total_exact_overlaps)

    print("\nNote:")
    print(
        "These are indicator-level overlap counts, not unique event counts."
    )
    print(
        "URL Host and URL IP:Port overlaps are contextual, "
        "not full URL detections."
    )

    print("\nCoverage validation completed.")


if __name__ == "__main__":
    main()
