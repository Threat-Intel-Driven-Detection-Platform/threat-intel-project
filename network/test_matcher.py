
import ipaddress
from pathlib import Path

from ioc_matcher import (
    load_json,
    build_indexes,
    match_dns,
    match_connections,
    normalize_domain,
    normalize_ip,
)


ROOT = Path(__file__).resolve().parent.parent

DNS_FILE = ROOT / "data" / "network" / "dns_queries.json"
CONN_FILE = ROOT / "data" / "network" / "connections.json"


def create_test_ioc(value, ioc_type, test_id):
    return {
        "id": test_id,
        "ioc": value,
        "ioc_type": ioc_type,
        "source": "CONTROLLED_TEST",
    }


def is_public_unicast_ipv4(value):
    ip = normalize_ip(value)

    if not ip:
        return False

    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.version == 4
            and obj.is_global
            and not obj.is_multicast
            and not obj.is_private
            and not obj.is_loopback
            and not obj.is_link_local
            and not obj.is_reserved
            and not obj.is_unspecified
        )
    except ValueError:
        return False


def run_domain_test(dns_records):
    record = next(
        (
            r for r in dns_records
            if normalize_domain(r.get("domain"))
            and "." in normalize_domain(r.get("domain"))
            and not normalize_domain(r.get("domain")).endswith(
                (".local", ".arpa")
            )
        ),
        None,
    )

    if record is None:
        return False, "No suitable DNS domain found"

    domain = normalize_domain(record["domain"])
    ioc = create_test_ioc(domain, "domain", -1)

    results = []
    match_dns([record], {domain: [ioc]}, {}, results, set())

    passed = (
        len(results) == 1
        and results[0]["match_type"] == "EXACT_DOMAIN"
        and results[0]["matched_value"] == domain
    )

    return passed, domain


def run_dns_answer_ip_test(dns_records):
    selected = None

    for record in dns_records:
        for answer in record.get("answers") or []:
            answer_ip = normalize_ip(answer)
            if answer_ip:
                selected = (record, answer_ip)
                break
        if selected:
            break

    if selected is None:
        return False, "No IPv4 DNS answer found"

    record, answer_ip = selected
    ioc = create_test_ioc(answer_ip, "IPv4", -2)

    results = []
    match_dns([record], {}, {answer_ip: [ioc]}, results, set())

    passed = (
        len(results) == 1
        and results[0]["match_type"] == "EXACT_IP"
        and results[0]["matched_field"] == "answer"
        and results[0]["matched_value"] == answer_ip
    )

    return passed, answer_ip


def find_public_endpoint(conn_records):
    for record in conn_records:
        for ip_field, port_field in (
            ("dst_ip", "dst_port"),
            ("src_ip", "src_port"),
        ):
            ip = normalize_ip(record.get(ip_field))
            port = record.get(port_field)

            if not is_public_unicast_ipv4(ip) or port is None:
                continue

            try:
                port = int(port)
            except (ValueError, TypeError):
                continue

            if 0 <= port <= 65535:
                return record, ip, port, ip_field

    return None


def run_connection_ip_test(endpoint):
    record, ip, port, field = endpoint
    ioc = create_test_ioc(ip, "IPv4", -3)

    results = []
    match_connections(
        [record], {ip: [ioc]}, {}, {}, results, set()
    )

    passed = (
        len(results) == 1
        and results[0]["match_type"] == "EXACT_IP"
        and results[0]["matched_value"] == ip
        and results[0]["matched_field"] == field
    )

    return passed, f"{ip} ({field})"


def run_ip_port_test(endpoint):
    record, ip, port, _ = endpoint
    ioc = create_test_ioc(f"{ip}:{port}", "ip:port", -4)

    results = []
    match_connections(
        [record],
        {},
        {(ip, port): [ioc]},
        {},
        results,
        set(),
    )

    passed = (
        len(results) == 1
        and results[0]["match_type"] == "EXACT_IP_PORT"
        and results[0]["matched_value"] == f"{ip}:{port}"
    )

    return passed, f"{ip}:{port}"


def run_url_ip_port_test(endpoint):
    record, ip, port, _ = endpoint
    url = f"http://{ip}:{port}/controlled-test"
    ioc = create_test_ioc(url, "url", -5)

    domains, ips, ip_ports, url_ip_ports, url_hosts = build_indexes([ioc])

    results = []
    match_connections(
        [record],
        ips,
        ip_ports,
        url_ip_ports,
        results,
        set(),
    )

    passed = (
        len(results) == 1
        and results[0]["match_type"] == "URL_IP_PORT_MATCH"
        and results[0]["matched_value"] == f"{ip}:{port}"
    )

    return passed, url


def run_url_host_overmatching_test():
    url = "https://example-test.invalid/malware.exe"
    ioc = create_test_ioc(url, "url", -6)

    domains, ips, ip_ports, url_ip_ports, url_hosts = build_indexes([ioc])

    dns_record = {
        "domain": "example-test.invalid",
        "answers": [],
        "uid": "controlled-url-host-test",
    }

    results = []
    match_dns([dns_record], domains, ips, results, set())

    passed = (
        len(results) == 0
        and "example-test.invalid" in url_hosts
        and "example-test.invalid" not in domains
    )

    return passed, "DNS hostname alone must not match a full URL IOC"


def run_deduplication_test(dns_records):
    record = next(
        (
            r for r in dns_records
            if normalize_domain(r.get("domain"))
            and "." in normalize_domain(r.get("domain"))
        ),
        None,
    )

    if record is None:
        return False, "No suitable DNS record found"

    domain = normalize_domain(record["domain"])
    ioc = create_test_ioc(domain, "domain", -7)

    results = []
    seen = set()

    # Process the exact same event twice.
    match_dns(
        [record, record],
        {domain: [ioc]},
        {},
        results,
        seen,
    )

    passed = len(results) == 1
    return passed, f"Duplicate event produced {len(results)} match(es)"


def main():
    print("Loading Zeek data...")
    dns_records = load_json(DNS_FILE)
    conn_records = load_json(CONN_FILE)

    print("DNS records:", len(dns_records))
    print("Connection records:", len(conn_records))

    endpoint = find_public_endpoint(conn_records)

    tests = []

    print("\nRunning controlled tests...")

    tests.append(("Exact Domain Matching", run_domain_test(dns_records)))
    tests.append(("DNS Answer IPv4 Matching", run_dns_answer_ip_test(dns_records)))

    if endpoint:
        tests.append(("Connection IPv4 Matching", run_connection_ip_test(endpoint)))
        tests.append(("Exact IP:Port Matching", run_ip_port_test(endpoint)))
        tests.append(("URL IP:Port Matching", run_url_ip_port_test(endpoint)))
    else:
        tests.extend([
            ("Connection IPv4 Matching", (False, "No public IPv4 endpoint found")),
            ("Exact IP:Port Matching", (False, "No public IPv4 endpoint found")),
            ("URL IP:Port Matching", (False, "No public IPv4 endpoint found")),
        ])

    tests.append(("Prevent URL Host Overmatching", run_url_host_overmatching_test()))
    tests.append(("Deduplication", run_deduplication_test(dns_records)))

    print("\n========== CONTROLLED TEST RESULTS ==========")

    passed_count = 0

    for index, (name, result) in enumerate(tests, start=1):
        passed, details = result
        status = "PASS" if passed else "FAIL"

        if passed:
            passed_count += 1

        print(f"\n[{index}] {name}")
        print("Details:", details)
        print("Result:", status)

    print("\n----------------------------------------------")
    print(f"Tests passed: {passed_count}/{len(tests)}")
    print(
        "Overall:",
        "ALL TESTS PASSED" if passed_count == len(tests)
        else "SOME TESTS FAILED",
    )
    print("==============================================")


if __name__ == "__main__":
    main()
