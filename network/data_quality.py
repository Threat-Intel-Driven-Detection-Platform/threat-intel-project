import json
from pathlib import Path
from collections import Counter
import ipaddress

ROOT = Path(__file__).resolve().parent.parent

files = {
    "Connections": ROOT / "data/network/connections.json",
    "DNS": ROOT / "data/network/dns_queries.json"
}

for name, file_path in files.items():

    with open(file_path, encoding="utf-8") as f:
        records = json.load(f)

    print(f"\n===== {name} DATA QUALITY =====")

    print("Total Records:", len(records))

    if name == "Connections":

        protocols = Counter(
            r["protocol"] for r in records if r.get("protocol")
        )

        missing_ips = sum(
            1 for r in records
            if not r.get("src_ip") or not r.get("dst_ip")
        )

        print("Missing IP records:", missing_ips)
        print("Protocols:", protocols)

    else:

        missing_domains = sum(
            1 for r in records if not r.get("domain")
        )

        unique_domains = len({
            r["domain"].lower().rstrip(".")
            for r in records if r.get("domain")
        })

        response_codes = Counter(
            r["response_code"]
            for r in records if r.get("response_code")
        )

        records_with_answers = sum(
            1 for r in records if r.get("answers")
        )

        records_without_answers = sum(
            1 for r in records if not r.get("answers")
        )

        print("Missing Domains:", missing_domains)
        print("Unique Domains:", unique_domains)
        print("Response Codes:", response_codes)

        print("Records with Answers:", records_with_answers)
        print("Records without Answers:", records_without_answers)

        print("\nSample DNS Answers:")

        samples = [
            r for r in records if r.get("answers")
        ]

        for r in samples[:5]:
            print("Domain:", r["domain"])
            print("Answers:", r["answers"])
            print("-" * 40)

            if records_with_answers > 0:
                    # نعرض أول 5 أمثلة فقط
                    records_with_answers -= 1

            if records_with_answers == 0:
                    break
        answer_ips = set()
        answer_domains = set()

        for record in records:
            for answer in record.get("answers", []):

                answer = answer.strip().rstrip(".")

                try:
                    ipaddress.ip_address(answer)
                    answer_ips.add(answer)

                except ValueError:
                    answer_domains.add(answer.lower())

        print("\n===== DNS ANSWERS ANALYSIS =====")
        print("Unique Answer IPs:", len(answer_ips))
        print("Unique Answer Domains:", len(answer_domains))

        print("\nSample Answer IPs:")
        for ip in list(sorted(answer_ips))[:10]:
            print(ip)

        print("\nSample Answer Domains:")
        for domain in sorted(answer_domains)[:10]:
            print(domain)            