import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("data/threat_intel.db")
OUTPUT_PATH = Path("docs/week4_ioc_distribution_report.md")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

total_original = cur.execute(
    "SELECT COUNT(*) FROM iocs"
).fetchone()[0]

total_derived = cur.execute(
    "SELECT COUNT(*) FROM derived_observables"
).fetchone()[0]

source_rows = cur.execute("""
SELECT source, COUNT(*)
FROM iocs
GROUP BY source
ORDER BY COUNT(*) DESC
""").fetchall()

type_rows = cur.execute("""
SELECT ioc_type, COUNT(*)
FROM iocs
GROUP BY ioc_type
ORDER BY COUNT(*) DESC
""").fetchall()

derived_type_rows = cur.execute("""
SELECT observable_type, COUNT(*)
FROM derived_observables
GROUP BY observable_type
ORDER BY COUNT(*) DESC
""").fetchall()

derived_source_rows = cur.execute("""
SELECT i.source, d.observable_type, COUNT(*)
FROM derived_observables d
JOIN iocs i ON i.original_ioc_ref = d.original_ioc_ref
GROUP BY i.source, d.observable_type
ORDER BY i.source, d.observable_type
""").fetchall()

quality_checks = {
    "Missing IOC": "ioc IS NULL OR TRIM(ioc) = ''",
    "Missing IOC Type": "ioc_type IS NULL OR TRIM(ioc_type) = ''",
    "Missing Source": "source IS NULL OR TRIM(source) = ''",
    "Missing Threat Type": "threat_type IS NULL OR TRIM(threat_type) = ''",
    "Missing First Seen": "first_seen IS NULL OR TRIM(first_seen) = ''",
    "Missing Confidence": "confidence IS NULL",
    "Invalid Confidence": "confidence < 0 OR confidence > 100",
}

quality_results = {}
for label, condition in quality_checks.items():
    quality_results[label] = cur.execute(
        f"SELECT COUNT(*) FROM iocs WHERE {condition}"
    ).fetchone()[0]

duplicate_groups = cur.execute("""
SELECT COUNT(*) FROM (
    SELECT ioc, LOWER(ioc_type), source
    FROM iocs
    GROUP BY ioc, LOWER(ioc_type), source
    HAVING COUNT(*) > 1
)
""").fetchone()[0]

derived_quality = {
    "Missing Observable": """
        observable IS NULL OR TRIM(observable) = ''
    """,
    "Missing Observable Type": """
        observable_type IS NULL OR TRIM(observable_type) = ''
    """,
    "Missing Original Reference": """
        original_ioc_ref IS NULL OR TRIM(original_ioc_ref) = ''
    """,
}

derived_results = {}
for label, condition in derived_quality.items():
    derived_results[label] = cur.execute(
        f"SELECT COUNT(*) FROM derived_observables WHERE {condition}"
    ).fetchone()[0]

confidence_rows = cur.execute("""
SELECT source,
       COUNT(*) AS total,
       SUM(CASE WHEN confidence IS NULL THEN 1 ELSE 0 END) AS missing,
       SUM(CASE WHEN confidence IS NOT NULL THEN 1 ELSE 0 END) AS available
FROM iocs
GROUP BY source
ORDER BY total DESC
""").fetchall()

conn.close()

lines = [
    "# Week 4 - IOC Distribution & Data Quality Report",
    "",
    f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    "",
    "## 1. Executive Summary",
    "",
    f"- Original IOCs: **{total_original:,}**",
    f"- Derived observables: **{total_derived:,}**",
    f"- Duplicate original IOC groups: **{duplicate_groups:,}**",
    "- Derived observables are extracted from existing URL IOCs. "
    "They are not additional original feed IOCs.",
    "",
    "## 2. Original IOCs by Source",
    "",
    "| Source | IOC Count |",
    "|---|---:|",
]

for source, count in source_rows:
    lines.append(f"| {source} | {count:,} |")

lines += [
    "",
    "## 3. Original IOCs by Type",
    "",
    "| IOC Type | Count |",
    "|---|---:|",
]

for ioc_type, count in type_rows:
    lines.append(f"| {ioc_type} | {count:,} |")

url_count = sum(
    count for ioc_type, count in type_rows
    if ioc_type.lower() == "url"
)
url_percentage = (url_count / total_original * 100) if total_original else 0

lines += [
    "",
    f"URL and URL-case variants account for **{url_count:,} "
    f"({url_percentage:.2f}%)** of original IOCs.",
    "",
    "### URL Dominance Explanation",
    "",
    "The feed is strongly URL-dominated, mainly because URLhaus contributes "
    "a large volume of URL indicators. This affects network detection coverage: "
    "connection and DNS matching generally use IPs and domains, while full URL "
    "and URI matching requires suitable HTTP-level evidence such as Zeek http.log. "
    "Derived IP and domain observables improve the availability of host indicators, "
    "but do not guarantee matches without suitable network traffic.",
    "",
    "## 4. Derived Observables",
    "",
    "| Observable Type | Count |",
    "|---|---:|",
]

for observable_type, count in derived_type_rows:
    lines.append(f"| {observable_type} | {count:,} |")

lines += [
    "",
    "### Derived Observables by Source",
    "",
    "| Source | Type | Count |",
    "|---|---|---:|",
]

for source, observable_type, count in derived_source_rows:
    lines.append(f"| {source} | {observable_type} | {count:,} |")

lines += [
    "",
    "Derived IPs, domains, and explicit ports retain a reference to their "
    "original URL IOC. Ports are contextual metadata and must not be matched "
    "as standalone indicators.",
    "",
    "## 5. Original IOC Data Quality",
    "",
    "| Check | Result |",
    "|---|---:|",
]

for label, count in quality_results.items():
    lines.append(f"| {label} | {count:,} |")

lines += [
    f"| Duplicate original IOC groups (case-insensitive type) | {duplicate_groups:,} |",
    "",
    "### Confidence Availability by Source",
    "",
    "| Source | Total | Missing | Available | Missing % |",
    "|---|---:|---:|---:|---:|",
]

for source, total, missing, available in confidence_rows:
    percentage = (missing / total * 100) if total else 0
    lines.append(
        f"| {source} | {total:,} | {missing:,} | "
        f"{available:,} | {percentage:.2f}% |"
    )

lines += [
    "",
    "Missing confidence values are source-related: URLhaus and OTX records "
    "in this dataset do not provide confidence values, while ThreatFox records "
    "do. Missing values are retained as NULL; no default confidence is invented.",
    "",
    "## 6. Derived Data Quality",
    "",
    "| Check | Result |",
    "|---|---:|",
]

for label, count in derived_results.items():
    lines.append(f"| {label} | {count:,} |")

lines += [
    "",
    "## 7. Interpretation and Limitations",
    "",
    "- Original IOC counts and derived observable counts are reported separately.",
    "- Derived observables originate from existing URLs and preserve provenance.",
    "- Extracted IP addresses are URL host values, not DNS-resolved addresses.",
    "- An extracted IP or domain does not imply that it appears in the analyzed PCAP.",
    "- Detection coverage also depends on the available Zeek logs and matcher support.",
    "- Missing confidence is not treated as zero confidence.",
    "",
    "## 8. Reproduction",
    "",
    "Run the following command from the project root:",
    "",
    "```powershell",
    "python normalization/ioc_quality_report.py",
    "```",
    "",
]

OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")
print(f"Report generated: {OUTPUT_PATH}")
print(f"Original IOCs: {total_original:,}")
print(f"Derived observables: {total_derived:,}")
