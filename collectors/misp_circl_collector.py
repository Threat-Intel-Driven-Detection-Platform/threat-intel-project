import json
import os
import requests
from urllib.parse import urljoin


BASE_URL = "https://www.circl.lu/doc/misp/feed-osint/"
OUTPUT_DIR = "data/raw/misp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "circl_osint_raw.json")


def get_json_files():
    print("Fetching CIRCL MISP feed index...")

    response = requests.get(BASE_URL, timeout=30)
    response.raise_for_status()

    html = response.text

    files = []

    for line in html.splitlines():
        if '.json"' in line:
            start = line.find('href="')
            if start == -1:
                continue

            start += len('href="')
            end = line.find('"', start)

            if end == -1:
                continue

            filename = line[start:end]

            if filename.endswith(".json"):
                files.append(filename)

    return sorted(set(files))


def download_events(files):
    events = []
    failed = 0

    print(f"JSON files discovered: {len(files)}")

    for index, filename in enumerate(files, start=1):
        url = urljoin(BASE_URL, filename)

        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            data = response.json()

            events.append({
                "filename": filename,
                "data": data
            })

            if index % 25 == 0 or index == len(files):
                print(f"Downloaded: {index}/{len(files)}")

        except Exception as e:
            failed += 1
            print(f"Failed: {filename} -> {e}")

    return events, failed


def main():
    print("=" * 40)
    print("CIRCL MISP OSINT Collection")
    print("=" * 40)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    files = get_json_files()

    print(f"Files found: {len(files)}")

    events, failed = download_events(files)

    output = {
        "source": "CIRCL",
        "feed_name": "CIRCL OSINT Feed",
        "feed_url": BASE_URL,
        "collected_files": len(events),
        "failed_files": failed,
        "events": events
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 40)
    print("Collection Complete")
    print("=" * 40)
    print(f"Files downloaded: {len(events)}")
    print(f"Files failed: {failed}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()