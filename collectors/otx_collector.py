
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

OUTPUT_FILE = DATA_DIR / "otx_raw.json"
CHECKPOINT_FILE = DATA_DIR / "otx_checkpoint.json"
METADATA_FILE = DATA_DIR / "otx_collection_metadata.json"

START_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

TIMEOUT = (15, 90)
MAX_RETRIES = 5
MAX_PAGES_PER_RUN = 50


def save_json_atomic(path, data):
    temp_path = path.with_suffix(path.suffix + ".tmp")

    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)

    os.replace(temp_path, path)


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme != "https" or parsed.hostname != "otx.alienvault.com":
        raise ValueError("Unexpected OTX pagination URL")

    return url


def pulse_key(pulse):
    pulse_id = pulse.get("id")

    if pulse_id is not None:
        return str(pulse_id)

    return json.dumps(pulse, sort_keys=True, ensure_ascii=False)


def load_checkpoint():
    if not CHECKPOINT_FILE.exists():
        return {
            "results": [],
            "next": START_URL,
            "pages_collected": 0,
            "api_reported_count": None,
        }

    with open(CHECKPOINT_FILE, "r", encoding="utf-8") as file:
        checkpoint = json.load(file)

    if not isinstance(checkpoint.get("results"), list):
        raise ValueError("Invalid checkpoint: results must be a list")

    next_url = checkpoint.get("next")

    if next_url:
        validate_url(next_url)

    return checkpoint


def fetch_page(session, url, page_number):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=TIMEOUT)
            print(f"Page {page_number}: HTTP {response.status_code}")

            if response.status_code in (429, 500, 502, 503, 504):
                if attempt == MAX_RETRIES:
                    response.raise_for_status()

                retry_after = response.headers.get("Retry-After")

                try:
                    delay = int(retry_after) if retry_after else 2 ** attempt
                except ValueError:
                    delay = 2 ** attempt

                delay = min(delay, 60)
                print(f"Retry {attempt}/{MAX_RETRIES} in {delay}s")
                time.sleep(delay)
                continue

            response.raise_for_status()

            data = response.json()

            if not isinstance(data, dict):
                raise ValueError("OTX returned an invalid JSON structure")

            if not isinstance(data.get("results"), list):
                raise ValueError("OTX response has no valid results list")

            return data

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as error:

            if attempt == MAX_RETRIES:
                raise

            delay = min(2 ** attempt, 60)
            print(
                f"Page {page_number}: connection problem "
                f"({error.__class__.__name__}). Retry in {delay}s"
            )
            time.sleep(delay)

    raise RuntimeError(f"Could not fetch page {page_number}")


def main():
    api_key = os.getenv("OTX_API_KEY")

    if not api_key:
        sys.exit("ERROR: OTX_API_KEY is not set")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    checkpoint = load_checkpoint()
    results = checkpoint["results"]
    current_url = checkpoint.get("next")
    pages_collected = int(checkpoint.get("pages_collected", 0))

    if not current_url:
        print("OTX collection is already complete.")
        return

    seen = {pulse_key(pulse) for pulse in results}

    session = requests.Session()
    session.headers.update({
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "Threat-Intel-Driven-Detection-Platform/1.0",
    })

    pages_this_run = 0

    print(f"Resuming from page {pages_collected + 1}")
    print(f"Previously saved pulses: {len(results)}")

    try:
        while current_url and pages_this_run < MAX_PAGES_PER_RUN:
            validate_url(current_url)

            page_number = pages_collected + 1
            print(f"\nFetching OTX page {page_number}...")

            data = fetch_page(session, current_url, page_number)

            page_results = data["results"]
            added = 0

            for pulse in page_results:
                if not isinstance(pulse, dict):
                    continue

                key = pulse_key(pulse)

                if key not in seen:
                    results.append(pulse)
                    seen.add(key)
                    added += 1

            current_url = data.get("next")

            if current_url:
                validate_url(current_url)

            pages_collected += 1
            pages_this_run += 1

            checkpoint = {
                "results": results,
                "next": current_url,
                "pages_collected": pages_collected,
                "api_reported_count": data.get("count"),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            # Save progress after EVERY successful page.
            save_json_atomic(CHECKPOINT_FILE, checkpoint)

            print(
                f"Page saved. New pulses: {added} | "
                f"Total unique pulses: {len(results)}"
            )

        complete = current_url is None

        metadata = {
            "source": "AlienVault OTX",
            "endpoint": START_URL,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "pages_collected": pages_collected,
            "pulses_collected": len(results),
            "api_reported_count": checkpoint.get("api_reported_count"),
            "collection_complete": complete,
        }

        if complete:
            raw_data = {
                "count": len(results),
                "next": None,
                "previous": None,
                "results": results,
            }

            save_json_atomic(OUTPUT_FILE, raw_data)
            save_json_atomic(METADATA_FILE, metadata)

            print("\nOTX COLLECTION COMPLETED")
            print(f"Pages collected: {pages_collected}")
            print(f"Unique pulses: {len(results)}")
            print(f"Saved to: {OUTPUT_FILE}")

            CHECKPOINT_FILE.unlink(missing_ok=True)

        else:
            save_json_atomic(METADATA_FILE, metadata)

            print("\nBATCH COMPLETED — MORE PAGES REMAIN")
            print(f"Pages collected so far: {pages_collected}")
            print(f"Unique pulses saved in checkpoint: {len(results)}")
            print("Run the same command again to resume.")
            print(f"Checkpoint: {CHECKPOINT_FILE}")

    except (requests.exceptions.RequestException,
            ValueError,
            RuntimeError) as error:

        print(f"\nCollection stopped: {error}")
        print("Progress from completed pages is saved.")
        print("Run the same command again to resume.")
        sys.exit(1)

    finally:
        session.close()


if __name__ == "__main__":
    main()
