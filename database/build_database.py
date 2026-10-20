import json
import os
import sqlite3
import sys
import tempfile

import ijson


DB_PATH = os.path.join("data", "database", "threat_intel.db")
DEFAULT_JSON = os.path.join("data", "database", "global_iocs.json")

SOURCE_META = {
    "circl": (
        "CIRCL OSINT",
        "feed",
        "https://www.circl.lu/doc/misp/feed-osint/",
    ),
    "feodo": (
        "Feodo Tracker",
        "feed",
        "https://feodotracker.abuse.ch/",
    ),
    "infoblox": (
        "Infoblox Threat Intelligence",
        "repository",
        "https://github.com/Infoblox-CTO/threat-intelligence",
    ),
    "malwarebazaar": (
        "MalwareBazaar",
        "api",
        "https://bazaar.abuse.ch/",
    ),
    "meta": (
        "Meta Threat Research",
        "repository",
        "https://github.com/facebook/threat-research",
    ),
    "openphish": (
        "OpenPhish",
        "feed",
        "https://openphish.com/",
    ),
    "otx": (
        "AlienVault OTX",
        "api",
        "https://otx.alienvault.com/",
    ),
    "talos": (
        "Cisco Talos",
        "repository",
        "https://github.com/Cisco-Talos/IOCs",
    ),
    "threatfox": (
        "ThreatFox",
        "api",
        "https://threatfox.abuse.ch/",
    ),
    "urlhaus": (
        "URLhaus",
        "api",
        "https://urlhaus.abuse.ch/",
    ),
}


def jdump(x):
    if x is None:
        return None
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"))


def scalar(x):
    if x is None:
        return None
    if isinstance(x, (dict, list)):
        return jdump(x)
    return str(x)


def source_key(name):
    s = (name or "").strip().lower()
    aliases = {
        "circl": "circl",
        "circl osint": "circl",
        "cisco talos": "talos",
        "talos": "talos",
        "alienvault otx": "otx",
        "otx": "otx",
        "urlhaus": "urlhaus",
        "threatfox": "threatfox",
        "feodo tracker": "feodo",
        "feodo": "feodo",
        "malwarebazaar": "malwarebazaar",
        "openphish": "openphish",
        "infoblox": "infoblox",
        "infoblox threat intelligence": "infoblox",
        "meta threat research": "meta",
        "meta": "meta",
    }
    return aliases.get(s, s)


def detect_array_key(path):
    """
    Return "" for a root array, or the first top-level array's key.
    Detection is streamed; nested metadata arrays are ignored.
    """
    with open(path, "rb") as f:
        events = ijson.parse(f, use_float=True)
        first = next(events, None)

        if first is None:
            raise ValueError("The JSON file is empty.")

        _, event, _ = first

        if event == "start_array":
            return ""

        if event != "start_map":
            raise ValueError(
                "Expected a JSON object containing an IOC array, "
                "or a root JSON array."
            )

        depth = 1
        key = None

        for _, event, value in events:
            if event == "map_key" and depth == 1:
                key = value
            elif event in ("start_map", "start_array"):
                if depth == 1 and event == "start_array":
                    return key
                depth += 1
            elif event in ("end_map", "end_array"):
                depth -= 1

    raise RuntimeError(
        "Could not find a top-level IOC array (expected iocs)."
    )


def iter_iocs(path, array_key):
    prefix = "item" if array_key == "" else f"{array_key}.item"

    with open(path, "rb") as f:
        # Native floats keep raw_metadata compatible with json.dumps.
        yield from ijson.items(f, prefix, use_float=True)


def insert_source(cur, key):
    key = source_key(key)
    meta = SOURCE_META.get(key)

    if meta:
        name, typ, url = meta
    else:
        name = key or "unknown"
        typ = "unknown"
        url = None

    cur.execute(
        """
        INSERT OR IGNORE INTO sources(name,source_type,url,description)
        VALUES(?,?,?,?)
        """,
        (name, typ, url, "Imported source"),
    )
    cur.execute("SELECT source_id FROM sources WHERE name=?", (name,))
    return cur.fetchone()[0]


def ensure_tag(cur, name):
    cur.execute(
        "INSERT OR IGNORE INTO tags(name) VALUES(?)",
        (str(name),),
    )
    cur.execute("SELECT tag_id FROM tags WHERE name=?", (str(name),))
    return cur.fetchone()[0]


def ensure_malware(cur, name):
    cur.execute(
        "INSERT OR IGNORE INTO malware(name) VALUES(?)",
        (str(name),),
    )
    cur.execute(
        "SELECT malware_id FROM malware WHERE name=?",
        (str(name),),
    )
    return cur.fetchone()[0]


def check_destination(db_path):
    # Never replace a database with outstanding journal/WAL files.
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = db_path + suffix
        if os.path.exists(sidecar):
            raise RuntimeError(
                f"SQLite sidecar exists: {sidecar}. "
                "Close programs using the database. Open and close it "
                "normally with SQLite to finish recovery/checkpointing, "
                "then retry. Do not manually delete sidecar files."
            )


def build(json_path=DEFAULT_JSON):
    json_path = os.path.abspath(json_path)
    db_path = os.path.abspath(DB_PATH)
    schema_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "schema.sql",
    )

    if not os.path.isfile(json_path):
        raise FileNotFoundError(json_path)

    if not os.path.isfile(schema_path):
        raise FileNotFoundError(schema_path)

    if os.path.normcase(json_path) == os.path.normcase(db_path):
        raise ValueError("Input JSON path must differ from the database path.")

    array_key = detect_array_key(json_path)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    check_destination(db_path)

    # Same directory ensures the replacement stays on the same filesystem.
    fd, temp_path = tempfile.mkstemp(
        prefix="threat_intel_build_",
        suffix=".db",
        dir=os.path.dirname(db_path),
    )
    os.close(fd)

    conn = None
    total = 0
    obs_count = 0
    skipped_count = 0

    try:
        conn = sqlite3.connect(temp_path)
        cur = conn.cursor()

        with open(schema_path, encoding="utf-8") as f:
            conn.executescript(f.read())

        conn.execute("PRAGMA foreign_keys=ON")

        # Keep the temporary database self-contained for os.replace.
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")

        source_cache = {}
        print("Streaming IOC records...", flush=True)

        for n, obj in enumerate(iter_iocs(json_path, array_key), 1):
            total = n

            if not isinstance(obj, dict):
                raise ValueError(f"IOC record #{n} must be a JSON object.")

            value = obj.get("value")
            typ = obj.get("canonical_type") or obj.get("type")

            if not value or not typ:
                skipped_count += 1
                continue

            cur.execute(
                "INSERT OR IGNORE INTO iocs(value,canonical_type) VALUES(?,?)",
                (str(value), str(typ)),
            )
            cur.execute(
                "SELECT ioc_id FROM iocs WHERE value=? AND canonical_type=?",
                (str(value), str(typ)),
            )
            ioc_id = cur.fetchone()[0]

            srcs = obj.get("sources") or []
            records = obj.get("records") or []

            for rec in records:
                sk = source_key(
                    rec.get("source")
                    or (srcs[0] if len(srcs) == 1 else "unknown")
                )

                if sk not in source_cache:
                    source_cache[sk] = insert_source(cur, sk)

                sid = source_cache[sk]
                fs = rec.get("first_seen")
                ls = rec.get("last_seen")

                cur.execute(
                    """
                    INSERT INTO observations(
                        ioc_id,source_id,source_record_id,
                        event_id,event_uuid,event_info,
                        first_seen,last_seen,timestamp,to_ids,
                        category,comment,threat_type,malware,
                        confidence,reporter,status,reference,tlp,
                        raw_metadata
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ioc_id,
                        sid,
                        rec.get("source_record_id"),
                        rec.get("event_id"),
                        rec.get("event_uuid"),
                        rec.get("event_info"),
                        fs,
                        ls,
                        scalar(rec.get("timestamp")),
                        (
                            int(rec["to_ids"])
                            if isinstance(rec.get("to_ids"), bool)
                            else None
                        ),
                        rec.get("category"),
                        rec.get("comment"),
                        rec.get("threat_type"),
                        scalar(rec.get("malware")),
                        scalar(rec.get("confidence")),
                        rec.get("reporter"),
                        rec.get("status"),
                        scalar(rec.get("reference")),
                        rec.get("tlp"),
                        jdump(rec),
                    ),
                )

                oid = cur.lastrowid
                obs_count += 1

                for tag in rec.get("tags") or []:
                    tid = ensure_tag(cur, tag)
                    cur.execute(
                        "INSERT OR IGNORE INTO observation_tags VALUES(?,?,?)",
                        (oid, tid, "record"),
                    )

                for tag in rec.get("event_tags") or []:
                    tid = ensure_tag(cur, tag)
                    cur.execute(
                        "INSERT OR IGNORE INTO observation_tags VALUES(?,?,?)",
                        (oid, tid, "event"),
                    )

                mal = rec.get("malware")
                if isinstance(mal, str) and mal.strip():
                    mid = ensure_malware(cur, mal.strip())
                    cur.execute(
                        "INSERT OR IGNORE INTO observation_malware VALUES(?,?)",
                        (oid, mid),
                    )

                techniques = (
                    rec.get("mitre_techniques")
                    or rec.get("attack_ids")
                    or []
                )
                for tech in techniques:
                    if isinstance(tech, dict):
                        tid = tech.get("id") or tech.get("technique_id")
                        name = tech.get("name")
                    else:
                        tid = str(tech)
                        name = None

                    if tid:
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO mitre_techniques(
                                technique_id,name
                            ) VALUES(?,?)
                            """,
                            (tid, name),
                        )
                        cur.execute(
                            "INSERT OR IGNORE INTO observation_mitre VALUES(?,?)",
                            (oid, tid),
                        )

                refs = rec.get("references") or []
                if isinstance(refs, str):
                    refs = [refs]

                for ref in refs:
                    if isinstance(ref, dict):
                        ref = ref.get("url") or ref.get("reference")

                    if ref:
                        cur.execute(
                            "INSERT OR IGNORE INTO ioc_references(url) VALUES(?)",
                            (str(ref),),
                        )
                        cur.execute(
                            "SELECT reference_id FROM ioc_references WHERE url=?",
                            (str(ref),),
                        )
                        rid = cur.fetchone()[0]
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO observation_references
                            VALUES(?,?)
                            """,
                            (oid, rid),
                        )

                if obs_count % 5000 == 0:
                    conn.commit()
                    print(
                        f"Processed {n:,} IOCs | "
                        f"observations {obs_count:,}",
                        flush=True,
                    )

            # Preserve sources declared on the IOC even without records.
            for s in srcs:
                sk = source_key(s)

                if sk not in source_cache:
                    source_cache[sk] = insert_source(cur, sk)

                sid = source_cache[sk]
                cur.execute(
                    """
                    INSERT OR IGNORE INTO ioc_sources(ioc_id,source_id)
                    VALUES(?,?)
                    """,
                    (ioc_id, sid),
                )

            if n % 5000 == 0:
                conn.commit()

        cur.execute(
            """
            INSERT OR REPLACE INTO ioc_sources(
                ioc_id,source_id,first_seen,last_seen,record_count
            )
            SELECT
                ioc_id,source_id,MIN(first_seen),MAX(last_seen),COUNT(*)
            FROM observations
            GROUP BY ioc_id,source_id
            """
        )
        conn.commit()

        print("Finalizing and checking database...", flush=True)
        conn.execute("VACUUM")

        for row in conn.execute("PRAGMA integrity_check"):
            if row[0] != "ok":
                raise RuntimeError(f"SQLite integrity check failed: {row[0]}")

        violation = conn.execute("PRAGMA foreign_key_check").fetchone()
        if violation is not None:
            raise RuntimeError(
                f"SQLite foreign key check failed: {violation}"
            )

        unique_count = cur.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

        conn.close()
        conn = None

        # Recheck immediately before publishing the completed database.
        check_destination(db_path)

        # No deletion of the existing DB: replacement happens only on success.
        os.replace(temp_path, db_path)

    finally:
        try:
            if conn is not None:
                conn.close()
        finally:
            # Only clean this build's temporary files.
            for suffix in ("", "-journal", "-wal", "-shm"):
                candidate = temp_path + suffix
                try:
                    os.remove(candidate)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    print(
                        f"Warning: could not remove temporary file "
                        f"{candidate}: {exc}",
                        file=sys.stderr,
                    )

    print(f"Created: {DB_PATH}")
    print(
        f"IOC records read: {total:,} | "
        f"Unique IOCs: {unique_count:,} | "
        f"observations: {obs_count:,} | "
        f"Skipped: {skipped_count:,}"
    )


if __name__ == "__main__":
    try:
        build(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON)
    except KeyboardInterrupt:
        print(
            "\nBuild cancelled. The existing database was not replaced.",
            file=sys.stderr,
        )
        sys.exit(130)
    except Exception as exc:
        print(
            f"\nBuild failed: {exc}\n"
            "The existing database was not replaced.",
            file=sys.stderr,
        )
        sys.exit(1)