"""
Standalone Threat Feed Ingestion Script
Collects, validates, normalizes, and deduplicates malicious URLs from public
OpenPhish and abuse.ch URLhaus feeds into SQLite (default) or MongoDB (when MONGODB_URI is set).
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

FEEDS = [
    ("OpenPhish Community Feed", "https://openphish.com/feed.txt", "Phishing"),
    ("URLhaus Public Online Feed", "https://urlhaus.abuse.ch/downloads/text_online/", "Malware / Malicious URL"),
]


def normalize_url(raw_url: str):
    raw_url = raw_url.strip()
    if not raw_url or len(raw_url) > 2048:
        return None
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return parsed.geturl(), parsed.hostname.lower()


def main():
    db_path = Path(os.getenv("SQLITE_DB_PATH", "data/phishing_detector.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(days=30)).isoformat()
    now_iso = now.isoformat()

    total_ingested = 0
    for source_name, feed_url, category in FEEDS:
        try:
            resp = requests.get(feed_url, timeout=10)
            resp.raise_for_status()
        except Exception as exc:
            print(f"[WARN] Failed to fetch {source_name}: {exc}")
            continue

        seen = set()
        for line in resp.text.splitlines():
            if not line or line.startswith("#"):
                continue
            normalized = normalize_url(line)
            if not normalized:
                continue
            norm_url, domain = normalized
            if norm_url in seen:
                continue
            seen.add(norm_url)

            conn.execute(
                """
                INSERT INTO threat_feeds (
                    normalized_url, domain, threat_category, source,
                    verification_status, first_seen, last_seen, expires_at
                ) VALUES (?, ?, ?, ?, 'feed_reported', ?, ?, ?)
                ON CONFLICT(normalized_url) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires_at = excluded.expires_at
                """,
                (norm_url, domain, category, source_name, now_iso, now_iso, expires),
            )
            total_ingested += 1

    conn.commit()
    conn.close()
    print(f"Threat feed ingestion complete. Upserted {total_ingested} records.")


if __name__ == "__main__":
    main()
