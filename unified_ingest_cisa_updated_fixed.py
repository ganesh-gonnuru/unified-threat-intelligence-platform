#!/usr/bin/env python3
"""Memory-conscious MISP + CISA KEV ingestion for the Unified TIP dashboard.

Reads existing attributes from MISP; it does not enable/fetch configured MISP feeds.
Requires: requests, python-dotenv. Uses SQLite on disk for deduplication.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

MISP_URL = os.getenv("MISP_URL", "https://misp.local").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "").strip()
VERIFY_TLS = os.getenv("MISP_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}
PAGE_SIZE = max(1, int(os.getenv("TIP_MISP_PAGE_SIZE", "250")))
MAX_PAGES = max(1, int(os.getenv("TIP_MISP_MAX_PAGES", "2000")))
REQUEST_TIMEOUT = max(5, int(os.getenv("TIP_REQUEST_TIMEOUT", "45")))
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DB_PATH = BASE / ".unified_ingest_working.sqlite3"
LOG_PATH = BASE / "unified_ingest.log"

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("unified_ingest")

SESSION = requests.Session()
SESSION.headers.update({"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"})


def atomic_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def write_csv(path: Path, rows, fields: list[str]) -> int:
    tmp = path.with_suffix(path.suffix + ".tmp")
    count = 0
    with tmp.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})
            count += 1
    tmp.replace(path)
    return count


def first_list(payload: Any, keys: tuple[str, ...]) -> list[dict]:
    """Find a list of records in common MISP response wrappers."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []

    # Prefer named containers, recursively handling wrappers such as
    # {"response": {"Feed": [...]}} or {"feeds": {"Feed": [...]}}.
    for key in keys:
        if key in payload:
            found = first_list(payload[key], keys)
            if found:
                return found

    # MISP can wrap each record in a singular model key, e.g. {"Feed": {...}}.
    for key in ("Feed", "Attribute", "feed", "attribute"):
        value = payload.get(key)
        if isinstance(value, dict):
            nested = first_list(value, keys)
            if nested:
                return nested
            if value.get("id") is not None or value.get("value") is not None:
                return [value]

    # Some endpoints return one record directly.
    if payload.get("id") is not None or payload.get("value") is not None:
        return [payload]
    return []


def fetch_feed_inventory() -> tuple[list[dict], str | None]:
    """Retrieve configured feed metadata, tolerating MISP response wrappers."""
    errors = []
    for url in (f"{MISP_URL}/feeds/index", f"{MISP_URL}/feeds/index.json"):
        try:
            response = SESSION.get(url, timeout=REQUEST_TIMEOUT, verify=VERIFY_TLS)
            response.raise_for_status()
            payload = response.json()
            feeds = first_list(payload, ("Feed", "feeds", "data", "response"))
            unique = {}
            for raw_feed in feeds:
                # MISP versions may wrap individual feed rows as {"Feed": {...}}.
                feed = raw_feed.get("Feed") if isinstance(raw_feed.get("Feed"), dict) else raw_feed
                feed_id = str(feed.get("id", ""))
                name = str(feed.get("name", ""))
                key = feed_id or name
                if not key:
                    continue
                unique[key] = {
                    "feed_id": feed_id,
                    "name": name,
                    "provider_url": str(feed.get("url", "")),
                    "enabled": feed.get("enabled", ""),
                    "caching_enabled": feed.get("caching_enabled", ""),
                    "source_format": str(feed.get("source_format", "")),
                    "provider": str(feed.get("provider", "")),
                    "lookup_visible": "configured; imported indicators checked separately",
                }
            if unique:
                log.info("MISP feed inventory retrieved: %s feeds", len(unique))
                return list(unique.values()), None
            errors.append(f"{url}: response contained no recognizable feed records")
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    return [], " | ".join(errors)


def unwrap_attribute(item: dict) -> dict:
    # MISP may return attributes directly or wrapped as {Attribute: {...}}.
    current = item
    for _ in range(3):
        value = current.get("Attribute") if isinstance(current, dict) else None
        if not isinstance(value, dict):
            break
        current = value
    return current


def fetch_attributes(db: sqlite3.Connection) -> tuple[int, int, bool, str | None]:
    """Page MISP attributes and insert them directly into SQLite; no giant Python list."""
    endpoint = f"{MISP_URL}/attributes/restSearch"
    total = pages = 0
    limit_reached = False
    previous_signature = None
    errors = []
    for page in range(1, MAX_PAGES + 1):
        body = {"returnFormat": "json", "limit": PAGE_SIZE, "page": page}
        try:
            response = SESSION.post(endpoint, json=body, timeout=REQUEST_TIMEOUT, verify=VERIFY_TLS)
            response.raise_for_status()
            payload = response.json()
            attrs = [unwrap_attribute(x) for x in first_list(payload, ("Attribute", "attributes", "data", "response"))]
            attrs = [a for a in attrs if isinstance(a, dict) and a.get("value") is not None]
            if not attrs:
                break
            signature = tuple(str(a.get("id") or f"{a.get('event_id','')}|{a.get('type','')}|{a.get('value','')}") for a in attrs[:10])
            if signature == previous_signature:
                log.warning("MISP repeated the same page signature at page %s; stopping to prevent duplicate loop", page)
                break
            previous_signature = signature
            for a in attrs:
                aid = str(a.get("id") or "")
                fallback = f"{a.get('event_id','')}|{a.get('type','')}|{a.get('value','')}"
                db.execute("INSERT OR IGNORE INTO raw_attributes(attr_key, payload) VALUES (?, ?)",
                           (aid or fallback, json.dumps(a, ensure_ascii=False)))
            db.commit()
            total += len(attrs)
            pages = page
            if page % 20 == 0:
                log.info("MISP retrieval progress: page=%s records_seen=%s", page, total)
            if len(attrs) < PAGE_SIZE:
                break
            if page == MAX_PAGES:
                limit_reached = True
        except Exception as exc:
            errors.append(f"page {page}: {type(exc).__name__}: {exc}")
            log.error("MISP attribute retrieval failed on page %s: %s", page, exc)
            break
    return total, pages, limit_reached, "; ".join(errors) if errors else None


def fetch_cisa_kev() -> tuple[dict, list[dict], str | None]:
    try:
        response = requests.get(CISA_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        vulns = payload.get("vulnerabilities", [])
        rows = []
        for v in vulns:
            rows.append({
                "cve_id": v.get("cveID", ""),
                "vendor_project": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "short_description": v.get("shortDescription", ""),
                "required_action": v.get("requiredAction", ""),
                "due_date": v.get("dueDate", ""),
                "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", ""),
                "cwes": "; ".join(v.get("cwes", []) or []),
                "notes": v.get("notes", ""),
                "source": "CISA KEV",
            })
        return payload, rows, None
    except Exception as exc:
        return {}, [], f"{type(exc).__name__}: {exc}"


def classify(value: str, attr_type: str) -> tuple[str, str]:
    value = value.strip()
    t = attr_type.lower().strip()
    if not value:
        return "empty", ""
    if t in {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "ip"}:
        candidate = value.split("|")[0].strip()
        try:
            return "ip", str(ipaddress.ip_address(candidate))
        except ValueError:
            try:
                return "ip_network", str(ipaddress.ip_network(candidate, strict=False))
            except ValueError:
                return "invalid_ip", value
    if "domain" in t or t in {"hostname", "hostname|port"}:
        return "domain", value.rstrip(".").lower()
    if "hash" in t or t in {"md5", "sha1", "sha256", "sha512", "ssdeep"}:
        return "hash", value.lower()
    if "url" in t or t in {"link", "uri"}:
        return "url", value
    return t or "other", value


def event_info(attr: dict) -> tuple[str, str]:
    event_id = str(attr.get("event_id", ""))
    event_name = ""
    event = attr.get("Event") or attr.get("event")
    if isinstance(event, dict):
        event_id = event_id or str(event.get("id", ""))
        event_name = str(event.get("info", event.get("name", "")))
    return event_id, event_name


def build_unified(db: sqlite3.Connection) -> tuple[int, Counter, Counter]:
    db.execute("DROP TABLE IF EXISTS unified")
    db.execute("""CREATE TABLE unified (
        kind TEXT NOT NULL, normalized TEXT NOT NULL, indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL, sources TEXT NOT NULL, event_ids TEXT NOT NULL,
        event_names TEXT NOT NULL, first_seen TEXT NOT NULL,
        PRIMARY KEY(kind, normalized)
    )""")
    source_counts, type_counts = Counter(), Counter()
    cur = db.execute("SELECT payload FROM raw_attributes")
    processed = 0
    for (raw,) in cur:
        try:
            attr = json.loads(raw)
        except json.JSONDecodeError:
            continue
        value = str(attr.get("value", "")).strip()
        if not value:
            continue
        attr_type = str(attr.get("type", "unknown"))
        kind, normalized = classify(value, attr_type)
        if kind == "invalid_ip" or not normalized:
            continue
        event_id, event_name = event_info(attr)
        src = "MISP"
        row = db.execute("SELECT indicator, indicator_type, sources, event_ids, event_names, first_seen FROM unified WHERE kind=? AND normalized=?", (kind, normalized)).fetchone()
        if row is None:
            db.execute("INSERT INTO unified VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (kind, normalized, value, attr_type, src, event_id, event_name, str(attr.get("timestamp", ""))))
        else:
            old_sources, old_ids, old_names = row[2], set(filter(None, row[3].split("; "))), set(filter(None, row[4].split("; ")))
            if event_id: old_ids.add(event_id)
            if event_name: old_names.add(event_name)
            sources = set(filter(None, old_sources.split("; "))); sources.add(src)
            db.execute("UPDATE unified SET sources=?, event_ids=?, event_names=? WHERE kind=? AND normalized=?",
                       ("; ".join(sorted(sources)), "; ".join(sorted(old_ids)), "; ".join(sorted(old_names)), kind, normalized))
        source_counts[src] += 1
        type_counts[attr_type] += 1
        processed += 1
        if processed % 25000 == 0:
            db.commit()
            log.info("Normalization progress: %s attributes processed", processed)
    db.commit()
    return processed, source_counts, type_counts


def main() -> int:
    started = datetime.now(timezone.utc).isoformat()
    log.info("Unified ingestion started")
    if not MISP_API_KEY:
        log.error("MISP_API_KEY is missing. Set it in %s/.env", BASE)
        print("ERROR: MISP_API_KEY is missing from .env; no ingestion was performed.")
        return 2
    if not VERIFY_TLS:
        log.warning("TLS certificate verification is disabled; use only for a trusted lab instance")

    if DB_PATH.exists():
        DB_PATH.unlink()
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA temp_store=FILE")
    db.execute("CREATE TABLE raw_attributes(attr_key TEXT PRIMARY KEY, payload TEXT NOT NULL)")

    feeds, feed_error = fetch_feed_inventory()
    write_csv(BASE / "feed_inventory.csv", feeds, ["feed_id", "name", "provider_url", "enabled", "caching_enabled", "source_format", "provider", "lookup_visible"])
    if feed_error:
        log.error("Feed inventory error: %s", feed_error)
        print("WARNING: Could not retrieve MISP feed inventory:", feed_error)

    cisa_payload, cisa_rows, cisa_error = fetch_cisa_kev()
    if not cisa_error:
        atomic_json(BASE / "cisa_kev.json", cisa_payload)
        write_csv(BASE / "cisa_kev.csv", cisa_rows, ["cve_id", "vendor_project", "product", "vulnerability_name", "date_added", "short_description", "required_action", "due_date", "known_ransomware_campaign_use", "cwes", "notes", "source"])
        log.info("CISA KEV retrieved: %s vulnerabilities", len(cisa_rows))
        print(f"CISA KEV vulnerabilities retrieved: {len(cisa_rows)}")
    else:
        log.error("CISA KEV retrieval error: %s", cisa_error)

    records_seen, pages, limit_reached, attr_error = fetch_attributes(db)
    unique_attributes, source_counts, type_counts = build_unified(db)
    out_csv = BASE / "unified_indicators.csv"
    tmp_csv = out_csv.with_suffix(out_csv.suffix + ".tmp")
    fields = ["indicator", "normalized_indicator", "indicator_kind", "type", "source", "misp_event_ids", "misp_event_names", "event_count", "multiple_events", "timestamp"]
    output_count = 0
    with tmp_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for kind, normalized, indicator, attr_type, sources, event_ids, event_names, first_seen in db.execute("SELECT kind, normalized, indicator, indicator_type, sources, event_ids, event_names, first_seen FROM unified ORDER BY kind, normalized"):
            ids = [x for x in event_ids.split("; ") if x]
            writer.writerow({"indicator": indicator, "normalized_indicator": normalized, "indicator_kind": kind, "type": attr_type, "source": sources, "misp_event_ids": event_ids, "misp_event_names": event_names, "event_count": len(ids), "multiple_events": "Yes" if len(ids) > 1 else "No", "timestamp": first_seen})
            output_count += 1
    tmp_csv.replace(out_csv)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": started,
        "configured_misp_feeds": len(feeds),
        "feed_inventory_error": feed_error,
        "cisa_kev_records_retrieved": len(cisa_rows),
        "cisa_kev_error": cisa_error,
        "misp_attributes_seen_from_api": records_seen,
        "misp_attributes_unique_by_id_or_fallback": db.execute("SELECT COUNT(*) FROM raw_attributes").fetchone()[0],
        "misp_bulk_pages_fetched": pages,
        "misp_retrieval_limit_reached": limit_reached,
        "misp_bulk_retrieval_complete": (not limit_reached and not attr_error),
        "misp_retrieval_error": attr_error,
        "normalized_attributes_processed": unique_attributes,
        "unique_indicators_written": output_count,
        "attribute_type_counts": dict(type_counts),
        "notes": ["Configured feed count does not mean feeds were fetched/imported.", "CISA KEV CVEs are kept in a separate dataset from MISP indicators.", "MISP retrieval is incomplete if the page limit was reached or an API error occurred."],
    }
    atomic_json(BASE / "unified_tip_report.json", report)
    db.close()
    log.info("Unified ingestion completed: feeds=%s api_records_seen=%s unique_indicators=%s pages=%s limit_reached=%s", len(feeds), records_seen, output_count, pages, limit_reached)
    print("\nUnified ingestion finished.")
    print(f"MISP feeds configured: {len(feeds)}")
    print(f"MISP attributes seen: {records_seen}")
    print(f"Unique indicators written: {output_count}")
    print(f"CISA KEV records: {len(cisa_rows)}")
    print(f"MISP page limit reached: {limit_reached}")
    print("Outputs: feed_inventory.csv, unified_indicators.csv, unified_tip_report.json, cisa_kev.csv, cisa_kev.json")
    if attr_error:
        print("WARNING: MISP retrieval error:", attr_error)
        return 1
    if limit_reached:
        print("WARNING: Retrieval page limit reached; data may be incomplete. Review TIP_MISP_MAX_PAGES.")
        return 1
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        print("Interrupted.")
        raise SystemExit(130)
    except Exception:
        log.exception("Fatal ingestion failure")
        print("ERROR: Ingestion failed. Review unified_ingest.log for details.")
        raise SystemExit(1)
