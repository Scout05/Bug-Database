"""
fetch_cves.py
Pulls CVEs from NVD API by platform keyword + date range, stores in SQLite.
Fetches only CVEs modified since 2020-01-01, filters severity locally.

Rate limits (no API key): 5 requests / 30 s  →  script sleeps automatically.
Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key
and paste it into API_KEY below to get 50 req/30 s.

NOTE: NVD API does NOT allow combining cvssV3Severity + keywordSearch + date
filters in a single request. We fetch by keyword+date only, then filter
severity locally before storing.
"""

import json
import time
import os
import requests
from datetime import datetime, timedelta
from db import get_conn, init_db

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY  = "8db290e2-3615-4b9d-8cbc-fbf8fdb883fb"

RESULTS_PER_PAGE = 100  # bumped up — fewer requests needed
SLEEP_NO_KEY     = 7
SLEEP_WITH_KEY   = 1

# NVD max date range is 120 days — we chunk 2020-now into windows
FETCH_START = "2020-01-01T00:00:00.000"


def sleep_between():
    delay = SLEEP_WITH_KEY if API_KEY else SLEEP_NO_KEY
    time.sleep(delay)


def build_headers():
    h = {"Accept": "application/json"}
    if API_KEY:
        h["apiKey"] = API_KEY
    return h


def date_windows(start_str: str, end_str: str, days: int = 110):
    """Split a date range into chunks of `days` days (NVD max is 120)."""
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    start = datetime.strptime(start_str, "%Y-%m-%dT%H:%M:%S.000")
    end   = datetime.strptime(end_str,   "%Y-%m-%dT%H:%M:%S.000")
    windows = []
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=days), end)
        windows.append((
            cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
            window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        ))
        cursor = window_end
    return windows


def fetch_page(keyword: str, start: int, start_date: str, end_date: str) -> dict:
    params = {
        "resultsPerPage":   RESULTS_PER_PAGE,
        "startIndex":       start,
        "lastModStartDate": start_date,
        "lastModEndDate":   end_date,
    }
    if keyword:
        params["keywordSearch"] = keyword

    r = requests.get(NVD_URL, params=params, headers=build_headers(), timeout=30)
    r.raise_for_status()
    return r.json()


def get_severity(cve_item: dict) -> str:
    """Extract CVSS v3 severity from a CVE item."""
    metrics = cve_item.get("metrics", {})
    cvss_data = (
        metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
        metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
    )
    return cvss_data.get("baseSeverity", "").upper()


def store_cves(data: dict, platform: str, severity_filter: str = "all"):
    """Store CVEs, optionally filtering by severity."""
    conn = get_conn()
    cur  = conn.cursor()
    stored = 0

    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")

        metrics   = cve.get("metrics", {})
        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
            metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        )
        score    = cvss_data.get("baseScore", None)
        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()

        # Filter by severity locally if requested
        if severity_filter != "all" and severity != severity_filter.upper():
            continue

        # Skip CVEs with no CVSS score at all
        if score is None:
            continue

        descs     = cve.get("descriptions", [])
        desc      = next((d["value"] for d in descs if d["lang"] == "en"), "")
        published = cve.get("published", "")
        refs      = json.dumps([r["url"] for r in cve.get("references", [])])

        cur.execute("""
            INSERT OR REPLACE INTO cves
                (cve_id, published, cvss_score, severity, platform, description, references_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, published, score, severity, platform, desc, refs))

        # CWE mappings
        for weakness in cve.get("weaknesses", []):
            for wd in weakness.get("description", []):
                cwe_raw = wd.get("value", "")
                if cwe_raw.startswith("CWE-"):
                    cur.execute("""
                        INSERT OR IGNORE INTO cve_cwe_map (cve_id, cwe_id) VALUES (?, ?)
                    """, (cve_id, cwe_raw))

        stored += 1

    conn.commit()
    conn.close()
    return stored


def fetch_platform(label: str, platform: str, keyword: str, target: int, severity_filter: str = "all"):
    """
    Fetch CVEs for a platform keyword across all date windows from 2020 to now.
    Stops early once `target` CVEs are stored.
    """
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
    windows = date_windows(FETCH_START, now)
    total_stored = 0

    print(f"\n[cves] {label!r} | keyword={keyword!r} | severity={severity_filter} | target={target}")
    print(f"       scanning {len(windows)} date windows from 2020 to now…")

    for (win_start, win_end) in reversed(windows):  # reversed = newest first
        if total_stored >= target:
            break

        start_idx = 0
        print(f"  [window] {win_start[:10]} → {win_end[:10]}")

        while total_stored < target:
            try:
                data = fetch_page(keyword, start_idx, win_start, win_end)
            except requests.HTTPError as e:
                print(f"    [!] HTTP {e.response.status_code}: {e}. Skipping window.")
                break

            total_results = data.get("totalResults", 0)
            stored = store_cves(data, platform, severity_filter)
            total_stored += stored
            start_idx    += RESULTS_PER_PAGE

            print(f"    → stored {stored:3d} this page | running total: {total_stored:4d} / {target}")

            if stored == 0 or start_idx >= total_results:
                break

            sleep_between()

        sleep_between()

    print(f"  [done] {label!r}: {total_stored} CVEs stored.")
    return total_stored


# ── Fetch plan ────────────────────────────────────────────────────────────────
# Each entry: (label, platform, keyword, target, severity_filter)
# severity_filter "all" = store everything; "CRITICAL" etc = filter locally
FETCH_PLAN = [
    # Android — all severities, let DB store them, dashboard filters
    ("android-all",   "android",  "android",               300, "all"),

    # Web — broad + specific attack types
    ("web-general",   "web",      "web application",        200, "all"),
    ("web-xss",       "web",      "cross-site scripting",   100, "all"),
    ("web-sqli",      "web",      "SQL injection",          100, "all"),
    ("web-rce",       "web",      "remote code execution",  100, "all"),
    ("web-csrf",      "web",      "CSRF",                    50, "all"),

    # General — no keyword, just recent critical/high
    ("general-crit",  "general",  "",                       200, "CRITICAL"),
    ("general-high",  "general",  "",                       200, "HIGH"),
]


if __name__ == "__main__":
    init_db()

    # Wipe old data for a clean fetch
    conn = get_conn()
    conn.execute("DELETE FROM cves")
    conn.execute("DELETE FROM cve_cwe_map")
    conn.commit()
    conn.close()
    print(f"[cves] Wiped old data. Fetching from 2020 to now…\n")

    grand_total = 0
    for (label, platform, keyword, target, sev_filter) in FETCH_PLAN:
        n = fetch_platform(label, platform, keyword, target, sev_filter)
        grand_total += n

    print(f"\n[cves] All done. Total CVEs stored: {grand_total}")
    print(f"[cves] Run  python3 main.py  to start the dashboard.")
