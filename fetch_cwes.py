"""
fetch_cwes.py
Downloads the full MITRE CWE list (XML), parses it, stores in SQLite.
Run once — the XML has ~900+ CWEs, so this covers everything.
"""

import io
import os
import zipfile
import requests
from lxml import etree
from db import get_conn, init_db, DB_PATH

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DATA_DIR    = os.path.join(os.path.dirname(__file__), "data")


# ── Broad category buckets based on CWE name keywords ───────────────────────
CATEGORY_KEYWORDS = {
    "Injection":       ["inject", "sql", "command", "xpath", "ldap", "xss", "script"],
    "Memory Safety":   ["buffer", "overflow", "memory", "heap", "stack", "use-after", "double free", "null pointer"],
    "Authentication":  ["authenticat", "credential", "password", "session", "token"],
    "Authorization":   ["authoriz", "privilege", "access control", "permission"],
    "Cryptography":    ["crypto", "cipher", "encrypt", "hash", "random", "entropy"],
    "Data Exposure":   ["exposure", "sensitive", "cleartext", "plain text", "information disclosure"],
    "Input Validation":["validat", "sanitiz", "input", "path traversal", "directory"],
    "Configuration":   ["misconfigur", "default", "hardcoded", "debug"],
    "Concurrency":     ["race condition", "thread", "deadlock", "concurren"],
    "Web":             ["http", "web", "cookie", "cors", "csrf", "redirect", "referrer"],
    "Android/Mobile":  ["android", "mobile", "intent", "activity", "manifest"],
}


def guess_category(name: str, desc: str) -> str:
    text = (name + " " + desc).lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(k in text for k in keywords):
            return cat
    return "Other"


def download_xml() -> bytes:
    zip_path = os.path.join(DATA_DIR, "cwec_latest.xml.zip")
    xml_path = os.path.join(DATA_DIR, "cwec_latest.xml")

    if os.path.exists(xml_path):
        print(f"[cwes] XML already on disk at {xml_path}, skipping download.")
        with open(xml_path, "rb") as f:
            return f.read()

    print(f"[cwes] Downloading CWE XML from MITRE (~30 MB)…")
    os.makedirs(DATA_DIR, exist_ok=True)
    r = requests.get(CWE_ZIP_URL, timeout=60)
    r.raise_for_status()

    with open(zip_path, "wb") as f:
        f.write(r.content)

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        xml_name = [n for n in z.namelist() if n.endswith(".xml")][0]
        xml_bytes = z.read(xml_name)

    with open(xml_path, "wb") as f:
        f.write(xml_bytes)

    print(f"[cwes] Saved {xml_path}")
    return xml_bytes


def parse_and_store(xml_bytes: bytes):
    print("[cwes] Parsing XML…")
    root = etree.fromstring(xml_bytes)

    # MITRE uses a namespace — strip it for easier access
    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

    weaknesses = root.findall(".//cwe:Weakness", ns)
    print(f"[cwes] Found {len(weaknesses)} weaknesses")

    conn = get_conn()
    cur  = conn.cursor()
    inserted = 0

    for w in weaknesses:
        cwe_id = "CWE-" + w.get("ID", "")
        name   = w.get("Name", "")

        desc_el = w.find("cwe:Description", ns)
        desc    = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        # Likelihood of exploit (not always present)
        like_el  = w.find("cwe:Likelihood_Of_Exploit", ns)
        likelihood = like_el.text.strip() if like_el is not None and like_el.text else "Unknown"

        category = guess_category(name, desc)

        cur.execute("""
            INSERT OR REPLACE INTO cwes (id, name, description, likelihood, category)
            VALUES (?, ?, ?, ?, ?)
        """, (cwe_id, name, desc, likelihood, category))
        inserted += 1

    conn.commit()
    conn.close()
    print(f"[cwes] Stored {inserted} CWEs in {DB_PATH}")


if __name__ == "__main__":
    init_db()
    xml_bytes = download_xml()
    parse_and_store(xml_bytes)
    print("[cwes] Done ✓")
