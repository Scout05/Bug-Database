import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cwes.db")


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS cwes (
            id          TEXT PRIMARY KEY,   -- e.g. "CWE-79"
            name        TEXT,
            description TEXT,
            likelihood  TEXT,               -- High / Medium / Low / Unknown
            category    TEXT                -- e.g. "Injection", "Memory Safety"
        );

        CREATE TABLE IF NOT EXISTS cves (
            cve_id          TEXT PRIMARY KEY,
            published       TEXT,
            cvss_score      REAL,
            severity        TEXT,           -- LOW / MEDIUM / HIGH / CRITICAL
            platform        TEXT,           -- "android" | "web" | "general"
            description     TEXT,
            references_json TEXT            -- raw JSON blob of NVD refs
        );

        CREATE TABLE IF NOT EXISTS cve_cwe_map (
            cve_id  TEXT,
            cwe_id  TEXT,
            PRIMARY KEY (cve_id, cwe_id),
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
            FOREIGN KEY (cwe_id) REFERENCES cwes(id)
        );
    """)

    conn.commit()
    conn.close()
    print("[db] Schema ready.")


if __name__ == "__main__":
    init_db()
