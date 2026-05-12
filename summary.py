"""
summary.py
Quick sanity check — prints what's in the database after fetching.
"""

from db import get_conn

def run():
    conn = get_conn()
    cur  = conn.cursor()

    print("=" * 50)
    print("DATABASE SUMMARY")
    print("=" * 50)

    # CWEs
    cur.execute("SELECT COUNT(*) FROM cwes")
    print(f"\n CWEs total:       {cur.fetchone()[0]}")

    cur.execute("SELECT category, COUNT(*) as n FROM cwes GROUP BY category ORDER BY n DESC")
    print("\n CWEs by category:")
    for row in cur.fetchall():
        print(f"   {row[0]:<25} {row[1]}")

    # CVEs
    cur.execute("SELECT COUNT(*) FROM cves")
    print(f"\n CVEs total:       {cur.fetchone()[0]}")

    cur.execute("SELECT platform, severity, COUNT(*) as n FROM cves GROUP BY platform, severity ORDER BY platform, severity")
    print("\n CVEs by platform + severity:")
    for row in cur.fetchall():
        print(f"   {row[0]:<12} {row[1]:<10} {row[2]}")

    # Mappings
    cur.execute("SELECT COUNT(*) FROM cve_cwe_map")
    print(f"\n CVE→CWE mappings: {cur.fetchone()[0]}")

    # Top 10 most referenced CWEs
    cur.execute("""
        SELECT m.cwe_id, c.name, COUNT(*) as hits
        FROM cve_cwe_map m
        LEFT JOIN cwes c ON c.id = m.cwe_id
        GROUP BY m.cwe_id
        ORDER BY hits DESC
        LIMIT 10
    """)
    print("\n Top 10 most referenced CWEs across all CVEs:")
    for row in cur.fetchall():
        print(f"   {row[0]:<12} {str(row[1]):<55} ({row[2]} CVEs)")

    conn.close()
    print("\n" + "=" * 50)

if __name__ == "__main__":
    run()
