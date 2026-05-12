"""
main.py  —  BugNexus local server
Run:  python main.py
Then open:  http://localhost:8000

New endpoints added for the unified control-center UI:
  DELETE /api/delete          — delete CVEs by date + optional platform/severity filters
  DELETE /api/delete-all      — nuke everything (CVEs + CWEs + mappings)
  POST   /api/run-fetch-cves  — trigger fetch_cves programmatically
  POST   /api/run-fetch-cwes  — trigger fetch_cwes programmatically
"""

import json
import os
import sqlite3
import threading
import webbrowser
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

DB_PATH    = os.path.join(os.path.dirname(__file__), "data", "cwes.db")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@asynccontextmanager
async def lifespan(app: FastAPI):
    webbrowser.open("http://localhost:8000")
    yield


app = FastAPI(title="BugNexus", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def stats():
    conn = db()
    cur  = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM cwes")
    total_cwes = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM cves")
    total_cves = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM cve_cwe_map")
    total_maps = cur.fetchone()[0]

    cur.execute("SELECT severity, COUNT(*) as n FROM cves GROUP BY severity ORDER BY severity")
    by_severity = {r["severity"]: r["n"] for r in cur.fetchall()}

    cur.execute("SELECT platform, COUNT(*) as n FROM cves GROUP BY platform ORDER BY platform")
    by_platform = {r["platform"]: r["n"] for r in cur.fetchall()}

    cur.execute("SELECT category, COUNT(*) as n FROM cwes GROUP BY category ORDER BY n DESC")
    by_category = [{"category": r["category"], "count": r["n"]} for r in cur.fetchall()]

    conn.close()
    return {
        "total_cwes":  total_cwes,
        "total_cves":  total_cves,
        "total_maps":  total_maps,
        "by_severity": by_severity,
        "by_platform": by_platform,
        "by_category": by_category,
    }


# ── Top CWEs ──────────────────────────────────────────────────────────────────

@app.get("/api/top-cwes")
def top_cwes(
    platform: str = Query("all"),
    severity: str = Query("all"),
    limit:    int = Query(20, le=100),
):
    conn   = db()
    cur    = conn.cursor()
    wheres = []
    params = []

    if platform != "all":
        wheres.append("v.platform = ?")
        params.append(platform)
    if severity != "all":
        wheres.append("v.severity = ?")
        params.append(severity.upper())

    where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""

    cur.execute(f"""
        SELECT m.cwe_id, w.name, w.category, w.likelihood,
               COUNT(DISTINCT m.cve_id) AS cve_count,
               ROUND(AVG(v.cvss_score), 2) AS avg_cvss
        FROM cve_cwe_map m
        JOIN cves  v ON v.cve_id = m.cve_id
        JOIN cwes  w ON w.id     = m.cwe_id
        {where_clause}
        GROUP BY m.cwe_id
        ORDER BY cve_count DESC
        LIMIT ?
    """, params + [limit])

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ── CWE list ──────────────────────────────────────────────────────────────────

@app.get("/api/cwes")
def cwes(
    category: str = Query("all"),
    search:   str = Query(""),
    sort:     str = Query("id"),
    order:    str = Query("asc"),
    page:     int = Query(1, ge=1),
    per_page: int = Query(50, le=200),
):
    conn   = db()
    cur    = conn.cursor()
    wheres = []
    params = []

    if category != "all":
        wheres.append("category = ?")
        params.append(category)
    if search:
        wheres.append("(id LIKE ? OR name LIKE ? OR description LIKE ?)")
        s = f"%{search}%"
        params += [s, s, s]

    where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""

    safe_sort  = sort  if sort  in ("id", "name", "category", "likelihood") else "id"
    safe_order = "DESC" if order.lower() == "desc" else "ASC"
    offset     = (page - 1) * per_page

    cur.execute(f"""
        SELECT w.id, w.name, w.category, w.likelihood, w.description,
               COUNT(m.cve_id) as cve_count
        FROM cwes w
        LEFT JOIN cve_cwe_map m ON m.cwe_id = w.id
        {where_clause}
        GROUP BY w.id
        ORDER BY {safe_sort} {safe_order}
        LIMIT ? OFFSET ?
    """, params + [per_page, offset])

    rows = [dict(r) for r in cur.fetchall()]

    cur.execute(f"SELECT COUNT(*) FROM cwes w {where_clause}", params)
    total = cur.fetchone()[0]

    conn.close()
    return {"items": rows, "total": total, "page": page, "per_page": per_page}


# ── CVE list ──────────────────────────────────────────────────────────────────

@app.get("/api/cves")
def cves(
    platform: str = Query("all"),
    severity: str = Query("all"),
    search:   str = Query(""),
    sort:     str = Query("cvss_score"),
    order:    str = Query("desc"),
    page:     int = Query(1, ge=1),
    per_page: int = Query(50, le=200),
):
    conn   = db()
    cur    = conn.cursor()
    wheres = []
    params = []

    if platform != "all":
        wheres.append("platform = ?")
        params.append(platform)
    if severity != "all":
        wheres.append("severity = ?")
        params.append(severity.upper())
    if search:
        wheres.append("(cve_id LIKE ? OR description LIKE ?)")
        s = f"%{search}%"
        params += [s, s]

    where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""

    safe_sort  = sort  if sort  in ("cve_id", "published", "cvss_score", "severity", "platform") else "cvss_score"
    safe_order = "DESC" if order.lower() == "desc" else "ASC"
    offset     = (page - 1) * per_page

    cur.execute(f"""
        SELECT cve_id, published, cvss_score, severity, platform,
               description, references_json
        FROM cves
        {where_clause}
        ORDER BY {safe_sort} {safe_order}
        LIMIT ? OFFSET ?
    """, params + [per_page, offset])

    rows = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["references"] = json.loads(d.pop("references_json") or "[]")[:5]
        except Exception:
            d["references"] = []
        rows.append(d)

    cur.execute(f"SELECT COUNT(*) FROM cves {where_clause}", params)
    total = cur.fetchone()[0]

    conn.close()
    return {"items": rows, "total": total, "page": page, "per_page": per_page}


# ── CWE detail ────────────────────────────────────────────────────────────────

@app.get("/api/cwe/{cwe_id}")
def cwe_detail(cwe_id: str):
    conn = db()
    cur  = conn.cursor()

    cur.execute("SELECT * FROM cwes WHERE id = ?", (cwe_id,))
    row = cur.fetchone()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Not found"})

    cwe = dict(row)

    cur.execute("""
        SELECT v.cve_id, v.published, v.cvss_score, v.severity, v.platform, v.description
        FROM cve_cwe_map m
        JOIN cves v ON v.cve_id = m.cve_id
        WHERE m.cwe_id = ?
        ORDER BY v.cvss_score DESC
        LIMIT 20
    """, (cwe_id,))
    cwe["cves"] = [dict(r) for r in cur.fetchall()]

    conn.close()
    return cwe


# ── Delete CVEs by date / filters ─────────────────────────────────────────────

@app.delete("/api/delete")
def delete_cves(
    before:   str = Query(..., description="ISO date string, e.g. 2020-01-01"),
    platform: str = Query("all"),
    severity: str = Query("all"),
):
    """
    Delete CVEs (and their cve_cwe_map rows) published strictly before `before`.
    Optionally filter by platform and/or severity.
    """
    conn   = db()
    cur    = conn.cursor()
    wheres = ["published < ?"]
    params: list = [before]

    if platform != "all":
        wheres.append("platform = ?")
        params.append(platform)
    if severity != "all":
        wheres.append("severity = ?")
        params.append(severity.upper())

    where_clause = "WHERE " + " AND ".join(wheres)

    # Collect IDs first so we can clean up the mapping table
    cur.execute(f"SELECT cve_id FROM cves {where_clause}", params)
    ids = [r[0] for r in cur.fetchall()]

    maps_deleted = 0
    if ids:
        placeholders = ",".join("?" * len(ids))
        cur.execute(f"DELETE FROM cve_cwe_map WHERE cve_id IN ({placeholders})", ids)
        maps_deleted = cur.rowcount
        cur.execute(f"DELETE FROM cves {where_clause}", params)

    deleted = len(ids)
    conn.commit()
    conn.close()

    print(f"[delete] Removed {deleted} CVEs (before={before}, platform={platform}, severity={severity})"
          f" + {maps_deleted} mappings.")
    return {"deleted": deleted, "maps_deleted": maps_deleted}


# ── Nuke everything ───────────────────────────────────────────────────────────

@app.delete("/api/delete-all")
def delete_all():
    """Wipe all CVEs, CWEs, and mappings. Schema stays intact."""
    conn = db()
    cur  = conn.cursor()

    cur.execute("DELETE FROM cve_cwe_map")
    maps = cur.rowcount
    cur.execute("DELETE FROM cves")
    cves_n = cur.rowcount
    cur.execute("DELETE FROM cwes")
    cwes_n = cur.rowcount

    conn.commit()
    conn.close()

    print(f"[delete-all] Wiped {cves_n} CVEs, {cwes_n} CWEs, {maps} mappings.")
    return {
        "deleted": cves_n,
        "cwes_deleted": cwes_n,
        "maps_deleted": maps,
        "message": f"Deleted {cves_n} CVEs, {cwes_n} CWEs, {maps} mappings.",
    }


# ── Trigger fetch (runs in background thread) ─────────────────────────────────

def _run_fetch_cves(platform: str, severity: str, keyword: str, target: int):
    """Background worker — imports fetch_cves and runs a single batch."""
    try:
        from fetch_cves import fetch_batch, sleep_between
        from db import init_db
        init_db()

        # Build a mini fetch plan from the supplied filters
        sev_list = (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            if severity == "all"
            else [severity.upper()]
        )
        plat_list = (
            [("android", "android"), ("web", "web application"), ("general", "")]
            if platform == "all"
            else [(platform, keyword or platform)]
        )

        for plat_label, kw in plat_list:
            for sev in sev_list:
                kw_use = keyword if keyword else kw
                fetch_batch(plat_label, plat_label, sev, kw_use, target)
                sleep_between()
        print("[run-fetch-cves] Done.")
    except Exception as e:
        print(f"[run-fetch-cves] Error: {e}")


def _run_fetch_cwes():
    """Background worker — downloads and parses the MITRE CWE XML."""
    try:
        from fetch_cwes import download_xml, parse_and_store
        from db import init_db
        init_db()
        xml_bytes = download_xml()
        parse_and_store(xml_bytes)
        print("[run-fetch-cwes] Done.")
    except Exception as e:
        print(f"[run-fetch-cwes] Error: {e}")


@app.post("/api/run-fetch-cves")
def run_fetch_cves(
    platform: str = Query("all"),
    severity: str = Query("all"),
    keyword:  str = Query(""),
    target:   int = Query(100, le=500),
):
    """
    Kick off a CVE fetch in a background thread so the HTTP response
    returns immediately. Watch the terminal for progress output.
    """
    t = threading.Thread(
        target=_run_fetch_cves,
        args=(platform, severity, keyword, target),
        daemon=True,
    )
    t.start()
    return {
        "message": f"CVE fetch started in background "
                   f"(platform={platform}, severity={severity}, target={target}). "
                   "Watch your terminal for progress."
    }


@app.post("/api/run-fetch-cwes")
def run_fetch_cwes():
    """
    Kick off a CWE download + parse in a background thread.
    Skips the download if the XML is already cached on disk.
    """
    t = threading.Thread(target=_run_fetch_cwes, daemon=True)
    t.start()
    return {
        "message": "CWE fetch started in background. "
                   "Watch your terminal for progress (~900 CWEs from MITRE XML)."
    }


# ── Serve frontend ────────────────────────────────────────────────────────────

os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
