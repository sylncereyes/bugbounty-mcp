# ---------------------------------------------------------------------------
# sync tool
# ---------------------------------------------------------------------------
@mcp.tool(name="bugcrowd_sync", description="Synchronize Bugcrowd CrowdStream disclosures (incremental)")
def sync_bugcrowd_disclosures(max_pages: int = 5):
    """Run incremental sync and return a summary.
    Returns a dict like {'new_reports': int, 'date_range': {'from': str, 'to': str}}.
    """
    sync_fn = _load_sync()
    result = sync_fn(max_pages=max_pages)
    return result

# ---------------------------------------------------------------------------
# search tool
# ---------------------------------------------------------------------------
@mcp.tool(name="bugcrowd_search", description="Full‑text search Bugcrowd disclosures")
def search_bugcrowd_reports(query: str, vrt_category: str = None, priority: str = None, limit: int = 10):
    db_mod = _load_db()
    with db_mod.db_connection() as conn:
        sql = """
        SELECT r.disclosure_uuid, r.title, r.program, r.vrt_category, r.priority,
               r.reward_amount, r.url, r.disclosed_date,
               snippet(bugcrowd_reports_fts, -1, '<b>', '</b>', '…', 10) AS snippet
        FROM bugcrowd_reports r
        JOIN bugcrowd_reports_fts fts ON r.rowid = fts.rowid
        WHERE fts MATCH ?
        """
        params = [query]
        if vrt_category:
            sql += " AND r.vrt_category = ?"
            params.append(vrt_category)
        if priority:
            sql += " AND r.priority = ?"
            params.append(priority)
        sql += " LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

# ---------------------------------------------------------------------------
# get single report
# ---------------------------------------------------------------------------
@mcp.tool(name="bugcrowd_get", description="Retrieve a single Bugcrowd disclosure by UUID")
def get_bugcrowd_report(disclosure_uuid: str):
    db_mod = _load_db()
    with db_mod.db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM bugcrowd_reports WHERE disclosure_uuid = ?", (disclosure_uuid,)
        ).fetchone()
        return dict(row) if row else None

# ---------------------------------------------------------------------------
# stats tool
# ---------------------------------------------------------------------------
@mcp.tool(name="bugcrowd_stats", description="Statistics for synced Bugcrowd disclosures")
def stats_bugcrowd_reports():
    db_mod = _load_db()
    with db_mod.db_connection() as conn:
        cur = conn.cursor()
        # total count
        total = cur.execute("SELECT COUNT(*) FROM bugcrowd_reports").fetchone()[0]
        # breakdown per vrt_category
        cat_rows = cur.execute("SELECT vrt_category, COUNT(*) FROM bugcrowd_reports GROUP BY vrt_category").fetchall()
        categories = {row[0] or 'unknown': row[1] for row in cat_rows}
        # breakdown per priority
        pr_rows = cur.execute("SELECT priority, COUNT(*) FROM bugcrowd_reports GROUP BY priority").fetchall()
        priorities = {row[0] or 'unknown': row[1] for row in pr_rows}
        # total reward (numeric extraction – strip non‑digits, ignore empties)
        reward_rows = cur.execute("SELECT reward_amount FROM bugcrowd_reports WHERE reward_amount IS NOT NULL").fetchall()
        total_reward = 0
        for (amt,) in reward_rows:
            # keep only digits and decimal point
            cleaned = ''.join(ch for ch in amt if ch.isdigit() or ch == '.')
            if cleaned:
                total_reward += float(cleaned)
        # date range
        dates = cur.execute("SELECT MIN(disclosed_date), MAX(disclosed_date) FROM bugcrowd_reports").fetchone()
        date_range = {"from": dates[0], "to": dates[1]}
        return {
            "total_reports": total,
            "by_vrt_category": categories,
            "by_priority": priorities,
            "total_reward_amount": total_reward,
            "date_range": date_range,
        }

# ---------------------------------------------------------------------------
# Register module load (MCP automatically counts tools when imported)
# ---------------------------------------------------------------------------
print("Bugcrowd knowledge‑base tool loaded –", len([n for n in globals() if n.startswith('bugcrowd_')]), "functions registered")
