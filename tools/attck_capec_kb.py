#!/usr/bin/env python3
"""
AGY Bug Bounty MCP - MITRE ATT&CK + CAPEC Knowledge Base Tools
Provides full-text search over ATT&CK techniques and CAPEC entries using SQLite FTS5.
"""
import sqlite3
import json
import xml.etree.ElementTree as ET
import urllib.request
from datetime import datetime, timezone
from mcp_instance import mcp
from tools.db import DB_PATH
import logging

logger = logging.getLogger("agy")

# Mapping from phase_name to tactic_id
# NOTE: TA0011 (Command and Control) excluded from web/API filtering per requirements
PHASE_TO_TACTIC = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

# Filtered tactic IDs for web/API-relevant techniques
WEB_RELEVANT_TACTICS = set(PHASE_TO_TACTIC.values())


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def sync_attck() -> dict:
    """Sync MITRE ATT&CK techniques from STIX 2.1 JSON."""
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json"
    fetched_at = datetime.now(timezone.utc).isoformat()
    synced_tactics = 0
    synced_techniques = 0
    parse_errors = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AGY-BugBounty-MCP/1.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e), "synced_tactics": 0, "synced_techniques": 0}

    # First pass: tactics (use the filtered set)
    with _get_conn() as conn:
        conn.execute("DELETE FROM attck_tactics")
        conn.execute("DELETE FROM attck_techniques")
        conn.execute("DELETE FROM attck_fts")

        # Build tactic map from STIX
        tactic_map = {}
        for obj in data.get("objects", []):
            if obj.get("type") == "x-mitre-tactic":
                ext_refs = obj.get("external_references", [])
                tac_id = None
                tac_url = None
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tac_id = ref.get("external_id")
                        tac_url = ref.get("url")
                        break
                if tac_id and tac_id in WEB_RELEVANT_TACTICS:
                    conn.execute(
                        "INSERT INTO attck_tactics (tactic_id, name, description, url) VALUES (?, ?, ?, ?)",
                        (tac_id, obj.get("name"), obj.get("description"), tac_url)
                    )
                    synced_tactics += 1
                    tactic_map[obj.get("id")] = tac_id

        # Second pass: techniques
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            ext_refs = obj.get("external_references", [])
            tech_id = None
            tech_url = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    tech_url = ref.get("url")
                    break
            if not tech_id:
                continue

            is_sub = obj.get("x_mitre_is_subtechnique", False)
            parent = obj.get("x_mitre_parent")
            platforms = json.dumps(obj.get("x_mitre_platforms", []))

            # Get tactic IDs from kill_chain_phases
            tactic_ids = []
            for phase in obj.get("kill_chain_phases", []):
                phase_name = phase.get("phase_name", "")
                tac_id = PHASE_TO_TACTIC.get(phase_name)
                if tac_id:
                    tactic_ids.append(tac_id)

            # Only include if has relevant tactic
            if set(tactic_ids) & WEB_RELEVANT_TACTICS:
                conn.execute(
                    """INSERT OR REPLACE INTO attck_techniques
                       (technique_id, name, description, detection, platforms, tactic_ids,
                        is_subtechnique, parent_id, url)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (tech_id, obj.get("name"), obj.get("description"), obj.get("x_mitre_detection"),
                     platforms, json.dumps(tactic_ids), is_sub, parent, tech_url)
                )
                synced_techniques += 1

        conn.commit()

    # Populate FTS5
    with _get_conn() as conn:
        conn.execute("DELETE FROM attck_fts")
        for row in conn.execute("SELECT rowid, technique_id, name, description, detection FROM attck_techniques"):
            conn.execute(
                "INSERT INTO attck_fts (rowid, technique_id, name, description, detection) VALUES (?, ?, ?, ?, ?)",
                (row["rowid"], row["technique_id"], row["name"], row["description"] or "", row["detection"] or "")
            )
        conn.commit()

    return {"synced_tactics": synced_tactics, "synced_techniques": synced_techniques, "parse_errors": parse_errors}


def sync_capec() -> dict:
    """Sync CAPEC entries from XML, filtering out Deprecated entries."""
    url = "https://capec.mitre.org/data/xml/capec_latest.xml"
    fetched_at = datetime.now(timezone.utc).isoformat()
    synced = 0
    parse_errors = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AGY-BugBounty-MCP/1.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            tree = ET.parse(resp)
    except Exception as e:
        return {"error": str(e), "synced": 0}

    root = tree.getroot()
    ns_uri = root.tag.split('}')[0].strip('{')
    ns = {'c': ns_uri}

    with _get_conn() as conn:
        conn.execute("DELETE FROM capec_entries")
        conn.execute("DELETE FROM capec_fts")

        for ap in root.findall('.//c:Attack_Pattern', ns):
            status = ap.get('Status', '')
            if status == 'Deprecated':
                continue

            capec_id = ap.get('ID')
            name = ap.get('Name') or ''
            likelihood = ap.get('Likelihood_Of_Attack')
            severity = ap.get('Typical_Severity')

            desc_elem = ap.find('c:Description', ns)
            description = desc_elem.text if desc_elem is not None else None

            ext_desc_elem = ap.find('c:Extended_Description', ns)
            extended_description = ""
            if ext_desc_elem is not None:
                for child in ext_desc_elem:
                    if child.text:
                        extended_description += child.text + " "

            prereqs = []
            for pr in ap.findall('.//c:Prerequisite', ns):
                if pr.text:
                    prereqs.append(pr.text)

            mitigations = []
            for mit in ap.findall('.//c:Mitigation', ns):
                if mit.text:
                    mitigations.append(mit.text)

            technique_ids = []
            for tax_map in ap.findall('.//c:Taxonomy_Mapping', ns):
                if tax_map.get('Taxonomy_Name') == 'ATTACK':
                    eid = tax_map.find('c:Entry_ID', ns)
                    if eid is not None and eid.text:
                        tid = eid.text
                        # Normalize to T-prefixed format (e.g., "1190" -> "T1190")
                        if not tid.startswith('T'):
                            tid = 'T' + tid
                        technique_ids.append(tid)

            conn.execute(
                """INSERT OR REPLACE INTO capec_entries
                   (capec_id, name, description, extended_description,
                    likelihood_of_attack, typical_severity, prerequisites,
                    mitigations, related_technique_ids, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (capec_id, name, description, extended_description[:5000] if extended_description else None,
                 likelihood, severity, json.dumps(prereqs), json.dumps(mitigations),
                 json.dumps(technique_ids), status)
            )
            synced += 1

        conn.commit()

    with _get_conn() as conn:
        conn.execute("DELETE FROM capec_fts")
        for row in conn.execute("SELECT rowid, capec_id, name, description FROM capec_entries"):
            conn.execute(
                "INSERT INTO capec_fts (rowid, capec_id, name, description) VALUES (?, ?, ?, ?)",
                (row["rowid"], row["capec_id"], row["name"], row["description"] or "")
            )
        conn.commit()

    return {"synced": synced, "parse_errors": parse_errors}


@mcp.tool()
def search_attck(query: str, tactic_id: str = None) -> dict:
    """FTS5 search across ATT&CK techniques."""
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    conn = _get_conn()
    try:
        if tactic_id:
            rows = conn.execute(
                """SELECT t.technique_id, t.name, t.tactic_ids, t.platforms,
                          snippet(attck_fts, 2, '<b>', '</b>', '…', 64) AS snippet
                   FROM attck_fts f
                   JOIN attck_techniques t ON f.rowid = t.rowid
                   WHERE f MATCH ? AND t.tactic_ids LIKE ?
                   LIMIT 20""",
                (safe_query, f'%{tactic_id}%')
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT t.technique_id, t.name, t.tactic_ids, t.platforms,
                          snippet(attck_fts, 2, '<b>', '</b>', '…', 64) AS snippet
                   FROM attck_fts f
                   JOIN attck_techniques t ON f.rowid = t.rowid
                   WHERE f MATCH ?
                   LIMIT 20""",
                (safe_query,)
            ).fetchall()

        results = [
            {
                "technique_id": r["technique_id"],
                "name": r["name"],
                "tactic_ids": json.loads(r["tactic_ids"]) if r["tactic_ids"] else [],
                "platforms": json.loads(r["platforms"]) if r["platforms"] else [],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "tactic_id": tactic_id, "count": len(results), "results": results}
    except Exception as e:
        logger.error("FTS5 search error: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_attck_technique(technique_id: str) -> dict:
    """Get full details for an ATT&CK technique including sub-techniques."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM attck_techniques WHERE technique_id = ?",
            (technique_id,)
        ).fetchone()

        if not row:
            return {"error": f"Technique {technique_id} not found", "found": False}

        subtechs = conn.execute(
            "SELECT technique_id, name FROM attck_techniques WHERE parent_id = ?",
            (row["technique_id"],)
        ).fetchall()

        return {
            "found": True,
            "technique_id": row["technique_id"],
            "name": row["name"],
            "description": row["description"],
            "detection": row["detection"],
            "platforms": json.loads(row["platforms"]) if row["platforms"] else [],
            "tactic_ids": json.loads(row["tactic_ids"]) if row["tactic_ids"] else [],
            "is_subtechnique": bool(row["is_subtechnique"]),
            "parent_id": row["parent_id"],
            "url": row["url"],
            "subtechniques": [{"technique_id": s["technique_id"], "name": s["name"]} for s in subtechs],
        }
    except Exception as e:
        logger.error("Error fetching ATT&CK technique: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def search_capec(query: str) -> dict:
    """FTS5 search across CAPEC entries."""
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    conn = _get_conn()
    try:
        rows = conn.execute(
            """SELECT c.capec_id, c.name, c.likelihood_of_attack, c.typical_severity,
                      c.related_technique_ids,
                      snippet(capec_fts, 2, '<b>', '</b>', '…', 64) AS snippet
               FROM capec_fts f
               JOIN capec_entries c ON f.rowid = c.rowid
               WHERE f MATCH ?
               LIMIT 20""",
            (safe_query,)
        ).fetchall()

        results = [
            {
                "capec_id": r["capec_id"],
                "name": r["name"],
                "likelihood_of_attack": r["likelihood_of_attack"],
                "typical_severity": r["typical_severity"],
                "related_technique_ids": json.loads(r["related_technique_ids"]) if r["related_technique_ids"] else [],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "count": len(results), "results": results}
    except Exception as e:
        logger.error("FTS5 search error: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_capec_by_technique(technique_id: str) -> dict:
    """Find CAPEC entries mapped to an ATT&CK technique."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            """SELECT capec_id, name, likelihood_of_attack, typical_severity,
                      related_technique_ids, extended_description
               FROM capec_entries
               WHERE related_technique_ids LIKE ?
               ORDER BY capec_id""",
            (f'%{technique_id}%',)
        ).fetchall()

        results = [
            {
                "capec_id": r["capec_id"],
                "name": r["name"],
                "likelihood_of_attack": r["likelihood_of_attack"],
                "typical_severity": r["typical_severity"],
                "related_technique_ids": json.loads(r["related_technique_ids"]) if r["related_technique_ids"] else [],
            }
            for r in rows
        ]
        return {"technique_id": technique_id, "count": len(results), "results": results}
    except Exception as e:
        logger.error("Error finding CAPEC by technique: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_attck_tactics() -> dict:
    """Return all ATT&CK tactics, ordered by tactic_id."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT tactic_id, name, description FROM attck_tactics ORDER BY tactic_id"
        ).fetchall()
        tactics = [
            {"tactic_id": r["tactic_id"], "name": r["name"], "description": r["description"]}
            for r in rows
        ]
        return {"count": len(tactics), "tactics": tactics}
    except Exception as e:
        logger.error("Error listing tactics: %s", e)
        return {"error": str(e), "tactics": []}
    finally:
        conn.close()