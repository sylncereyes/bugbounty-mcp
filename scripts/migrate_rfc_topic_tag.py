#!/usr/bin/env python3
"""
Migrate RFC schema: add topic_tag column and backfill existing RFCs.
Run once to migrate database, safe to re-run (idempotent).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.db import db_connection

def migrate_rfc_topic_tag():
    """Add topic_tag column and backfill existing HTTP RFCs."""
    with db_connection() as conn:
        # Check if topic_tag column exists
        cols = conn.execute("PRAGMA table_info(rfc_documents)").fetchall()
        col_names = [c[1] for c in cols]
        
        if 'topic_tag' not in col_names:
            print("[INFO] Adding topic_tag column...")
            conn.execute("ALTER TABLE rfc_documents ADD COLUMN topic_tag TEXT")
        else:
            print("[INFO] topic_tag column already exists")
        
        # Backfill HTTP RFCs (those already in database without topic_tag)
        updated = conn.execute(
            "UPDATE rfc_documents SET topic_tag = 'HTTP' WHERE topic_tag IS NULL"
        ).rowcount
        print(f"[OK] Tagged {updated} existing RFCs as HTTP")

if __name__ == "__main__":
    migrate_rfc_topic_tag()