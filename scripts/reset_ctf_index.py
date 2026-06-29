#!/usr/bin/env python3
"""Reset CTF writeups index and rebuild from scratch."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "database" / "bugbounty.db"

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("DELETE FROM ctf_writeups_index;")
c.execute("DELETE FROM ctf_writeups_index_fts;")
conn.commit()
conn.close()
print("Reset complete.")