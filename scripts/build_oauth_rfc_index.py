#!/usr/bin/env python3
"""
Build OAuth 2.0 RFC index using existing add_rfc_to_db() function.
Skips RFCs already in database (7521, 7523, 9068 are tagged JWT).
"""
import sys
import time
sys.path.insert(0, '/home/kali/bugbounty-mcp/tools')

from db import add_rfc_to_db
import sqlite3

# OAuth 2.0 RFC seed list (excluding 7521, 7523, 9068 which are already tagged JWT)
OAUTH_RFC_LIST = [
    6749,   # The OAuth 2.0 Authorization Framework
    6750,   # Bearer Token Usage
    6819,   # Threat Model and Security Considerations
    7009,   # Token Revocation
    7591,   # Dynamic Client Registration Protocol
    7592,   # Dynamic Client Registration Management Protocol
    7636,   # PKCE (Proof Key for Code Exchange)
    7662,   # Token Introspection
    8252,   # OAuth 2.0 for Native Apps
    8414,   # Authorization Server Metadata
    8628,   # Device Authorization Grant
    8693,   # Token Exchange
    8705,   # Mutual-TLS Client Authentication
    9126,   # Pushed Authorization Requests
    9207,   # Authorization Server Issuer Identification
    9700,   # Best Current Practices for OAuth 2.0 Security
]

def get_existing_rfc_numbers(db_path: str) -> set:
    """Get all RFC numbers already in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT rfc_number FROM rfc_documents")
    existing = {row[0] for row in cursor.fetchall()}
    conn.close()
    return existing

def main():
    db_path = '/home/kali/bugbounty-mcp/database/bugbounty.db'
    existing_rfcs = get_existing_rfc_numbers(db_path)
    
    print(f"Existing RFCs in database: {sorted(existing_rfcs)}")
    print(f"Processing {len(OAUTH_RFC_LIST)} OAuth RFCs...")
    print()
    
    indexed = []
    skipped = []
    
    for rfc_num in OAUTH_RFC_LIST:
        if rfc_num in existing_rfcs:
            # Get existing tag for reporting
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT topic_tag FROM rfc_documents WHERE rfc_number = ?", (rfc_num,))
            row = cursor.fetchone()
            conn.close()
            existing_tag = row[0] if row else "unknown"
            print(f"[SKIP] RFC {rfc_num}: already indexed as topic_tag='{existing_tag}'")
            skipped.append((rfc_num, existing_tag))
            continue
        
        print(f"[FETCH] RFC {rfc_num}...")
        try:
            add_rfc_to_db(rfc_num, topic_tag='OAuth')
            print(f"[OK]   RFC {rfc_num} indexed as OAuth")
            indexed.append(rfc_num)
        except Exception as e:
            print(f"[ERR]  RFC {rfc_num}: {e}")
        
        time.sleep(1)  # Be nice to rfc-editor.org
    
    print()
    print("=" * 50)
    print(f"SUMMARY: {len(indexed)} indexed, {len(skipped)} skipped")
    print(f"Indexed: {indexed}")
    print(f"Skipped: {skipped}")

if __name__ == '__main__':
    main()