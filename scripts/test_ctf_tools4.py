#!/usr/bin/env python3
"""Test search and tags via the MCP tool interface."""

import sys
sys.path.insert(0, '/home/kali/bugbounty-mcp')
from tools.ctf_writeups_kb import search_ctf_writeups, list_ctf_writeup_tags
import json

# Test search for "SQL injection"
print('=== SEARCH "SQL injection" ===')
results = search_ctf_writeups("SQL injection", limit=5)
print(json.dumps(results, indent=2))

# Test list tags
print('\n=== LIST TAGS ===')
tags = list_ctf_writeup_tags()
print(json.dumps(tags[:20], indent=2))