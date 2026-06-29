#!/usr/bin/env python3
"""Test CTF writeup tools."""

import sys
sys.path.insert(0, '/home/kali/bugbounty-mcp')
from tools.ctf_writeups_kb import search_ctf_writeups, get_ctf_writeup_content, list_ctf_writeup_tags
import json

# Test search
print('=== SEARCH TEST ===')
results = search_ctf_writeups('forensics', limit=3)
print(json.dumps(results, indent=2))

# Test get content
print('\n=== GET CONTENT TEST ===')
if results:
    content = get_ctf_writeup_content(results[0]["ctftime_writeup_id"])
    print(json.dumps({k: v[:200] if k == "content" else v for k, v in content.items()}, indent=2))

# Test tags
print('\n=== TAGS TEST ===')
tags = list_ctf_writeup_tags()
print(json.dumps(tags[:10], indent=2))